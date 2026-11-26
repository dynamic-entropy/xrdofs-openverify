#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <string>
#include <thread>

#include "OpenVerifySingleFlight.hh"

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

void ConfigureSmallLimits(int queue_timeout_ms = 120, int verify_timeout_ms = 1000) {
    setenv("XRD_OPENVERIFY_MAX_INFLIGHT", "1", 1);
    setenv("XRD_OPENVERIFY_MAX_WAITERS", "1", 1);
    setenv("XRD_OPENVERIFY_QUEUE_TIMEOUT_MS", std::to_string(queue_timeout_ms).c_str(), 1);
    setenv("XRD_OPENVERIFY_VERIFY_TIMEOUT", "5", 1);
    (void)verify_timeout_ms;
}

void Test_WaitSlotReleasedAfterQueueTimeout() {
    // Limits force contention: one in-flight operation and one waiter slot.
    ConfigureSmallLimits();
    OpenVerifyMetrics metrics;
    OpenVerifySingleFlight sf(metrics);

    std::promise<void> release_leader;
    std::shared_future<void> release_signal(release_leader.get_future());

    // Keep k1 in-flight so later requests must queue behind it.
    auto leader = std::async(std::launch::async, [&]() {
        return sf.Run("k1", "h1", 1094, [&]() {
            release_signal.wait();
            return XrdCl::XRootDStatus{};
        });
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    auto waiter1 = std::async(std::launch::async, [&]() {
        return sf.Run("k2", "h2", 1094, [&]() { return XrdCl::XRootDStatus{}; });
    });
    const auto r1 = waiter1.get();
    // k2 should wait for in-flight capacity and eventually hit queue timeout.
    Expect(!r1.IsOK() && r1.GetErrorMessage() == "openverify_queue_timeout",
           "first waiter should timeout while waiting for in-flight slot");

    auto waiter2 = std::async(std::launch::async, [&]() {
        return sf.Run("k3", "h3", 1094, [&]() { return XrdCl::XRootDStatus{}; });
    });
    const auto r2 = waiter2.get();
    // If waiter bookkeeping is correct, k3 can also occupy the wait slot and timeout.
    Expect(!r2.IsOK() && r2.GetErrorMessage() == "openverify_queue_timeout",
           "second waiter should also get queue_timeout (wait slot must be released)");

    // Unblock k1 and verify the leader path itself still succeeds.
    release_leader.set_value();
    const auto lr = leader.get();
    Expect(lr.IsOK(), "leader should finish successfully");
}

void Test_WaitSlotReleasedOnWaitToInFlightTransition() {
    // Same tight limits; this test covers waiter -> in-flight transition.
    ConfigureSmallLimits();
    OpenVerifyMetrics metrics;
    OpenVerifySingleFlight sf(metrics);

    std::promise<void> release_leader;
    std::promise<void> release_second;
    std::shared_future<void> leader_signal(release_leader.get_future());
    std::shared_future<void> second_signal(release_second.get_future());

    // k1 starts first and holds the in-flight slot.
    auto leader = std::async(std::launch::async, [&]() {
        return sf.Run("k1", "h1", 1094, [&]() {
            leader_signal.wait();
            return XrdCl::XRootDStatus{};
        });
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // k2 should initially be a waiter, then become in-flight after k1 releases.
    auto second = std::async(std::launch::async, [&]() {
        return sf.Run("k2", "h2", 1094, [&]() {
            second_signal.wait();
            return XrdCl::XRootDStatus{};
        });
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    release_leader.set_value();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // k3 arrives while k2 is in-flight; it should be able to wait (not queue_full) then timeout.
    auto third = std::async(std::launch::async, [&]() {
        return sf.Run("k3", "h3", 1094, [&]() { return XrdCl::XRootDStatus{}; });
    });
    const auto t = third.get();
    Expect(!t.IsOK() && t.GetErrorMessage() == "openverify_queue_timeout",
           "third request should wait then timeout, not fail queue_full");

    // Finish k2 and ensure both successful paths complete cleanly.
    release_second.set_value();
    const auto r2 = second.get();
    const auto r1 = leader.get();
    Expect(r1.IsOK(), "leader should succeed");
    Expect(r2.IsOK(), "second should succeed after becoming in-flight");
}

void Test_HostInflightCapRejectsBusyAndAllowsOtherHost() {
    setenv("XRD_OPENVERIFY_MAX_INFLIGHT", "4", 1);
    setenv("XRD_OPENVERIFY_MAX_WAITERS", "8", 1);
    setenv("XRD_OPENVERIFY_QUEUE_TIMEOUT_MS", "2000", 1);
    unsetenv("XRD_OPENVERIFY_MAX_INFLIGHT_PER_HOST");  // default 50% of 4 → 2
    OpenVerifyMetrics metrics;
    OpenVerifySingleFlight sf(metrics);

    std::promise<void> release;
    std::shared_future<void> release_signal(release.get_future());

    auto a1 = std::async(std::launch::async, [&]() {
        return sf.Run("a1", "siteA", 1094, [&]() {
            release_signal.wait();
            return XrdCl::XRootDStatus{};
        });
    });
    auto a2 = std::async(std::launch::async, [&]() {
        return sf.Run("a2", "siteA", 1094, [&]() {
            release_signal.wait();
            return XrdCl::XRootDStatus{};
        });
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto a3 = std::async(std::launch::async, [&]() {
        return sf.Run("a3", "siteA", 1094, [&]() { return XrdCl::XRootDStatus{}; });
    });
    const auto r3 = a3.get();
    Expect(!r3.IsOK() && r3.GetErrorMessage() == "openverify_host_busy",
           "third probe to siteA should hit per-host inflight cap");

    auto b1 = std::async(std::launch::async, [&]() {
        return sf.Run("b1", "siteB", 1094, [&]() { return XrdCl::XRootDStatus{}; });
    });
    const auto rb = b1.get();
    Expect(rb.IsOK(), "siteB should still get a global slot while siteA is at its cap");

    release.set_value();
    Expect(a1.get().IsOK(), "siteA leader 1 should succeed");
    Expect(a2.get().IsOK(), "siteA leader 2 should succeed");
}

void Test_FollowerTimeoutIsNotQueuePassThrough() {
    // Follower bound is the queue timeout plus 4 * VERIFY_TIMEOUT seconds.
    setenv("XRD_OPENVERIFY_MAX_INFLIGHT", "4", 1);
    setenv("XRD_OPENVERIFY_MAX_WAITERS", "4", 1);
    setenv("XRD_OPENVERIFY_QUEUE_TIMEOUT_MS", "50", 1);
    setenv("XRD_OPENVERIFY_VERIFY_TIMEOUT", "1", 1);
    OpenVerifyMetrics metrics;
    OpenVerifySingleFlight sf(metrics);

    std::promise<void> release;
    std::shared_future<void> sig(release.get_future());
    auto leader = std::async(std::launch::async, [&]() {
        return sf.Run("same-key", "h", 1094, [&]() {
            sig.wait();
            return XrdCl::XRootDStatus{};
        });
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    auto follower = std::async(std::launch::async, [&]() {
        return sf.Run("same-key", "h", 1094, [&]() { return XrdCl::XRootDStatus{}; });
    });
    const auto fr = follower.get();
    Expect(!fr.IsOK() && fr.GetErrorMessage() == "openverify_inflight_timeout",
           "follower timeout must not be openverify_queue_timeout (that pass-throughs)");
    release.set_value();
    Expect(leader.get().IsOK(), "leader still publishes after the follower gives up");
}

}  // namespace

int main() {
    Test_WaitSlotReleasedAfterQueueTimeout();
    Test_WaitSlotReleasedOnWaitToInFlightTransition();
    Test_HostInflightCapRejectsBusyAndAllowsOtherHost();
    Test_FollowerTimeoutIsNotQueuePassThrough();

    if (g_failures) {
        std::cerr << g_failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "All tests passed.\n";
    return 0;
}
