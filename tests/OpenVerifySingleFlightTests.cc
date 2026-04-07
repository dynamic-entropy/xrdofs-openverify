#include <chrono>
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
    setenv("XRD_OPENVERIFY_VERIFY_TIMEOUT_MS", std::to_string(verify_timeout_ms).c_str(), 1);
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
        return sf.Run("k1", [&]() {
            release_signal.wait();
            return XrdCl::XRootDStatus{};
        });
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    auto waiter1 = std::async(std::launch::async, [&]() {
        return sf.Run("k2", [&]() { return XrdCl::XRootDStatus{}; });
    });
    const auto r1 = waiter1.get();
    // k2 should wait for in-flight capacity and eventually hit queue timeout.
    Expect(!r1.IsOK() && r1.GetErrorMessage() == "openverify_queue_timeout",
           "first waiter should timeout while waiting for in-flight slot");

    auto waiter2 = std::async(std::launch::async, [&]() {
        return sf.Run("k3", [&]() { return XrdCl::XRootDStatus{}; });
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
        return sf.Run("k1", [&]() {
            leader_signal.wait();
            return XrdCl::XRootDStatus{};
        });
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // k2 should initially be a waiter, then become in-flight after k1 releases.
    auto second = std::async(std::launch::async, [&]() {
        return sf.Run("k2", [&]() {
            second_signal.wait();
            return XrdCl::XRootDStatus{};
        });
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    release_leader.set_value();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // k3 arrives while k2 is in-flight; it should be able to wait (not queue_full) then timeout.
    auto third = std::async(std::launch::async, [&]() {
        return sf.Run("k3", [&]() { return XrdCl::XRootDStatus{}; });
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

}  // namespace

int main() {
    Test_WaitSlotReleasedAfterQueueTimeout();
    Test_WaitSlotReleasedOnWaitToInFlightTransition();

    if (g_failures) {
        std::cerr << g_failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "All tests passed.\n";
    return 0;
}
