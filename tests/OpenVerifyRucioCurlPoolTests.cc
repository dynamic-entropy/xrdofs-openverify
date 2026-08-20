#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "OpenVerifyRucioCurlPool.hh"

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

void RestoreEnv(const char* name, const char* old, const std::string& saved) {
    if (old) {
        setenv(name, saved.c_str(), 1);
    } else {
        unsetenv(name);
    }
}

void Test_PoolSizeFollowsMaxInflight() {
    const char* old_pool = std::getenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE");
    const std::string saved_pool = old_pool ? old_pool : "";
    const char* old_inflight = std::getenv("XRD_OPENVERIFY_MAX_INFLIGHT");
    const std::string saved_inflight = old_inflight ? old_inflight : "";

    unsetenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE");
    unsetenv("XRD_OPENVERIFY_MAX_INFLIGHT");
    Expect(OpenVerifyRucioPoolSizeFromEnv() == 32, "default tracks MAX_INFLIGHT default 32");

    setenv("XRD_OPENVERIFY_MAX_INFLIGHT", "12", 1);
    Expect(OpenVerifyRucioPoolSizeFromEnv() == 12, "unset pool size follows MAX_INFLIGHT");

    setenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE", "4", 1);
    Expect(OpenVerifyRucioPoolSizeFromEnv() == 4, "explicit pool size overrides MAX_INFLIGHT");

    RestoreEnv("XRD_OPENVERIFY_MAX_INFLIGHT", old_inflight, saved_inflight);
    RestoreEnv("XRD_OPENVERIFY_RUCIO_POOL_SIZE", old_pool, saved_pool);
}

void Test_PoolSizeFromEnvClamp() {
    const char* old = std::getenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE");
    const std::string saved = old ? old : "";
    setenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE", "0", 1);
    Expect(OpenVerifyRucioPoolSizeFromEnv() == 1, "zero clamps to 1");
    setenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE", "999", 1);
    Expect(OpenVerifyRucioPoolSizeFromEnv() == 256, "999 clamps to 256");
    setenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE", "8", 1);
    Expect(OpenVerifyRucioPoolSizeFromEnv() == 8, "8 is honored");
    RestoreEnv("XRD_OPENVERIFY_RUCIO_POOL_SIZE", old, saved);
}

void Test_AcquireReleaseAndReuse() {
    OpenVerifyRucioCurlPool pool(2);
    Expect(pool.Size() == 2, "size 2");
    Expect(pool.IdleCount() == 2, "both idle at start");

    CURL* first = nullptr;
    CURL* second = nullptr;
    {
        auto a = pool.Acquire();
        Expect(static_cast<bool>(a), "acquire a");
        Expect(pool.IdleCount() == 1, "one idle after first acquire");
        first = a.get();
        auto b = pool.Acquire();
        Expect(static_cast<bool>(b), "acquire b");
        Expect(a.get() != b.get(), "handles are distinct");
        Expect(pool.IdleCount() == 0, "none idle when both checked out");
        second = b.get();
    }
    Expect(pool.IdleCount() == 2, "both returned on Handle dtor");

    auto c = pool.Acquire();
    Expect(static_cast<bool>(c), "reacquire after release");
    Expect(c.get() == first || c.get() == second, "reuses a pooled easy handle");
}

void Test_ConcurrentCheckout() {
    OpenVerifyRucioCurlPool pool(4);
    std::atomic<int> ok{0};
    std::atomic<int> nulls{0};
    std::vector<std::thread> threads;
    threads.reserve(8);
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 50; ++i) {
                auto h = pool.Acquire();
                if (!h) {
                    ++nulls;
                    continue;
                }
                curl_easy_setopt(h.get(), CURLOPT_TIMEOUT, 1L);
                ++ok;
            }
        });
    }
    for (auto& th : threads) th.join();
    Expect(nulls == 0, "no null handles while pool is alive");
    Expect(ok == 8 * 50, "all checkouts succeeded");
    Expect(pool.IdleCount() == pool.Size(), "all handles idle after join");
}

}  // namespace

int main() {
    Test_PoolSizeFollowsMaxInflight();
    Test_PoolSizeFromEnvClamp();
    Test_AcquireReleaseAndReuse();
    Test_ConcurrentCheckout();
    if (g_failures) {
        std::cerr << g_failures << " OpenVerifyRucioCurlPool test(s) failed\n";
        return 1;
    }
    std::cout << "All OpenVerifyRucioCurlPool tests passed\n";
    return 0;
}
