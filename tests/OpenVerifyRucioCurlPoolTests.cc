#include <atomic>
#include <chrono>
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

void Test_PoolConfigFromEnvDefaults() {
    const char* old_min = std::getenv("XRD_OPENVERIFY_RUCIO_POOL_MIN");
    const std::string saved_min = old_min ? old_min : "";
    const char* old_max = std::getenv("XRD_OPENVERIFY_RUCIO_POOL_MAX");
    const std::string saved_max = old_max ? old_max : "";
    const char* old_size = std::getenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE");
    const std::string saved_size = old_size ? old_size : "";

    unsetenv("XRD_OPENVERIFY_RUCIO_POOL_MIN");
    unsetenv("XRD_OPENVERIFY_RUCIO_POOL_MAX");
    unsetenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE");
    auto cfg = OpenVerifyRucioCurlPoolConfig::FromEnv();
    Expect(cfg.min_handles == 1, "default min 1");
    Expect(cfg.max_handles == 500, "default max 500");

    setenv("XRD_OPENVERIFY_RUCIO_POOL_MIN", "5", 1);
    setenv("XRD_OPENVERIFY_RUCIO_POOL_MAX", "20", 1);
    cfg = OpenVerifyRucioCurlPoolConfig::FromEnv();
    Expect(cfg.min_handles == 5 && cfg.max_handles == 20, "min/max env");

    unsetenv("XRD_OPENVERIFY_RUCIO_POOL_MIN");
    unsetenv("XRD_OPENVERIFY_RUCIO_POOL_MAX");
    setenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE", "8", 1);
    cfg = OpenVerifyRucioCurlPoolConfig::FromEnv();
    Expect(cfg.min_handles == 8, "POOL_SIZE aliases min");
    Expect(cfg.max_handles == 500, "POOL_SIZE leaves default max");

    setenv("XRD_OPENVERIFY_RUCIO_POOL_MIN", "80", 1);
    setenv("XRD_OPENVERIFY_RUCIO_POOL_MAX", "40", 1);
    cfg = OpenVerifyRucioCurlPoolConfig::FromEnv();
    Expect(cfg.min_handles == 80 && cfg.max_handles == 80, "max raised to min");

    setenv("XRD_OPENVERIFY_RUCIO_POOL_MIN", "0", 1);
    setenv("XRD_OPENVERIFY_RUCIO_POOL_MAX", "999", 1);
    cfg = OpenVerifyRucioCurlPoolConfig::FromEnv();
    Expect(cfg.min_handles == 1, "min 0 clamps to 1");
    Expect(cfg.max_handles == 500, "max 999 clamps to 500");

    RestoreEnv("XRD_OPENVERIFY_RUCIO_POOL_MIN", old_min, saved_min);
    RestoreEnv("XRD_OPENVERIFY_RUCIO_POOL_MAX", old_max, saved_max);
    RestoreEnv("XRD_OPENVERIFY_RUCIO_POOL_SIZE", old_size, saved_size);
}

void Test_AcquireReleaseAndReuse() {
    OpenVerifyRucioCurlPool pool(2, 2);
    Expect(pool.MinSize() == 2 && pool.MaxSize() == 2, "fixed 2/2");
    Expect(pool.Size() == 2, "size 2");
    Expect(pool.IdleCount() == 2, "both idle at start");

    CURL* first = nullptr;
    CURL* second = nullptr;
    {
        auto a = pool.Acquire();
        Expect(static_cast<bool>(a), "acquire a");
        Expect(a.Reused(), "warm handle is reused");
        Expect(pool.IdleCount() == 1, "one idle after first acquire");
        first = a.get();
        auto b = pool.Acquire();
        Expect(static_cast<bool>(b), "acquire b");
        Expect(b.Reused(), "second warm handle is reused");
        Expect(a.get() != b.get(), "handles are distinct");
        Expect(pool.IdleCount() == 0, "none idle when both checked out");
        second = b.get();
    }
    Expect(pool.IdleCount() == 2, "both returned on Handle dtor");

    auto c = pool.Acquire();
    Expect(static_cast<bool>(c), "reacquire after release");
    Expect(c.Reused(), "reacquire marks reused");
    Expect(c.get() == first || c.get() == second, "reuses a pooled easy handle");
}

void Test_GrowsWithDemand() {
    OpenVerifyRucioCurlPool pool(2, 8, std::chrono::hours(1));
    Expect(pool.Size() == 2, "grow: start at min");
    auto a = pool.Acquire();
    auto b = pool.Acquire();
    Expect(a.Reused() && b.Reused(), "grow: min handles reused");
    Expect(pool.IdleCount() == 0, "grow: min checked out");
    auto c = pool.Acquire();
    Expect(static_cast<bool>(c), "grow: third acquire succeeds");
    Expect(!c.Reused(), "grow: new handle under load");
    Expect(pool.Size() == 3, "grow: created 3");
    Expect(pool.GetStats().grows == 1, "grow: one demand-driven create");
    Expect(pool.IdleCount() == 0, "grow: all in use");
    c = {};
    Expect(pool.Size() == 3, "grow: extra kept while idle TTL not elapsed");
    Expect(pool.IdleCount() == 1, "grow: extra returned to idle");
    auto d = pool.Acquire();
    Expect(d.Reused(), "grow: extra later reused from idle");
}

void Test_ShrinksIdleExtras() {
    OpenVerifyRucioCurlPool pool(2, 8, std::chrono::milliseconds(0));
    std::vector<OpenVerifyRucioCurlPool::Handle> held;
    held.reserve(5);
    for (int i = 0; i < 5; ++i) held.push_back(pool.Acquire());
    Expect(pool.Size() == 5, "shrink: grew to 5");
    Expect(pool.GetStats().grows == 3, "shrink: grew 3 above min");
    held.clear();
    Expect(pool.Size() == 2, "shrink: extras destroyed immediately (TTL 0)");
    Expect(pool.IdleCount() == 2, "shrink: min remain idle");
    Expect(pool.GetStats().shrinks == 3, "shrink: destroyed 3 extras");
}

void Test_ConcurrentCheckout() {
    OpenVerifyRucioCurlPool pool(2, 32, std::chrono::hours(1));
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
    Expect(pool.Size() >= 2 && pool.Size() <= 32, "concurrent: stayed in [min,max]");
    Expect(pool.IdleCount() == pool.Size(), "all handles idle after join");
}

}  // namespace

int main() {
    Test_PoolConfigFromEnvDefaults();
    Test_AcquireReleaseAndReuse();
    Test_GrowsWithDemand();
    Test_ShrinksIdleExtras();
    Test_ConcurrentCheckout();
    if (g_failures) {
        std::cerr << g_failures << " OpenVerifyRucioCurlPool test(s) failed\n";
        return 1;
    }
    std::cout << "All OpenVerifyRucioCurlPool tests passed\n";
    return 0;
}
