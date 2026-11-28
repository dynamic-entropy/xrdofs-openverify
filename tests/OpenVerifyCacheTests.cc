#include <chrono>
#include <iostream>
#include <string>

#include "OpenVerifyCache.hh"
#include "OpenVerifyCacheKey.hh"

using Clock = std::chrono::steady_clock;

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

void Test_MissInitially() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    Expect(cache.Get(key, t0).status == OpenVerifyCache::Status::Miss, "MissInitially: empty cache should miss");
}

void Test_PositivePutAndGet() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutPositive(key, std::chrono::seconds(120), t0);
    Expect(cache.Get(key, t0).status == OpenVerifyCache::Status::Positive, "PositivePutAndGet: should be positive");
}

void Test_NegativePutAndGet() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutNegative(key, std::chrono::seconds(15), t0);
    Expect(cache.Get(key, t0).status == OpenVerifyCache::Status::Negative, "NegativePutAndGet: should be negative");
}

void Test_TtlExpiryViaNow() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutPositive(key, std::chrono::seconds(10), t0);
    Expect(cache.Get(key, t0 + std::chrono::seconds(9)).status == OpenVerifyCache::Status::Positive,
           "TtlExpiryViaNow: should be positive before expiry");
    Expect(cache.Get(key, t0 + std::chrono::seconds(10)).status == OpenVerifyCache::Status::Miss,
           "TtlExpiryViaNow: should miss at expiry boundary");
    Expect(cache.Get(key, t0 + std::chrono::seconds(11)).status == OpenVerifyCache::Status::Miss,
           "TtlExpiryViaNow: should miss after expiry");
}

void Test_PathSegmentationAndNormalization() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b/c", "h", 1);
    cache.PutPositive(key, std::chrono::seconds(10), t0);

    Expect(cache.Get(key, t0).status == OpenVerifyCache::Status::Positive, "PathSegmentation: exact path hit");

    // Our SplitPath collapses repeated '/' so this should hit the same node.
    const auto key_slashes = MakeOpenVerifyCacheKey("/a//b///c", "h", 1);
    Expect(cache.Get(key_slashes, t0).status == OpenVerifyCache::Status::Positive,
           "PathSegmentation: repeated slashes should still hit");

    const auto sibling = MakeOpenVerifyCacheKey("/a/b/d", "h", 1);
    Expect(cache.Get(sibling, t0).status == OpenVerifyCache::Status::Miss, "PathSegmentation: sibling path miss");
}

void Test_HostPortIsolation() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto k1 = MakeOpenVerifyCacheKey("/a/b", "h1", 1);
    const auto k2 = MakeOpenVerifyCacheKey("/a/b", "h2", 2);
    cache.PutPositive(k1, std::chrono::seconds(10), t0);
    Expect(cache.Get(k1, t0).status == OpenVerifyCache::Status::Positive, "HostPortIsolation: should hit h1:1");
    Expect(cache.Get(k2, t0).status == OpenVerifyCache::Status::Miss, "HostPortIsolation: should miss h2:2");
}

void Test_ResetClearsAll() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutNegative(key, std::chrono::seconds(10), t0);
    cache.Reset();
    Expect(cache.Get(key, t0).status == OpenVerifyCache::Status::Miss, "ResetClearsAll: should miss after reset");
}

void Test_ExpirePrunes() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto pkey = MakeOpenVerifyCacheKey("/a/b/c/d", "h", 1);
    const auto nkey = MakeOpenVerifyCacheKey("/x/y", "h", 9);
    cache.PutPositive(pkey, std::chrono::seconds(1), t0);
    cache.PutNegative(nkey, std::chrono::seconds(100), t0);

    cache.Expire(t0 + std::chrono::seconds(2));

    Expect(cache.Get(pkey, t0 + std::chrono::seconds(2)).status == OpenVerifyCache::Status::Miss,
           "ExpirePrunes: expired entry should be removed");
    Expect(cache.Get(nkey, t0 + std::chrono::seconds(2)).status == OpenVerifyCache::Status::Negative,
           "ExpirePrunes: non-expired entry should remain");
}

void Test_NoPrefixMatch() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key_ab = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutPositive(key_ab, std::chrono::seconds(10), t0);

    const auto key_abcd = MakeOpenVerifyCacheKey("/a/b/c/d", "h", 1);
    Expect(cache.Get(key_abcd, t0).status == OpenVerifyCache::Status::Miss,
           "NoPrefixMatch: should not match ancestor entry");
}

void Test_EvictsOldestWhenOverCap() {
    OpenVerifyCache cache(2);
    const auto t0 = Clock::time_point{};
    const auto k1 = MakeOpenVerifyCacheKey("/a", "h", 1);
    const auto k2 = MakeOpenVerifyCacheKey("/b", "h", 1);
    const auto k3 = MakeOpenVerifyCacheKey("/c", "h", 1);
    cache.PutPositive(k1, std::chrono::seconds(30), t0);
    cache.PutPositive(k2, std::chrono::seconds(30), t0);
    cache.PutPositive(k1, std::chrono::seconds(30), t0);  // refresh k1 so k2 is oldest
    cache.PutNegative(k3, std::chrono::seconds(30), t0);
    Expect(cache.Get(k2, t0).status == OpenVerifyCache::Status::Miss, "Evict: oldest entry dropped");
    Expect(cache.Get(k1, t0).status == OpenVerifyCache::Status::Positive, "Evict: refreshed entry kept");
    Expect(cache.Get(k3, t0).status == OpenVerifyCache::Status::Negative, "Evict: newest entry kept");
}

void Test_PositiveStoresFinalServer() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "redir", 1094);
    cache.PutPositive(key, std::chrono::seconds(60), "disk.example", 1095, t0);

    const auto hit = cache.Get(key, t0);
    Expect(hit.status == OpenVerifyCache::Status::Positive, "PositiveStoresFinalServer: status");
    Expect(hit.final_host == "disk.example", "PositiveStoresFinalServer: host");
    Expect(hit.final_port == 1095, "PositiveStoresFinalServer: port");

    cache.PutPositive(key, std::chrono::seconds(60), t0);
    const auto no_ds = cache.Get(key, t0);
    Expect(no_ds.status == OpenVerifyCache::Status::Positive, "PositiveStoresFinalServer: overwrite status");
    Expect(no_ds.final_host.empty(), "PositiveStoresFinalServer: overwrite clears host");
    Expect(no_ds.final_port == -1, "PositiveStoresFinalServer: overwrite clears port");
}

}  // namespace

int main() {
    Test_MissInitially();
    Test_PositivePutAndGet();
    Test_NegativePutAndGet();
    Test_TtlExpiryViaNow();
    Test_PathSegmentationAndNormalization();
    Test_HostPortIsolation();
    Test_ResetClearsAll();
    Test_ExpirePrunes();
    Test_NoPrefixMatch();
    Test_EvictsOldestWhenOverCap();
    Test_PositiveStoresFinalServer();

    if (g_failures) {
        std::cerr << g_failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "All tests passed.\n";
    return 0;
}
