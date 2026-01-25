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
    Expect(cache.Get(key, t0) == OpenVerifyCache::Status::Miss, "MissInitially: empty cache should miss");
}

void Test_PositivePutAndGet() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutPositive(key, std::chrono::seconds(120), t0);
    Expect(cache.Get(key, t0) == OpenVerifyCache::Status::Positive, "PositivePutAndGet: should be positive");
}

void Test_NegativePutAndGet() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutNegative(key, std::chrono::seconds(15), t0);
    Expect(cache.Get(key, t0) == OpenVerifyCache::Status::Negative, "NegativePutAndGet: should be negative");
}

void Test_TtlExpiryViaNow() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutPositive(key, std::chrono::seconds(10), t0);
    Expect(cache.Get(key, t0 + std::chrono::seconds(9)) == OpenVerifyCache::Status::Positive,
           "TtlExpiryViaNow: should be positive before expiry");
    Expect(cache.Get(key, t0 + std::chrono::seconds(10)) == OpenVerifyCache::Status::Miss,
           "TtlExpiryViaNow: should miss at expiry boundary");
    Expect(cache.Get(key, t0 + std::chrono::seconds(11)) == OpenVerifyCache::Status::Miss,
           "TtlExpiryViaNow: should miss after expiry");
}

void Test_PathSegmentationAndNormalization() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b/c", "h", 1);
    cache.PutPositive(key, std::chrono::seconds(10), t0);

    Expect(cache.Get(key, t0) == OpenVerifyCache::Status::Positive, "PathSegmentation: exact path hit");

    // Our SplitPath collapses repeated '/' so this should hit the same node.
    const auto key_slashes = MakeOpenVerifyCacheKey("/a//b///c", "h", 1);
    Expect(cache.Get(key_slashes, t0) == OpenVerifyCache::Status::Positive,
           "PathSegmentation: repeated slashes should still hit");

    const auto sibling = MakeOpenVerifyCacheKey("/a/b/d", "h", 1);
    Expect(cache.Get(sibling, t0) == OpenVerifyCache::Status::Miss, "PathSegmentation: sibling path miss");
}

void Test_HostPortIsolation() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto k1 = MakeOpenVerifyCacheKey("/a/b", "h1", 1);
    const auto k2 = MakeOpenVerifyCacheKey("/a/b", "h2", 2);
    cache.PutPositive(k1, std::chrono::seconds(10), t0);
    Expect(cache.Get(k1, t0) == OpenVerifyCache::Status::Positive, "HostPortIsolation: should hit h1:1");
    Expect(cache.Get(k2, t0) == OpenVerifyCache::Status::Miss, "HostPortIsolation: should miss h2:2");
}

void Test_ResetClearsAll() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutNegative(key, std::chrono::seconds(10), t0);
    cache.Reset();
    Expect(cache.Get(key, t0) == OpenVerifyCache::Status::Miss, "ResetClearsAll: should miss after reset");
}

void Test_ExpirePrunes() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto pkey = MakeOpenVerifyCacheKey("/a/b/c/d", "h", 1);
    const auto nkey = MakeOpenVerifyCacheKey("/x/y", "h", 9);
    cache.PutPositive(pkey, std::chrono::seconds(1), t0);
    cache.PutNegative(nkey, std::chrono::seconds(100), t0);

    cache.Expire(t0 + std::chrono::seconds(2));

    Expect(cache.Get(pkey, t0 + std::chrono::seconds(2)) == OpenVerifyCache::Status::Miss,
           "ExpirePrunes: expired entry should be removed");
    Expect(cache.Get(nkey, t0 + std::chrono::seconds(2)) == OpenVerifyCache::Status::Negative,
           "ExpirePrunes: non-expired entry should remain");
}

void Test_NoPrefixMatch() {
    OpenVerifyCache cache;
    const auto t0 = Clock::time_point{};
    const auto key_ab = MakeOpenVerifyCacheKey("/a/b", "h", 1);
    cache.PutPositive(key_ab, std::chrono::seconds(10), t0);

    const auto key_abcd = MakeOpenVerifyCacheKey("/a/b/c/d", "h", 1);
    Expect(cache.Get(key_abcd, t0) == OpenVerifyCache::Status::Miss, "NoPrefixMatch: should not match ancestor entry");
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

    if (g_failures) {
        std::cerr << g_failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "All tests passed.\n";
    return 0;
}
