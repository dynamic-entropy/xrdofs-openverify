#include <chrono>
#include <iostream>
#include <string>

#include "OpenVerifyRucioListCache.hh"

using Clock = std::chrono::steady_clock;

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

OpenVerifyRucioCandidate Cand(const std::string& host, int port, const std::string& pfn) {
    OpenVerifyRucioCandidate c;
    c.host = host;
    c.port = port;
    c.pfn = pfn;
    return c;
}

void Test_DisabledTtlZero() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(0);
    cfg.max_entries = 8;
    OpenVerifyRucioListCache cache(cfg);
    Expect(!cache.Enabled(), "DisabledTtlZero: not enabled");
    const auto t0 = Clock::time_point{};
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("h", 1094, "root://h:1094//store/a.root")},
              t0);
    Expect(!cache.Get("/store/a.root", "root", t0).hit, "DisabledTtlZero: put is ignored");
}

void Test_DisabledSizeZero() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(60);
    cfg.max_entries = 0;
    OpenVerifyRucioListCache cache(cfg);
    Expect(!cache.Enabled(), "DisabledSizeZero: not enabled");
}

void Test_HitMissAndCopy() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(60);
    cfg.max_entries = 8;
    OpenVerifyRucioListCache cache(cfg);
    const auto t0 = Clock::time_point{};
    const auto cands = std::vector<OpenVerifyRucioCandidate>{
        Cand("gfe02.grid.hep.ph.ic.ac.uk", 1094, "root://gfe02.grid.hep.ph.ic.ac.uk:1094//pnfs/a.root"),
        Cand("xrootd-cms.infn.it", 1194, "root://xrootd-cms.infn.it:1194//store/a.root"),
    };
    Expect(!cache.Get("/store/a.root", "root", t0).hit, "HitMiss: initial miss");
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::Ok, cands, t0);
    const auto hit = cache.Get("/store/a.root", "root", t0);
    Expect(hit.hit, "HitMiss: hit");
    Expect(hit.status == OpenVerifyRucioLookupResult::Ok, "HitMiss: status ok");
    Expect(hit.candidates.size() == 2, "HitMiss: two candidates");
    Expect(hit.candidates[0].host == "gfe02.grid.hep.ph.ic.ac.uk", "HitMiss: host 0");
    Expect(hit.candidates[0].pfn.find("/pnfs/") != std::string::npos, "HitMiss: pfn 0");
    Expect(hit.candidates[1].host == "xrootd-cms.infn.it" && hit.candidates[1].port == 1194, "HitMiss: host 1");
    Expect(cache.Get("/store/other.root", "root", t0).hit == false, "HitMiss: other lfn miss");
}

void Test_SchemeIsolationAndNormalize() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(60);
    cfg.max_entries = 8;
    OpenVerifyRucioListCache cache(cfg);
    const auto t0 = Clock::time_point{};
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("h", 1094, "root://h:1094//store/a.root")},
              t0);
    Expect(cache.Get("/store/a.root", "xroot", t0).hit, "Scheme: xroot shares root key");
    Expect(!cache.Get("/store/a.root", "davs", t0).hit, "Scheme: davs is distinct");
    cache.Put("//store/a.root/", "https", OpenVerifyRucioLookupResult::Ok,
              {Cand("d", 443, "davs://d:443/store/a.root")}, t0);
    Expect(cache.Get("/store/a.root", "davs", t0).hit, "Scheme: https/davs + slash normalize");
}

void Test_EmptyCached() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(30);
    cfg.max_entries = 4;
    OpenVerifyRucioListCache cache(cfg);
    const auto t0 = Clock::time_point{};
    cache.Put("/store/missing.root", "root", OpenVerifyRucioLookupResult::Empty, {}, t0);
    const auto hit = cache.Get("/store/missing.root", "root", t0);
    Expect(hit.hit, "Empty: hit");
    Expect(hit.status == OpenVerifyRucioLookupResult::Empty, "Empty: status");
    Expect(hit.candidates.empty(), "Empty: no pfns");
}

void Test_ErrorNotCached() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(30);
    cfg.max_entries = 4;
    OpenVerifyRucioListCache cache(cfg);
    const auto t0 = Clock::time_point{};
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::Timeout, {}, t0);
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::Error, {}, t0);
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::AuthError, {}, t0);
    Expect(!cache.Get("/store/a.root", "root", t0).hit, "ErrorNotCached: timeout/error/auth ignored");
}

void Test_TtlExpiry() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(10);
    cfg.max_entries = 4;
    OpenVerifyRucioListCache cache(cfg);
    const auto t0 = Clock::time_point{};
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("h", 1094, "root://h//store/a.root")}, t0);
    Expect(cache.Get("/store/a.root", "root", t0 + std::chrono::seconds(9)).hit, "Ttl: hit before expiry");
    Expect(!cache.Get("/store/a.root", "root", t0 + std::chrono::seconds(10)).hit, "Ttl: miss at expiry");
    Expect(cache.Size() == 0, "Ttl: expired entry dropped");
}

void Test_LruEviction() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(60);
    cfg.max_entries = 2;
    OpenVerifyRucioListCache cache(cfg);
    const auto t0 = Clock::time_point{};
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("a", 1094, "root://a//a")}, t0);
    cache.Put("/store/b.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("b", 1094, "root://b//b")}, t0);
    Expect(cache.Size() == 2, "Lru: two entries");
    // Touch a so b is LRU.
    Expect(cache.Get("/store/a.root", "root", t0).hit, "Lru: touch a");
    cache.Put("/store/c.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("c", 1094, "root://c//c")}, t0);
    Expect(cache.Size() == 2, "Lru: still two after insert");
    Expect(!cache.Get("/store/b.root", "root", t0).hit, "Lru: b evicted");
    Expect(cache.Get("/store/a.root", "root", t0).hit, "Lru: a kept");
    Expect(cache.Get("/store/c.root", "root", t0).hit, "Lru: c kept");
}

void Test_PutRefreshPromotes() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(10);
    cfg.max_entries = 2;
    OpenVerifyRucioListCache cache(cfg);
    const auto t0 = Clock::time_point{};
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("a", 1094, "root://a//a")}, t0);
    cache.Put("/store/b.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("b", 1094, "root://b//b")}, t0);
    // Refresh a at t0+5: new TTL and MRU.
    cache.Put("/store/a.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("a2", 1094, "root://a2//a")},
              t0 + std::chrono::seconds(5));
    Expect(cache.Get("/store/a.root", "root", t0 + std::chrono::seconds(14)).hit, "Refresh: ttl extended");
    cache.Put("/store/c.root", "root", OpenVerifyRucioLookupResult::Ok, {Cand("c", 1094, "root://c//c")},
              t0 + std::chrono::seconds(5));
    Expect(!cache.Get("/store/b.root", "root", t0 + std::chrono::seconds(5)).hit, "Refresh: b evicted not a");
}

}  // namespace

int main() {
    Test_DisabledTtlZero();
    Test_DisabledSizeZero();
    Test_HitMissAndCopy();
    Test_SchemeIsolationAndNormalize();
    Test_EmptyCached();
    Test_ErrorNotCached();
    Test_TtlExpiry();
    Test_LruEviction();
    Test_PutRefreshPromotes();

    if (g_failures) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "All OpenVerifyRucioListCache tests passed\n";
    return 0;
}
