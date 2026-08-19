#pragma once

#include <chrono>
#include <cstddef>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "OpenVerifyRucio.hh"

// TTL LRU of Rucio list_replicas results: (lfn, scheme) → PFN candidates.
//
// XRD_OPENVERIFY_RUCIO_CACHE_TTL    seconds (default 60; 0 disables)
// XRD_OPENVERIFY_RUCIO_CACHE_SIZE   max entries (default 8192; 0 disables)
//
// Key is normalized LFN + Rucio protocol id (root|davs). Client IP is not part
// of the key: the replica *set* is cached, then OpenVerifyRucioSelector re-orders
// on every hit. Auth/timeout/error responses are not stored.
//
struct OpenVerifyRucioListCacheConfig {
    std::chrono::seconds ttl{60};
    std::size_t max_entries{8192};

    static OpenVerifyRucioListCacheConfig FromEnv();
};

class OpenVerifyRucioListCache {
   public:
    struct Lookup {
        bool hit{false};
        OpenVerifyRucioLookupResult status{OpenVerifyRucioLookupResult::Ok};
        std::vector<OpenVerifyRucioCandidate> candidates;
    };

    explicit OpenVerifyRucioListCache(OpenVerifyRucioListCacheConfig cfg = {});

    bool Enabled() const { return m_ttl.count() > 0 && m_max_entries > 0; }
    std::chrono::seconds Ttl() const { return m_ttl; }
    std::size_t MaxEntries() const { return m_max_entries; }

    Lookup Get(const std::string& lfn, const std::string& scheme,
               std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    // Stores Ok (with candidates) and Empty only. Other statuses are ignored.
    void Put(const std::string& lfn, const std::string& scheme, OpenVerifyRucioLookupResult status,
             const std::vector<OpenVerifyRucioCandidate>& candidates,
             std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    std::size_t Size() const;
    void Reset();

   private:
    struct Key {
        std::string scheme;
        std::string lfn;
        bool operator==(const Key& o) const { return scheme == o.scheme && lfn == o.lfn; }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept {
            return std::hash<std::string>{}(k.scheme) ^ (std::hash<std::string>{}(k.lfn) << 1);
        }
    };
    struct Entry {
        OpenVerifyRucioLookupResult status{OpenVerifyRucioLookupResult::Ok};
        std::vector<OpenVerifyRucioCandidate> candidates;
        std::chrono::steady_clock::time_point expiry{};
    };

    static Key MakeKey(const std::string& lfn, const std::string& scheme);

    const std::chrono::seconds m_ttl;
    const std::size_t m_max_entries;

    mutable std::mutex m_mu;
    std::list<Key> m_lru;  // front = most recently used
    std::unordered_map<Key, std::pair<Entry, std::list<Key>::iterator>, KeyHash> m_map;
};
