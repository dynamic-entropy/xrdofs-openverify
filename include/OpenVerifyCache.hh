#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <list>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

// Exact-match verify cache (path + host + port) with TTLs.
// Positive entries may also retain the final data-server host:port observed
// during verify (for XRD_OPENVERIFY_DIRECT_SERVER).
//
// XRD_OPENVERIFY_CACHE_MAX: maximum entries (default 65536). 0 disables the
// cap. Expired entries are treated as misses immediately and reclaimed by
// the expiry thread. Repeated '/' in a key collapse, matching the old trie.
//
class OpenVerifyCache {
   public:
    enum class Status { Miss, Positive, Negative };

    struct Lookup {
        Status status{Status::Miss};
        // Set only for Positive hits when a data server was recorded at Put time.
        std::string final_host;
        int final_port{-1};
    };

    // max_entries == 0 reads XRD_OPENVERIFY_CACHE_MAX (default 65536; env 0 is unlimited).
    explicit OpenVerifyCache(std::size_t max_entries = 0);
    OpenVerifyCache(const OpenVerifyCache&) = delete;
    OpenVerifyCache& operator=(const OpenVerifyCache&) = delete;
    ~OpenVerifyCache();

    void StartExpiryThread();

    void StopExpiryThread();

    // Lookup for a key (exact match).
    Lookup Get(const std::string& key,
               std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;

    void PutPositive(const std::string& key, std::chrono::seconds ttl,
                     std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void PutPositive(const std::string& key, std::chrono::seconds ttl, std::string final_host, int final_port,
                     std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void PutNegative(const std::string& key, std::chrono::seconds ttl,
                     std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void Expire(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void Reset();

   private:
    struct Entry {
        Status status{Status::Miss};
        std::chrono::steady_clock::time_point expiry{};
        std::string final_host;
        int final_port{-1};
        std::list<std::string>::iterator lru_it{};
    };

    void ExpireThread();
    static std::size_t MaxFromEnv();
    static std::string NormalizeKey(const std::string& key);
    void EvictOverflowLocked();

    std::size_t m_max_entries{0};

    std::mutex m_shutdown_lock;
    std::condition_variable m_shutdown_requested_cv;
    bool m_shutdown_requested = false;
    std::condition_variable m_shutdown_complete_cv;
    bool m_shutdown_complete = true;  // true until thread starts
    bool m_thread_started = false;
    std::thread m_expiry_thread;

    mutable std::shared_mutex m_mutex;
    // Front is newest. Keys are normalized.
    std::list<std::string> m_lru;
    std::unordered_map<std::string, Entry> m_map;
};
