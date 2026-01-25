#pragma once

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// A path-segment trie cache keyed by path, storing whether a previous
// open_verify succeeded ("positive") or failed ("negative") with TTLs.
//
class OpenVerifyCache {
   public:
    enum class Status { Miss, Positive, Negative };

    OpenVerifyCache() = default;
    OpenVerifyCache(const OpenVerifyCache&) = delete;
    OpenVerifyCache& operator=(const OpenVerifyCache&) = delete;
    ~OpenVerifyCache();

    void StartExpiryThread();

    void StopExpiryThread();

    // Lookup for a key (exact match).
    Status Get(const std::string& key,
               std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;

    void PutPositive(const std::string& key, std::chrono::seconds ttl,
                     std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void PutNegative(const std::string& key, std::chrono::seconds ttl,
                     std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void Expire(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void Reset();

   private:
    struct Entry {
        Status status;
        std::chrono::steady_clock::time_point expiry;
    };

    struct Node {
        std::unordered_map<std::string, std::unique_ptr<Node>> children;
        std::unique_ptr<Entry> entry;
    };

    void ExpireThread();

    static std::vector<std::string> SplitPath(const std::string& path);
    Node* TraverseCreate(const std::vector<std::string>& segments);
    const Node* Traverse(const std::vector<std::string>& segments) const;

    std::mutex m_shutdown_lock;
    std::condition_variable m_shutdown_requested_cv;
    bool m_shutdown_requested = false;
    std::condition_variable m_shutdown_complete_cv;
    bool m_shutdown_complete = true;  // true until thread starts
    bool m_thread_started = false;
    std::thread m_expiry_thread;

    mutable std::shared_mutex m_mutex;
    Node m_root;
};
