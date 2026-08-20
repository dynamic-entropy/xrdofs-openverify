#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <vector>

#include <curl/curl.h>

// Bounded pool of long-lived libcurl easy handles plus a CURLSH share
// (DNS, SSL session, CONNECT) so TCP+TLS to cms-rucio / cms-rucio-auth is
// reused instead of curl_easy_init/cleanup per request.
//
// XRD_OPENVERIFY_RUCIO_POOL_SIZE  concurrent handles (default = MAX_INFLIGHT,
//                                 usually 32; min 1, max 256)
//
// XRootD already runs Open on worker threads; callers block on Acquire when
// the pool is busy (natural bound on concurrent Rucio HTTPS). Each handle is
// used by one thread at a time. curl_easy_reset between checkouts keeps the
// connection cache.
//
std::size_t OpenVerifyRucioPoolSizeFromEnv();

class OpenVerifyRucioCurlPool {
   public:
    class Handle {
       public:
        Handle() = default;
        Handle(OpenVerifyRucioCurlPool* pool, CURL* easy);
        ~Handle();

        Handle(Handle&& other) noexcept;
        Handle& operator=(Handle&& other) noexcept;

        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

        CURL* get() const { return m_easy; }
        explicit operator bool() const { return m_easy != nullptr; }

       private:
        OpenVerifyRucioCurlPool* m_pool{nullptr};
        CURL* m_easy{nullptr};
    };

    explicit OpenVerifyRucioCurlPool(std::size_t size);
    ~OpenVerifyRucioCurlPool();

    OpenVerifyRucioCurlPool(const OpenVerifyRucioCurlPool&) = delete;
    OpenVerifyRucioCurlPool& operator=(const OpenVerifyRucioCurlPool&) = delete;

    Handle Acquire();

    std::size_t Size() const { return m_size; }
    std::size_t IdleCount() const;

   private:
    void Release(CURL* easy);
    void ApplyPooledOptions(CURL* easy);
    static void ShareLock(CURL* handle, curl_lock_data data, curl_lock_access access, void* userptr);
    static void ShareUnlock(CURL* handle, curl_lock_data data, void* userptr);

    std::size_t m_size{0};
    CURLSH* m_share{nullptr};
    std::mutex m_share_locks[CURL_LOCK_DATA_LAST];

    mutable std::mutex m_mu;
    std::condition_variable m_cv;
    std::vector<CURL*> m_idle;
    std::size_t m_checked_out{0};
    bool m_stopping{false};
};
