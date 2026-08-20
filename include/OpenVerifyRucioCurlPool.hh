#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>

#include <curl/curl.h>

// Elastic pool of long-lived libcurl easy handles plus a CURLSH share (DNS +
// SSL session). TCP+TLS stays on each easy handle across curl_easy_reset.
//
// XRD_OPENVERIFY_RUCIO_POOL_MIN   warm handles (default 50; min 1)
// XRD_OPENVERIFY_RUCIO_POOL_MAX   cap (default 500; >= min)
// XRD_OPENVERIFY_RUCIO_POOL_SIZE  optional alias for MIN (compat)
//
// Grows when all handles are busy (up to MAX). Shrinks idle extras older than
// 15s back toward MIN on the next Acquire/Release (no janitor thread). At MAX,
// Acquire waits for a handle. Each CURL* is used by one thread at a time.
//
struct OpenVerifyRucioCurlPoolConfig {
    std::size_t min_handles{50};
    std::size_t max_handles{500};
    std::chrono::milliseconds shrink_idle{std::chrono::seconds(15)};

    static OpenVerifyRucioCurlPoolConfig FromEnv();
};

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

    explicit OpenVerifyRucioCurlPool(OpenVerifyRucioCurlPoolConfig cfg);
    OpenVerifyRucioCurlPool(std::size_t min_handles, std::size_t max_handles,
                            std::chrono::milliseconds shrink_idle = std::chrono::seconds(15));
    ~OpenVerifyRucioCurlPool();

    OpenVerifyRucioCurlPool(const OpenVerifyRucioCurlPool&) = delete;
    OpenVerifyRucioCurlPool& operator=(const OpenVerifyRucioCurlPool&) = delete;

    Handle Acquire();

    std::size_t MinSize() const { return m_min; }
    std::size_t MaxSize() const { return m_max; }
    std::size_t Size() const;
    std::size_t IdleCount() const;

   private:
    void InitShareAndWarm();
    void DestroyEasy(CURL* easy);
    void ShrinkIdleLocked(std::chrono::steady_clock::time_point now);
    void Release(CURL* easy);
    void ApplyPooledOptions(CURL* easy);
    static void ShareLock(CURL* handle, curl_lock_data data, curl_lock_access access, void* userptr);
    static void ShareUnlock(CURL* handle, curl_lock_data data, void* userptr);

    std::size_t m_min{50};
    std::size_t m_max{500};
    std::chrono::milliseconds m_shrink_idle{std::chrono::seconds(15)};

    CURLSH* m_share{nullptr};
    std::mutex m_share_locks[CURL_LOCK_DATA_LAST];

    struct IdleSlot {
        CURL* easy{nullptr};
        std::chrono::steady_clock::time_point idle_since{};
    };

    mutable std::mutex m_mu;
    std::condition_variable m_cv;
    std::deque<IdleSlot> m_idle;  // back = newest (Acquire); front = oldest (shrink)
    std::size_t m_created{0};
    std::size_t m_checked_out{0};
    bool m_stopping{false};
};
