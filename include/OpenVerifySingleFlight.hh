#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <semaphore>
#include <string>
#include <unordered_map>

#include "OpenVerifyMetrics.hh"
#include "XrdCl/XrdClXRootDResponses.hh"


class OpenVerifySingleFlight {
   public:
    explicit OpenVerifySingleFlight(OpenVerifyMetrics& metrics);
    OpenVerifySingleFlight(const OpenVerifySingleFlight&) = delete;
    OpenVerifySingleFlight& operator=(const OpenVerifySingleFlight&) = delete;

    // Runs `fn` once per key while in-flight; concurrent callers wait and receive the same result.
    XrdCl::XRootDStatus Run(const std::string& key, const std::function<XrdCl::XRootDStatus()>& fn);

   private:
    struct InFlight {
        std::mutex mtx;
        std::condition_variable cv;
        bool done{false};
        XrdCl::XRootDStatus result;
    };

    class SemaphorePermit {
       public:
        explicit SemaphorePermit(std::counting_semaphore<>& sem) : m_sem(&sem) {}
        SemaphorePermit(const SemaphorePermit&) = delete;
        SemaphorePermit& operator=(const SemaphorePermit&) = delete;
        SemaphorePermit(SemaphorePermit&&) = delete;
        SemaphorePermit& operator=(SemaphorePermit&&) = delete;

        ~SemaphorePermit() { Release(); }

        void Release() {
            if (m_sem != nullptr) {
                m_sem->release();
                m_sem = nullptr;
            }
        }

       private:
        std::counting_semaphore<>* m_sem{nullptr};
    };

    // constant set from XRD_OPENVERIFY_MAX_INFLIGHT
    const int m_main_limit;
    // constant set from XRD_OPENVERIFY_MAX_WAITERS
    const int m_wait_limit;

    // XRD_OPENVERIFY_QUEUE_TIMEOUT_MS
    const std::chrono::milliseconds m_queue_timeout;

    // main semaphore for the ongoing open verify operations
    std::counting_semaphore<> m_main_sem;
    // counting semaphore for the wait queue
    std::counting_semaphore<> m_wait_sem;
    OpenVerifyMetrics& m_metrics;

    mutable std::mutex m_map_mutex;
    std::unordered_map<std::string, std::shared_ptr<InFlight>> m_in_flight_map;
};
