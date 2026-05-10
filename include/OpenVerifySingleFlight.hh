#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
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

    // Each waiting leader holds one of these on its stack; the per-waiter CV allows
    // targeted wakeup (notify_one on the head) instead of notify_all.
    struct FifoWaitTag {
        std::condition_variable cv;
    };

    // Maximum leaders admitted to run concurrently (XRD_OPENVERIFY_MAX_INFLIGHT).
    const int m_main_limit;
    // Maximum leaders allowed to wait in the FIFO backlog (XRD_OPENVERIFY_MAX_WAITERS).
    const int m_wait_limit;

    // XRD_OPENVERIFY_QUEUE_TIMEOUT_MS
    const std::chrono::milliseconds m_queue_timeout;

    std::mutex m_fifo_mutex;
    std::list<FifoWaitTag*> m_fifo;
    size_t m_active{0};

    OpenVerifyMetrics& m_metrics;

    mutable std::mutex m_map_mutex;
    std::unordered_map<std::string, std::shared_ptr<InFlight>> m_in_flight_map;
};
