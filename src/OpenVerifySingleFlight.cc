#include "OpenVerifySingleFlight.hh"

#include <cstdlib>
#include <memory>

namespace {

int ReadIntEnvOrDefault(const char* name, int dflt) {
    const char* p = std::getenv(name);
    if (!p || !*p) return dflt;
    const int v = std::atoi(p);
    return v > 0 ? v : dflt;
}

}  // namespace

OpenVerifySingleFlight::OpenVerifySingleFlight(OpenVerifyMetrics& metrics)
    : m_main_limit(ReadIntEnvOrDefault("XRD_OPENVERIFY_MAX_INFLIGHT", 32)),
      m_wait_limit(ReadIntEnvOrDefault("XRD_OPENVERIFY_MAX_WAITERS", 128)),
      m_queue_timeout(std::chrono::milliseconds(ReadIntEnvOrDefault("XRD_OPENVERIFY_QUEUE_TIMEOUT_MS", 5000))),
      m_main_sem(m_main_limit),
      m_wait_sem(m_wait_limit),
      m_metrics(metrics) {}

XrdCl::XRootDStatus OpenVerifySingleFlight::Run(const std::string& key, const std::function<XrdCl::XRootDStatus()>& fn) {
    std::shared_ptr<InFlight> in_flight;
    bool leader = false;
    {
        std::lock_guard<std::mutex> map_lock(m_map_mutex);
        auto existing = m_in_flight_map.find(key);
        if (existing == m_in_flight_map.end()) {
            in_flight = std::make_shared<InFlight>();
            m_in_flight_map.emplace(key, in_flight);
            leader = true;
        } else {
            in_flight = existing->second;
        }
    }

    if (leader) {
        m_metrics.RecordSingleFlightLeader();
        // helper to signal followers with requests for the same key to stop waiting
        // and erase the key from map
        auto finish_leader = [&](XrdCl::XRootDStatus result) -> XrdCl::XRootDStatus {
            {
                std::lock_guard<std::mutex> lk(in_flight->mtx);
                in_flight->result = result;
                in_flight->done = true;
            }
            in_flight->cv.notify_all();
            std::lock_guard<std::mutex> erase_lock(m_map_mutex);
            auto it = m_in_flight_map.find(key);
            if (it != m_in_flight_map.end() && it->second == in_flight) {
                m_in_flight_map.erase(it);
            }
            return result;
        };

        // if queue is full / number of waiting ov requests is greater than configured wait value
        // return with queue_full
        if (!m_wait_sem.try_acquire()) {
            m_metrics.RecordQueueAdmissionFull();
            return finish_leader(
                XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errThresholdExceeded, 0, "openverify_queue_full"});
        }

        // we have been admitted to the queue now
        SemaphorePermit wait_permit(m_wait_sem);
        // We wait for maximum m_queue_timeout to acquire the main-semaphore 
        // This is analogous to staying in a wait queue for the same time period
        // Acquiring the semaphore allows us a permit to perform the operation
        if (!m_main_sem.try_acquire_for(m_queue_timeout)) {
            m_metrics.RecordQueueAdmissionTimeout();
            return finish_leader(
                XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errOperationExpired, 0, "openverify_queue_timeout"});
        }
        m_metrics.RecordQueueAdmissionAdmitted();

        // Successful in acquiring the main semaphore
        // Move on to the open_verify call; remember to release the wait permit
        SemaphorePermit main_permit(m_main_sem);
        wait_permit.Release();

        XrdCl::XRootDStatus result;
        try {
            result = fn ? fn() : XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errInvalidOp, 0, "openverify_noop"};
        } catch (...) {
            result = XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errInternal, 0, "openverify_exception"};
        }

        return finish_leader(result);
    }
    m_metrics.RecordSingleFlightFollower();

    std::unique_lock<std::mutex> lk(in_flight->mtx);
    in_flight->cv.wait(lk, [&in_flight] { return in_flight->done; });
    return in_flight->result;
}
