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

        // total number of requests allowed to run concurrently
        const size_t cap = static_cast<size_t>(m_main_limit);
        // total number of requets in the wait queue
        const size_t wait_cap = static_cast<size_t>(m_wait_limit);

        std::unique_lock<std::mutex> fifo_lock(m_fifo_mutex);
        if (m_fifo.size() >= wait_cap) {
            fifo_lock.unlock();
            m_metrics.RecordQueueAdmissionFull();
            return finish_leader(
                XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errThresholdExceeded, 0, "openverify_queue_full"});
        }

        // get a ticket to wait and push to the fifo queue
        FifoWaitTag tag;
        m_fifo.push_back(&tag);
        const auto my_it = std::prev(m_fifo.end());
        const auto deadline = std::chrono::steady_clock::now() + m_queue_timeout;

        // wait_until checks the predicate before blocking
        // so the first requets always go through without waiting
        const bool admitted = tag.cv.wait_until(fifo_lock, deadline, [&] {
            return m_fifo.front() == &tag && m_active < cap;
        });

        if (!admitted) {
            // Timed out: erase self from the queue. If we were at the front, wake the
            // new head so it can check whether a slot is now available.
            const bool was_front = (my_it == m_fifo.begin());
            m_fifo.erase(my_it);
            if (was_front && !m_fifo.empty())
                m_fifo.front()->cv.notify_one();
            fifo_lock.unlock();
            m_metrics.RecordQueueAdmissionTimeout();
            return finish_leader(
                XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errOperationExpired, 0, "openverify_queue_timeout"});
        }

        m_fifo.pop_front();
        ++m_active;
        // If capacity remains, wake the new head immediately
        if (!m_fifo.empty() && m_active < cap)
            m_fifo.front()->cv.notify_one();
        fifo_lock.unlock();
        m_metrics.RecordQueueAdmissionAdmitted();

        XrdCl::XRootDStatus result;
        try {
            result = fn ? fn() : XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errInvalidOp, 0, "openverify_noop"};
        } catch (...) {
            result = XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errInternal, 0, "openverify_exception"};
        }

        {
            std::lock_guard<std::mutex> lk(m_fifo_mutex);
            --m_active;
            if (!m_fifo.empty())
                m_fifo.front()->cv.notify_one();
        }

        return finish_leader(result);
    }
    m_metrics.RecordSingleFlightFollower();

    std::unique_lock<std::mutex> lk(in_flight->mtx);
    in_flight->cv.wait(lk, [&in_flight] { return in_flight->done; });
    return in_flight->result;
}
