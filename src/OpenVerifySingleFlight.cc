#include "OpenVerifySingleFlight.hh"

#include "OpenVerifyTimeout.hh"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <memory>

namespace {

int ReadIntEnvOrDefault(const char* name, int dflt) {
    const char* p = std::getenv(name);
    if (!p || !*p) return dflt;
    const int v = std::atoi(p);
    return v > 0 ? v : dflt;
}

double ElapsedSeconds(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

}  // namespace

OpenVerifySingleFlight::OpenVerifySingleFlight(OpenVerifyMetrics& metrics)
    : m_main_limit(ReadIntEnvOrDefault("XRD_OPENVERIFY_MAX_INFLIGHT", 32)),
      m_host_limit(std::min(m_main_limit,
                            ReadIntEnvOrDefault("XRD_OPENVERIFY_MAX_INFLIGHT_PER_HOST",
                                                std::max(1, m_main_limit / 2)))),
      m_wait_limit(ReadIntEnvOrDefault("XRD_OPENVERIFY_MAX_WAITERS", 128)),
      m_queue_timeout(std::chrono::milliseconds(OpenVerifyQueueTimeoutMs())),
      m_metrics(metrics) {}

std::string OpenVerifySingleFlight::HostPortKey(const std::string& host, int port) {
    return host + ":" + std::to_string(port);
}

size_t OpenVerifySingleFlight::HostActiveLocked(const std::string& host_key) const {
    auto it = m_host_active.find(host_key);
    return it == m_host_active.end() ? 0 : it->second;
}

void OpenVerifySingleFlight::IncHostLocked(const std::string& host_key) {
    m_host_active[host_key] += 1;
}

void OpenVerifySingleFlight::DecHostLocked(const std::string& host_key) {
    auto it = m_host_active.find(host_key);
    if (it == m_host_active.end()) return;
    if (it->second <= 1) {
        m_host_active.erase(it);
    } else {
        --it->second;
    }
}

XrdCl::XRootDStatus OpenVerifySingleFlight::HostBusyStatus() const {
    return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errThresholdExceeded, 0, "openverify_host_busy"};
}

XrdCl::XRootDStatus OpenVerifySingleFlight::Run(const std::string& key, const std::string& host, int port,
                                                const std::function<XrdCl::XRootDStatus()>& fn) {
    const std::string host_key = HostPortKey(host, port);
    const size_t host_cap = static_cast<size_t>(m_host_limit);

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

        auto reject_host_busy = [&]() -> XrdCl::XRootDStatus {
            m_metrics.RecordQueueAdmissionHostBusy();
            m_metrics.RecordHostBusy(host, port);
            return finish_leader(HostBusyStatus());
        };

        // total number of requests allowed to run concurrently
        const size_t cap = static_cast<size_t>(m_main_limit);
        // total number of requets in the wait queue
        const size_t wait_cap = static_cast<size_t>(m_wait_limit);

        std::unique_lock<std::mutex> fifo_lock(m_fifo_mutex);
        if (HostActiveLocked(host_key) >= host_cap) {
            fifo_lock.unlock();
            return reject_host_busy();
        }
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
        const auto queue_t0 = std::chrono::steady_clock::now();
        const auto deadline = queue_t0 + m_queue_timeout;

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
            m_metrics.RecordQueueWait(ElapsedSeconds(queue_t0), /*timed_out=*/true);
            m_metrics.RecordQueueAdmissionTimeout();
            return finish_leader(
                XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errOperationExpired, 0, "openverify_queue_timeout"});
        }

        // Global slot is free for the head, but this host may have hit its cap
        // while we waited (or a slot freed for a different host). Fail-fast busy
        // so the next waiter can take the global slot.
        if (HostActiveLocked(host_key) >= host_cap) {
            m_fifo.erase(my_it);
            if (!m_fifo.empty())
                m_fifo.front()->cv.notify_one();
            fifo_lock.unlock();
            m_metrics.RecordQueueWait(ElapsedSeconds(queue_t0), /*timed_out=*/false);
            return reject_host_busy();
        }

        m_fifo.pop_front();
        ++m_active;
        IncHostLocked(host_key);
        // If capacity remains, wake the new head immediately
        if (!m_fifo.empty() && m_active < cap)
            m_fifo.front()->cv.notify_one();
        fifo_lock.unlock();
        m_metrics.RecordQueueWait(ElapsedSeconds(queue_t0), /*timed_out=*/false);
        m_metrics.RecordQueueAdmissionAdmitted();

        XrdCl::XRootDStatus result;
        const auto verify_t0 = std::chrono::steady_clock::now();
        try {
            result = fn ? fn() : XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errInvalidOp, 0, "openverify_noop"};
        } catch (...) {
            result = XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errInternal, 0, "openverify_exception"};
        }
        m_metrics.RecordVerifyRtt(ElapsedSeconds(verify_t0), result.IsOK());

        {
            std::lock_guard<std::mutex> lk(m_fifo_mutex);
            --m_active;
            DecHostLocked(host_key);
            if (!m_fifo.empty())
                m_fifo.front()->cv.notify_one();
        }

        return finish_leader(result);
    }
    m_metrics.RecordSingleFlightFollower();

    // The leader's probe is bounded (open+stat+read+close). Do not wait forever
    // if that bound is missed: a stuck leader would pin every coalesced worker.
    const auto follower_limit = m_queue_timeout + std::chrono::seconds(OpenVerifyTimeoutSeconds() * 4);
    std::unique_lock<std::mutex> lk(in_flight->mtx);
    const bool finished = in_flight->cv.wait_until(lk, std::chrono::steady_clock::now() + follower_limit,
                                                    [&in_flight] { return in_flight->done; });
    if (!finished) {
        m_metrics.RecordQueueAdmissionTimeout();
        return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errOperationExpired, 0, "openverify_queue_timeout"};
    }
    return in_flight->result;
}
