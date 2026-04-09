#include <algorithm>

#include "OpenVerifyHostReliability.hh"

namespace {

double FailureWeightForCode(uint16_t code) {
    // We take the error classes defined in XrdCl/XrdClStatus.hh
    // 100s socket/network, 200s protocol/session, 300s xrootd, 400s error response/local.
    const uint16_t bucket = static_cast<uint16_t>(code / 100);
    switch (bucket) {
        case 1:
            return 1.0;  // reachability/connectivity
        case 2:
            return 0.7;  // protocol/session/auth-ish
        case 3:
            return 0.6;  // xrootd-level
        case 4:
            return 0.6;  // server response/local
        case 5:
            return 0.6;  // negative response
        default:
            return 0.6;  // generic/unknown
    }
}

}  // namespace

OpenVerifyHostReliability::OpenVerifyHostReliability()
    : m_ewma_alpha_fail(0.05),
      m_ewma_alpha_success(0.10),
      m_min_attempts(20),
      m_quarantine_threshold(0.6),
      m_recover_threshold(0.4),
      m_probe_cooldown(std::chrono::seconds(60)) {}

std::string OpenVerifyHostReliability::HostPortKey(const std::string& host, int port) {
    return host + ":" + std::to_string(port);
}

void OpenVerifyHostReliability::UpdateHealthState(HostStats& stats) {
    const uint64_t attempts = stats.successes + stats.failures;
    if (attempts < m_min_attempts) return;

    const double q = std::clamp(m_quarantine_threshold, 0.0, 1.0);
    const double r = std::clamp(m_recover_threshold, 0.0, q);
    if (stats.healthy && stats.ewma_health >= q) {
        stats.healthy = false;
        // Start cooldown from transition to unhealthy.
        stats.last_probe_at = std::chrono::steady_clock::now();
    } else if (!stats.healthy && stats.ewma_health <= r) {
        stats.healthy = true;
        stats.last_probe_at = std::chrono::steady_clock::time_point{};
    }
}

bool OpenVerifyHostReliability::AvoidSite(const std::string& host, int port) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_hoststat_map.find(HostPortKey(host, port));
    if (it == m_hoststat_map.end()) return false;
    HostStats& stats = it->second;
    if (stats.healthy) return false;
    // Allow probing of unhealthy sites
    if (stats.last_probe_at.time_since_epoch().count() == 0 || (now - stats.last_probe_at) >= m_probe_cooldown) {
        return false;
    }
    return true;
}

void OpenVerifyHostReliability::RecordVerifySuccess(const std::string& host, int port) {
    std::lock_guard<std::mutex> lock(m_mtx);
    HostStats& stats = m_hoststat_map[HostPortKey(host, port)];
    stats.successes += 1;
    stats.ewma_health = (1.0 - m_ewma_alpha_success) * stats.ewma_health;
    UpdateHealthState(stats);
}

void OpenVerifyHostReliability::RecordVerifyFailure(const std::string& host, int port, uint16_t xrdcl_code) {
    std::lock_guard<std::mutex> lock(m_mtx);
    HostStats& stats = m_hoststat_map[HostPortKey(host, port)];
    stats.failures += 1;
    const double penalty = std::clamp(FailureWeightForCode(xrdcl_code), 0.0, 1.0);
    stats.ewma_health = m_ewma_alpha_fail * penalty + (1.0 - m_ewma_alpha_fail) * stats.ewma_health;
    if (!stats.healthy) {
        // Failed attempt while unhealthy: start/refresh cooldown from this outcome.
        stats.last_probe_at = std::chrono::steady_clock::now();
    }
    UpdateHealthState(stats);
}
