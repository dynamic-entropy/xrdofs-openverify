#include <algorithm>
#include <random>

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

// Returns base ± 20% so probe deadlines are spread across daemon instances.
std::chrono::seconds JitteredCooldown(std::chrono::seconds base) {
    static thread_local std::mt19937 rng{std::random_device{}()};
    const int base_s = static_cast<int>(base.count());
    const int delta = static_cast<int>(base_s * 0.2f);
    std::uniform_int_distribution<int> dist(-delta, +delta);
    return std::chrono::seconds(base_s + dist(rng));
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
        // Set the first probe deadline immediately on quarantine so there is a
        // full cooldown window before any probe is allowed.
        stats.next_probe_at = std::chrono::steady_clock::now() + JitteredCooldown(m_probe_cooldown);
    } else if (!stats.healthy && stats.ewma_health <= r) {
        stats.healthy = true;
        stats.next_probe_at = {};
    }
}

bool OpenVerifyHostReliability::AvoidSite(const std::string& host, int port) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_hoststat_map.find(HostPortKey(host, port));
    if (it == m_hoststat_map.end()) return false;
    HostStats& stats = it->second;
    if (stats.healthy) return false;

    if (now >= stats.next_probe_at) {
        // Claim the probe slot by advancing the deadline before returning.
        // Concurrent threads arriving after this point will see a future deadline
        // and continue avoiding the site, so only one probe fires per window.
        stats.next_probe_at = now + JitteredCooldown(m_probe_cooldown);
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
        // Failed probe: push the deadline out again from now so the cooldown
        // restarts from the most recent failure, not from when the slot was claimed.
        stats.next_probe_at = std::chrono::steady_clock::now() + JitteredCooldown(m_probe_cooldown);
    }
    UpdateHealthState(stats);
}
