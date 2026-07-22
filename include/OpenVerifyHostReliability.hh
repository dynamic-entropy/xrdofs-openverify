#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Per-(host,port) verify outcomes only (post-redirect): attempts, successes, failures.
// Host health uses EWMA scoring with hysteresis.
class OpenVerifyHostReliability {
   public:
    struct SiteSnapshot {
        std::string host;
        int port{-1};
        double ewma_health{0.0};
        bool healthy{true};
        uint64_t successes{0};
        uint64_t failures{0};
    };

    OpenVerifyHostReliability();
    OpenVerifyHostReliability(const OpenVerifyHostReliability&) = delete;
    OpenVerifyHostReliability& operator=(const OpenVerifyHostReliability&) = delete;

    // Add a site to the tried list if its ewma score is below threshold
    bool AvoidSite(const std::string& host, int port);

    void RecordVerifySuccess(const std::string& host, int port);
    void RecordVerifyFailure(const std::string& host, int port, uint16_t xrdcl_code);

    // Thread-safe copy of current per-site scores for metrics export.
    std::vector<SiteSnapshot> Snapshot() const;

   private:
    struct HostStats {
        uint64_t successes{0};  // openverify success counts for host
        uint64_t failures{0};   // openverify failure counts for host
        double ewma_health{0.0};
        bool healthy{true};
        // Deadline after which the next probe is allowed.
        std::chrono::steady_clock::time_point next_probe_at{};
        std::string host;
        int port{-1};
    };

    static std::string HostPortKey(const std::string& host, int port);
    void UpdateHealthState(HostStats& stats);

    // we keep separate alpha for failures and success
    // to ensure faster recovery on success but still smoother
    // transition to diabled on failure
    const double m_ewma_alpha_fail;
    const double m_ewma_alpha_success;
    const uint64_t m_min_attempts;
    // Create a dead band of thresholds to not oscillate
    // between healthy and otherwise
    const double m_quarantine_threshold;
    const double m_recover_threshold;
    const std::chrono::seconds m_probe_cooldown;

    mutable std::mutex m_mtx;
    std::unordered_map<std::string, HostStats> m_hoststat_map;
};
