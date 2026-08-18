#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Per-(host,port) verify outcomes only (post-redirect): attempts, successes, failures.
// Host health uses EWMA scoring with hysteresis.
//
// XRD_OPENVERIFY_EWMA_ALPHA_FAIL          failure blend (default 0.05, range (0,1])
// XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS       success decay (default 0.10, range (0,1])
// XRD_OPENVERIFY_MIN_ATTEMPTS             samples before quarantine/recover (default 20)
// XRD_OPENVERIFY_QUARANTINE_THRESHOLD     enter quarantine at/above this (default 0.6)
// XRD_OPENVERIFY_RECOVER_THRESHOLD        leave quarantine at/below this (default 0.4)
// XRD_OPENVERIFY_PROBE_COOLDOWN           seconds between probes while quarantined (default 60)
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

    struct Config {
        double ewma_alpha_fail{0.05};
        double ewma_alpha_success{0.10};
        uint64_t min_attempts{20};
        double quarantine_threshold{0.6};
        double recover_threshold{0.4};
        std::chrono::seconds probe_cooldown{60};
    };

    OpenVerifyHostReliability();
    OpenVerifyHostReliability(const OpenVerifyHostReliability&) = delete;
    OpenVerifyHostReliability& operator=(const OpenVerifyHostReliability&) = delete;

    // Skip the site while quarantined, except for one probe per cooldown window.
    bool AvoidSite(const std::string& host, int port);

    void RecordVerifySuccess(const std::string& host, int port);
    void RecordVerifyFailure(const std::string& host, int port, uint16_t xrdcl_code);

    // Thread-safe copy of current per-site scores for metrics export.
    std::vector<SiteSnapshot> Snapshot() const;

    Config GetConfig() const;
    std::string ConfigSummary() const;

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

    explicit OpenVerifyHostReliability(Config cfg);
    static Config LoadConfigFromEnv();
    static std::string HostPortKey(const std::string& host, int port);
    void UpdateHealthState(HostStats& stats);

    // Separate alphas: smaller fail alpha slows quarantine; larger success alpha
    // speeds recovery. Invalid env values fall back to the defaults above.
    const double m_ewma_alpha_fail;
    const double m_ewma_alpha_success;
    const uint64_t m_min_attempts;
    // Dead band so a site does not oscillate between healthy and quarantined.
    const double m_quarantine_threshold;
    const double m_recover_threshold;
    const std::chrono::seconds m_probe_cooldown;

    mutable std::mutex m_mtx;
    std::unordered_map<std::string, HostStats> m_hoststat_map;
};
