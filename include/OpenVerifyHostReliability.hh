#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// File-level or local failures. They still negative-cache the replica, but they must
// not move a site's EWMA: the server answered, or the probe URL was ours.
inline bool OpenVerifyFailureAffectsSiteHealth(const std::string& reason) {
    return reason != "openverify_empty_file" && reason != "openverify_invalid_key" &&
           reason != "openverify_cleartext_bearer";
}

// Per-(host,port) verify outcomes only (post-redirect): attempts, successes, failures.
// Host health uses EWMA scoring with hysteresis.
//
// XRD_OPENVERIFY_EWMA_ALPHA_FAIL          failure blend (default 0.05, range (0,1])
// XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS       success decay (default 0.10, range (0,1])
// XRD_OPENVERIFY_MIN_ATTEMPTS             samples before quarantine/recover (default 20)
// XRD_OPENVERIFY_QUARANTINE_THRESHOLD     enter quarantine at/above this (default 0.6)
// XRD_OPENVERIFY_RECOVER_THRESHOLD        leave quarantine at/below this (default 0.4)
// XRD_OPENVERIFY_PROBE_COOLDOWN           seconds between probes while quarantined (default 60)
// XRD_OPENVERIFY_FAILSAFE_MAX_SITES       unique sites quarantined in the window that trips
//                                         the circuit breaker (default 8; 0 disables)
// XRD_OPENVERIFY_FAILSAFE_WINDOW          fail-safe window/hold seconds (default 300)
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

    struct FailSafeSnapshot {
        bool active{false};
        uint64_t trips{0};
        uint64_t recent_sites{0};
        uint64_t max_sites{8};
        std::chrono::seconds window{300};
    };

    struct Config {
        double ewma_alpha_fail{0.05};
        double ewma_alpha_success{0.10};
        uint64_t min_attempts{20};
        double quarantine_threshold{0.6};
        double recover_threshold{0.4};
        std::chrono::seconds probe_cooldown{60};
        uint64_t failsafe_max_sites{8};
        std::chrono::seconds failsafe_window{300};
    };

    using Clock = std::function<std::chrono::steady_clock::time_point()>;
    using EventLog = std::function<void(const char* msg)>;

    OpenVerifyHostReliability();
    explicit OpenVerifyHostReliability(Config cfg);
    OpenVerifyHostReliability(Config cfg, Clock clock);
    OpenVerifyHostReliability(const OpenVerifyHostReliability&) = delete;
    OpenVerifyHostReliability& operator=(const OpenVerifyHostReliability&) = delete;

    // Optional WARN-line logger (set once at plugin init). Used for fail-safe trip/clear.
    void SetEventLog(EventLog log);

    // Skip the site while quarantined, except for one probe per cooldown window.
    // Always false while the mass-quarantine fail-safe is active.
    bool AvoidSite(const std::string& host, int port);

    void RecordVerifySuccess(const std::string& host, int port);
    void RecordVerifyFailure(const std::string& host, int port, uint16_t xrdcl_code);

    // Thread-safe copy of current per-site scores for metrics export.
    std::vector<SiteSnapshot> Snapshot() const;
    FailSafeSnapshot GetFailSafeSnapshot() const;

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

    static Config LoadConfigFromEnv();
    static std::string HostPortKey(const std::string& host, int port);
    std::chrono::steady_clock::time_point Now() const;

    void UpdateHealthState(HostStats& stats, std::chrono::steady_clock::time_point now);
    void NoteQuarantineEntry(const HostStats& stats, std::chrono::steady_clock::time_point now);
    void ReleaseAllQuarantines();
    // Prune the window, trip or clear the fail-safe. Returns a log line on transition.
    std::string EvaluateFailSafe(std::chrono::steady_clock::time_point now);
    void EmitFailSafeLog(const std::string& msg, const EventLog& log) const;

    // Separate alphas: smaller fail alpha slows quarantine; larger success alpha
    // speeds recovery. Invalid env values fall back to the defaults above.
    const double m_ewma_alpha_fail;
    const double m_ewma_alpha_success;
    const uint64_t m_min_attempts;
    // Dead band so a site does not oscillate between healthy and quarantined.
    const double m_quarantine_threshold;
    const double m_recover_threshold;
    const std::chrono::seconds m_probe_cooldown;
    const uint64_t m_failsafe_max_sites;
    const std::chrono::seconds m_failsafe_window;
    const Clock m_clock;

    mutable std::mutex m_mtx;
    EventLog m_event_log;
    std::unordered_map<std::string, HostStats> m_hoststat_map;
    // host:port → time the site last entered quarantine (unique sites in the window).
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_recent_quarantines;
    bool m_failsafe_active{false};
    std::chrono::steady_clock::time_point m_failsafe_until{};
    uint64_t m_failsafe_trips{0};
};
