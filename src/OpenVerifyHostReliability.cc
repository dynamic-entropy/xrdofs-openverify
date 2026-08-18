#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <random>
#include <sstream>

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

// Inclusive [lo, hi]. Empty / unparsable / out of range → dflt.
double EnvDoubleOrDefault(const char* name, double dflt, double lo, double hi) {
    const char* p = std::getenv(name);
    if (!p || !*p) return dflt;
    char* end = nullptr;
    const double v = std::strtod(p, &end);
    if (end == p || *end != '\0' || !std::isfinite(v) || v < lo || v > hi) return dflt;
    return v;
}

// Exclusive of lo, inclusive of hi — used for alphas where 0 would freeze EWMA.
double EnvAlphaOrDefault(const char* name, double dflt, double lo, double hi) {
    const char* p = std::getenv(name);
    if (!p || !*p) return dflt;
    char* end = nullptr;
    const double v = std::strtod(p, &end);
    if (end == p || *end != '\0' || !std::isfinite(v) || v <= lo || v > hi) return dflt;
    return v;
}

long EnvLongOrDefault(const char* name, long dflt, long lo) {
    const char* p = std::getenv(name);
    if (!p || !*p) return dflt;
    char* end = nullptr;
    const long v = std::strtol(p, &end, 10);
    if (end == p || *end != '\0' || v < lo) return dflt;
    return v;
}

}  // namespace

OpenVerifyHostReliability::Config OpenVerifyHostReliability::LoadConfigFromEnv() {
    Config cfg;
    cfg.ewma_alpha_fail = EnvAlphaOrDefault("XRD_OPENVERIFY_EWMA_ALPHA_FAIL", 0.05, 0.0, 1.0);
    cfg.ewma_alpha_success = EnvAlphaOrDefault("XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS", 0.10, 0.0, 1.0);
    cfg.min_attempts = static_cast<uint64_t>(EnvLongOrDefault("XRD_OPENVERIFY_MIN_ATTEMPTS", 20, 1));
    cfg.quarantine_threshold = EnvDoubleOrDefault("XRD_OPENVERIFY_QUARANTINE_THRESHOLD", 0.6, 0.0, 1.0);
    cfg.recover_threshold = EnvDoubleOrDefault("XRD_OPENVERIFY_RECOVER_THRESHOLD", 0.4, 0.0, 1.0);
    if (cfg.recover_threshold > cfg.quarantine_threshold) {
        cfg.recover_threshold = cfg.quarantine_threshold;
    }
    cfg.probe_cooldown = std::chrono::seconds(EnvLongOrDefault("XRD_OPENVERIFY_PROBE_COOLDOWN", 60, 1));
    cfg.failsafe_max_sites = static_cast<uint64_t>(EnvLongOrDefault("XRD_OPENVERIFY_FAILSAFE_MAX_SITES", 8, 0));
    cfg.failsafe_window = std::chrono::seconds(EnvLongOrDefault("XRD_OPENVERIFY_FAILSAFE_WINDOW", 300, 1));
    return cfg;
}

OpenVerifyHostReliability::OpenVerifyHostReliability() : OpenVerifyHostReliability(LoadConfigFromEnv(), {}) {}

OpenVerifyHostReliability::OpenVerifyHostReliability(Config cfg) : OpenVerifyHostReliability(std::move(cfg), {}) {}

OpenVerifyHostReliability::OpenVerifyHostReliability(Config cfg, Clock clock)
    : m_ewma_alpha_fail(cfg.ewma_alpha_fail),
      m_ewma_alpha_success(cfg.ewma_alpha_success),
      m_min_attempts(cfg.min_attempts),
      m_quarantine_threshold(cfg.quarantine_threshold),
      m_recover_threshold(cfg.recover_threshold),
      m_probe_cooldown(cfg.probe_cooldown),
      m_failsafe_max_sites(cfg.failsafe_max_sites),
      m_failsafe_window(cfg.failsafe_window),
      m_clock(std::move(clock)) {}

void OpenVerifyHostReliability::SetEventLog(EventLog log) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_event_log = std::move(log);
}

OpenVerifyHostReliability::Config OpenVerifyHostReliability::GetConfig() const {
    return Config{
        m_ewma_alpha_fail,      m_ewma_alpha_success, m_min_attempts,        m_quarantine_threshold,
        m_recover_threshold,    m_probe_cooldown,     m_failsafe_max_sites,  m_failsafe_window,
    };
}

std::string OpenVerifyHostReliability::ConfigSummary() const {
    std::ostringstream os;
    os << "openverify site health alpha_fail=" << m_ewma_alpha_fail << " alpha_success=" << m_ewma_alpha_success
       << " min_attempts=" << m_min_attempts << " quarantine=" << m_quarantine_threshold
       << " recover=" << m_recover_threshold << " probe_cooldown_s=" << m_probe_cooldown.count()
       << " failsafe_max_sites=" << m_failsafe_max_sites << " failsafe_window_s=" << m_failsafe_window.count();
    return os.str();
}

std::string OpenVerifyHostReliability::HostPortKey(const std::string& host, int port) {
    return host + ":" + std::to_string(port);
}

std::chrono::steady_clock::time_point OpenVerifyHostReliability::Now() const {
    return m_clock ? m_clock() : std::chrono::steady_clock::now();
}

void OpenVerifyHostReliability::NoteQuarantineEntry(const HostStats& stats,
                                                    std::chrono::steady_clock::time_point now) {
    if (m_failsafe_max_sites == 0) return;
    m_recent_quarantines[HostPortKey(stats.host, stats.port)] = now;
}

void OpenVerifyHostReliability::ReleaseAllQuarantines() {
    for (auto& kv : m_hoststat_map) {
        HostStats& s = kv.second;
        if (s.healthy) continue;
        s.healthy = true;
        s.next_probe_at = {};
        // Require min_attempts again so the storm cannot re-quarantine on the next sample.
        s.successes = 0;
        s.failures = 0;
    }
}

std::string OpenVerifyHostReliability::EvaluateFailSafe(std::chrono::steady_clock::time_point now) {
    if (m_failsafe_max_sites == 0) return {};

    const auto cutoff = now - m_failsafe_window;
    for (auto it = m_recent_quarantines.begin(); it != m_recent_quarantines.end();) {
        if (it->second <= cutoff) {
            it = m_recent_quarantines.erase(it);
        } else {
            ++it;
        }
    }

    if (!m_failsafe_active) {
        if (m_recent_quarantines.size() >= m_failsafe_max_sites) {
            m_failsafe_active = true;
            m_failsafe_until = now + m_failsafe_window;
            m_failsafe_trips += 1;
            const auto n = m_recent_quarantines.size();
            ReleaseAllQuarantines();
            std::ostringstream os;
            os << "openverify fail-safe tripped: " << n << " sites entered quarantine within "
               << m_failsafe_window.count() << "s (threshold " << m_failsafe_max_sites
               << "); disabling site skip until the hold expires";
            return os.str();
        }
        return {};
    }

    if (now >= m_failsafe_until) {
        m_failsafe_active = false;
        m_failsafe_until = {};
        m_recent_quarantines.clear();
        return "openverify fail-safe cleared: hold expired; site skip re-enabled";
    }
    return {};
}

void OpenVerifyHostReliability::EmitFailSafeLog(const std::string& msg, const EventLog& log) const {
    if (!msg.empty() && log) log(msg.c_str());
}

void OpenVerifyHostReliability::UpdateHealthState(HostStats& stats, std::chrono::steady_clock::time_point now) {
    const uint64_t attempts = stats.successes + stats.failures;
    if (attempts < m_min_attempts) return;

    const double q = std::clamp(m_quarantine_threshold, 0.0, 1.0);
    const double r = std::clamp(m_recover_threshold, 0.0, q);

    if (m_failsafe_active) {
        // Traffic is flowing; allow recovery bookkeeping but do not enter quarantine.
        if (!stats.healthy && stats.ewma_health <= r) {
            stats.healthy = true;
            stats.next_probe_at = {};
        }
        return;
    }

    if (stats.healthy && stats.ewma_health >= q) {
        stats.healthy = false;
        // Set the first probe deadline immediately on quarantine so there is a
        // full cooldown window before any probe is allowed.
        stats.next_probe_at = now + JitteredCooldown(m_probe_cooldown);
        NoteQuarantineEntry(stats, now);
    } else if (!stats.healthy && stats.ewma_health <= r) {
        stats.healthy = true;
        stats.next_probe_at = {};
    }
}

bool OpenVerifyHostReliability::AvoidSite(const std::string& host, int port) {
    std::string failsafe_log;
    EventLog log;
    bool avoid = false;
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        const auto now = Now();
        failsafe_log = EvaluateFailSafe(now);
        log = m_event_log;
        if (m_failsafe_active) {
            avoid = false;
        } else {
            auto it = m_hoststat_map.find(HostPortKey(host, port));
            if (it != m_hoststat_map.end()) {
                HostStats& stats = it->second;
                if (!stats.healthy) {
                    if (now >= stats.next_probe_at) {
                        // Claim the probe slot by advancing the deadline before returning.
                        // Concurrent threads arriving after this point will see a future deadline
                        // and continue avoiding the site, so only one probe fires per window.
                        stats.next_probe_at = now + JitteredCooldown(m_probe_cooldown);
                        avoid = false;
                    } else {
                        avoid = true;
                    }
                }
            }
        }
    }
    EmitFailSafeLog(failsafe_log, log);
    return avoid;
}

void OpenVerifyHostReliability::RecordVerifySuccess(const std::string& host, int port) {
    std::string failsafe_log;
    EventLog log;
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        const auto now = Now();
        HostStats& stats = m_hoststat_map[HostPortKey(host, port)];
        stats.host = host;
        stats.port = port;
        stats.successes += 1;
        stats.ewma_health = (1.0 - m_ewma_alpha_success) * stats.ewma_health;
        UpdateHealthState(stats, now);
        failsafe_log = EvaluateFailSafe(now);
        log = m_event_log;
    }
    EmitFailSafeLog(failsafe_log, log);
}

void OpenVerifyHostReliability::RecordVerifyFailure(const std::string& host, int port, uint16_t xrdcl_code) {
    std::string failsafe_log;
    EventLog log;
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        const auto now = Now();
        HostStats& stats = m_hoststat_map[HostPortKey(host, port)];
        stats.host = host;
        stats.port = port;
        stats.failures += 1;
        const double penalty = std::clamp(FailureWeightForCode(xrdcl_code), 0.0, 1.0);
        stats.ewma_health = m_ewma_alpha_fail * penalty + (1.0 - m_ewma_alpha_fail) * stats.ewma_health;
        if (!stats.healthy) {
            // Failed probe: push the deadline out again from now so the cooldown
            // restarts from the most recent failure, not from when the slot was claimed.
            stats.next_probe_at = now + JitteredCooldown(m_probe_cooldown);
        }
        UpdateHealthState(stats, now);
        failsafe_log = EvaluateFailSafe(now);
        log = m_event_log;
    }
    EmitFailSafeLog(failsafe_log, log);
}

std::vector<OpenVerifyHostReliability::SiteSnapshot> OpenVerifyHostReliability::Snapshot() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    std::vector<SiteSnapshot> out;
    out.reserve(m_hoststat_map.size());
    for (const auto& kv : m_hoststat_map) {
        const HostStats& s = kv.second;
        SiteSnapshot snap;
        snap.host = s.host.empty() ? kv.first : s.host;
        snap.port = s.port;
        snap.ewma_health = s.ewma_health;
        snap.healthy = s.healthy;
        snap.successes = s.successes;
        snap.failures = s.failures;
        out.push_back(std::move(snap));
    }
    return out;
}

OpenVerifyHostReliability::FailSafeSnapshot OpenVerifyHostReliability::GetFailSafeSnapshot() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    FailSafeSnapshot snap;
    snap.active = m_failsafe_active;
    snap.trips = m_failsafe_trips;
    snap.recent_sites = m_recent_quarantines.size();
    snap.max_sites = m_failsafe_max_sites;
    snap.window = m_failsafe_window;
    return snap;
}
