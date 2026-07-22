#include "OpenVerifyMetrics.hh"

#include "OpenVerifyHostReliability.hh"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

namespace {

const char* kEnvPath = "XRD_OPENVERIFY_METRICS_PATH";
const char* kEnvInstance = "XRD_OPENVERIFY_METRICS_INSTANCE";

std::string PortLabelForMetrics(int port) { return port >= 0 ? std::to_string(port) : "none"; }

std::string FailureMapKey(const std::string& host, int port, const std::string& reason) {
    return host + '\x1e' + PortLabelForMetrics(port) + '\x1e' + reason;
}

std::string EscapeLabelValue(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        if (c == '\\') {
            out += "\\\\";
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '"') {
            out += "\\\"";
        } else {
            out += c;
        }
    }
    return out;
}

const char* DelayOutcomeLabel(OpenVerifyMetrics::DelayOutcome o) {
    switch (o) {
        case OpenVerifyMetrics::DelayOutcome::CacheHitPositive:
            return "cache_hit_positive";
        case OpenVerifyMetrics::DelayOutcome::CacheHitNegative:
            return "cache_hit_negative";
        case OpenVerifyMetrics::DelayOutcome::VerifySuccess:
            return "verify_success";
        case OpenVerifyMetrics::DelayOutcome::VerifyFailure:
            return "verify_failure";
        case OpenVerifyMetrics::DelayOutcome::Avoided:
            return "avoided";
        default:
            return "unknown";
    }
}

}  // namespace

OpenVerifyMetrics::OpenVerifyMetrics() {
    if (const char* p = std::getenv(kEnvPath)) {
        m_path.assign(p);  // empty string -> no file export (explicit disable)
    } else {
        std::error_code ec;
        const std::filesystem::path cwd = std::filesystem::current_path(ec);
        if (!ec) {
            m_path = (cwd / "openverify_metrics.prom").string();
        }
    }

    if (const char* inst = std::getenv(kEnvInstance)) {
        if (*inst) {
            m_instance_label = EscapeLabelValue(std::string(inst));
        }
        // set but empty: leave m_instance_label blank
    } else {
        std::error_code ec;
        const std::filesystem::path cwd = std::filesystem::current_path(ec);
        if (!ec) {
            const std::string base = cwd.filename().string();
            if (!base.empty() && base != "." && base != "..") {
                m_instance_label = EscapeLabelValue(base);
            }
        }
    }

    // Sync disk to in-memory zeros after restart; otherwise a stale file persists until the first Record*.
    if (!m_path.empty()) {
        Flush();
    }
}

OpenVerifyMetrics::PerFailureMetrics& OpenVerifyMetrics::EnsureFailure(const std::string& host, int port,
                                                                     const std::string& reason) {
    const std::string key = FailureMapKey(host, port, reason);
    const std::string pl = PortLabelForMetrics(port);

    std::lock_guard<std::mutex> lock(m_failure_mtx);
    std::unique_ptr<PerFailureMetrics>& slot = m_failures_by_target_reason[key];
    if (!slot) {
        slot = std::make_unique<PerFailureMetrics>();
        slot->host_esc = EscapeLabelValue(host);
        slot->port_lbl = pl;
        slot->reason_esc = EscapeLabelValue(reason);
    }
    return *slot;
}

std::string OpenVerifyMetrics::BuildExpositionBody() const {
    const std::string lbl =
        m_instance_label.empty() ? std::string() : (",xrootd_instance=\"" + m_instance_label + "\"");

    std::ostringstream body;
    body << "# HELP xrootd_openverify_cache_lookups_total OpenVerify cache lookups by outcome.\n"
            "# TYPE xrootd_openverify_cache_lookups_total counter\n"
            "xrootd_openverify_cache_lookups_total{result=\"miss\""
         << lbl << "} " << m_cache_miss.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_cache_lookups_total{result=\"hit_positive\""
         << lbl << "} " << m_cache_hit_positive.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_cache_lookups_total{result=\"hit_negative\""
         << lbl << "} " << m_cache_hit_negative.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_runs_total OpenVerify executions after a cache miss.\n"
            "# TYPE xrootd_openverify_runs_total counter\n"
            "xrootd_openverify_runs_total{result=\"success\""
         << lbl << "} " << m_verify_success.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_runs_total{result=\"failure\""
         << lbl << "} " << m_verify_failure.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_queue_admissions_total Queue admissions around OpenVerify FIFO capacity wait.\n"
            "# TYPE xrootd_openverify_queue_admissions_total counter\n"
            "xrootd_openverify_queue_admissions_total{result=\"admitted\""
         << lbl << "} " << m_queue_admitted.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_queue_admissions_total{result=\"queue_full\""
         << lbl << "} " << m_queue_full.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_queue_admissions_total{result=\"queue_timeout\""
         << lbl << "} " << m_queue_timeout.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_singleflight_requests_total Single-flight requests split by role.\n"
            "# TYPE xrootd_openverify_singleflight_requests_total counter\n"
            "xrootd_openverify_singleflight_requests_total{role=\"leader\""
         << lbl << "} " << m_singleflight_leader.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_singleflight_requests_total{role=\"follower\""
         << lbl << "} " << m_singleflight_follower.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_redirects_handled_total SFS_REDIRECT responses seen by OpenVerify.\n"
            "# TYPE xrootd_openverify_redirects_handled_total counter\n"
            "xrootd_openverify_redirects_handled_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_redirects_handled.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_redirects_avoided_total Bad redirects skipped before client follow.\n"
            "# TYPE xrootd_openverify_redirects_avoided_total counter\n"
            "xrootd_openverify_redirects_avoided_total{reason=\"quarantine\""
         << lbl << "} " << m_redirects_avoided_quarantine.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_redirects_avoided_total{reason=\"negative_cache\""
         << lbl << "} " << m_redirects_avoided_negative_cache.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_cmsd_stalls_total cmsd SFS_STALL responses seen before a redirect.\n"
            "# TYPE xrootd_openverify_cmsd_stalls_total counter\n"
            "xrootd_openverify_cmsd_stalls_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_cmsd_stall_events.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_cmsd_stall_seconds_total Sum of cmsd stall seconds requested.\n"
            "# TYPE xrootd_openverify_cmsd_stall_seconds_total counter\n"
            "xrootd_openverify_cmsd_stall_seconds_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_cmsd_stall_seconds_sum.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_cmsd_stall_budget_exhausted_total Opens that hit XRD_OPENVERIFY_STALL_TIMEOUT.\n"
            "# TYPE xrootd_openverify_cmsd_stall_budget_exhausted_total counter\n"
            "xrootd_openverify_cmsd_stall_budget_exhausted_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_cmsd_stall_budget_exhausted.load(std::memory_order_relaxed) << "\n";

    body << "# HELP xrootd_openverify_cmsd_stall_seconds Histogram of individual cmsd stall durations.\n"
            "# TYPE xrootd_openverify_cmsd_stall_seconds histogram\n";
    {
        const DelayHistogram& h = m_cmsd_stall_hist;
        uint64_t cumulative = 0;
        for (size_t b = 0; b < DelayHistogram::kBucketCount; ++b) {
            cumulative += h.buckets[b].load(std::memory_order_relaxed);
            body << "xrootd_openverify_cmsd_stall_seconds_bucket{le=\"";
            if (b < DelayHistogram::kBoundCount) {
                body << DelayHistogram::kBounds[b];
            } else {
                body << "+Inf";
            }
            body << "\"" << lbl << "} " << cumulative << "\n";
        }
        const double sum_s = static_cast<double>(h.sum_micros.load(std::memory_order_relaxed)) / 1e6;
        const std::string inst =
            m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}");
        body << "xrootd_openverify_cmsd_stall_seconds_sum" << inst << " " << sum_s << "\n"
             << "xrootd_openverify_cmsd_stall_seconds_count" << inst << " "
             << h.count.load(std::memory_order_relaxed) << "\n";
    }

    body << "# HELP xrootd_openverify_redirect_delay_seconds OpenVerify handling time per redirect target.\n"
            "# TYPE xrootd_openverify_redirect_delay_seconds histogram\n";
    for (int oi = 0; oi < static_cast<int>(DelayOutcome::Count); ++oi) {
        const auto outcome = static_cast<DelayOutcome>(oi);
        const char* olabel = DelayOutcomeLabel(outcome);
        const DelayHistogram& h = m_delay[oi];
        uint64_t cumulative = 0;
        for (size_t b = 0; b < DelayHistogram::kBucketCount; ++b) {
            cumulative += h.buckets[b].load(std::memory_order_relaxed);
            body << "xrootd_openverify_redirect_delay_seconds_bucket{outcome=\"" << olabel << "\",le=\"";
            if (b < DelayHistogram::kBoundCount) {
                body << DelayHistogram::kBounds[b];
            } else {
                body << "+Inf";
            }
            body << "\"" << lbl << "} " << cumulative << "\n";
        }
        const double sum_s = static_cast<double>(h.sum_micros.load(std::memory_order_relaxed)) / 1e6;
        body << "xrootd_openverify_redirect_delay_seconds_sum{outcome=\"" << olabel << "\"" << lbl << "} " << sum_s
             << "\n"
             << "xrootd_openverify_redirect_delay_seconds_count{outcome=\"" << olabel << "\"" << lbl << "} "
             << h.count.load(std::memory_order_relaxed) << "\n";
    }

    body << "# HELP xrootd_openverify_verify_failures_total OpenVerify verify failures by redirect target and reason.\n"
            "# TYPE xrootd_openverify_verify_failures_total counter\n";

    {
        std::lock_guard<std::mutex> lock(m_failure_mtx);
        for (const auto& kv : m_failures_by_target_reason) {
            const PerFailureMetrics* e = kv.second.get();
            if (!e) continue;
            body << "xrootd_openverify_verify_failures_total{host=\"" << e->host_esc << "\",port=\""
                 << e->port_lbl << "\",reason=\"" << e->reason_esc << "\"" << lbl << "} "
                 << e->count.load(std::memory_order_relaxed) << "\n";
        }
    }

    if (m_sites) {
        const auto sites = m_sites->Snapshot();
        body << "# HELP xrootd_openverify_site_ewma_health EWMA badness score (0=healthy, higher=worse).\n"
                "# TYPE xrootd_openverify_site_ewma_health gauge\n"
                "# HELP xrootd_openverify_site_healthy 1 if site is not quarantined, else 0.\n"
                "# TYPE xrootd_openverify_site_healthy gauge\n"
                "# HELP xrootd_openverify_site_verify_successes_total Per-site verify successes.\n"
                "# TYPE xrootd_openverify_site_verify_successes_total counter\n"
                "# HELP xrootd_openverify_site_verify_failures_total Per-site verify failures.\n"
                "# TYPE xrootd_openverify_site_verify_failures_total counter\n";
        for (const auto& s : sites) {
            const std::string host_esc = EscapeLabelValue(s.host);
            const std::string port_lbl = PortLabelForMetrics(s.port);
            body << "xrootd_openverify_site_ewma_health{host=\"" << host_esc << "\",port=\"" << port_lbl << "\"" << lbl
                 << "} " << s.ewma_health << "\n"
                 << "xrootd_openverify_site_healthy{host=\"" << host_esc << "\",port=\"" << port_lbl << "\"" << lbl
                 << "} " << (s.healthy ? 1 : 0) << "\n"
                 << "xrootd_openverify_site_verify_successes_total{host=\"" << host_esc << "\",port=\"" << port_lbl
                 << "\"" << lbl << "} " << s.successes << "\n"
                 << "xrootd_openverify_site_verify_failures_total{host=\"" << host_esc << "\",port=\"" << port_lbl
                 << "\"" << lbl << "} " << s.failures << "\n";
        }
    }

    return body.str();
}

void OpenVerifyMetrics::RecordCacheMiss() {
    m_cache_miss.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordCacheHitPositive(double delay_seconds) {
    m_cache_hit_positive.fetch_add(1, std::memory_order_relaxed);
    if (delay_seconds >= 0) RecordRedirectDelay(delay_seconds, DelayOutcome::CacheHitPositive);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordCacheHitNegative(double delay_seconds) {
    m_cache_hit_negative.fetch_add(1, std::memory_order_relaxed);
    if (delay_seconds >= 0) RecordRedirectDelay(delay_seconds, DelayOutcome::CacheHitNegative);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordVerifySuccess() {
    m_verify_success.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordVerifyFailure(const std::string& host, int port, const std::string& reason) {
    const std::string r = reason.empty() ? std::string("unknown") : reason;
    m_verify_failure.fetch_add(1, std::memory_order_relaxed);
    EnsureFailure(host, port, r).count.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordQueueAdmissionAdmitted() {
    m_queue_admitted.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordQueueAdmissionFull() {
    m_queue_full.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordQueueAdmissionTimeout() {
    m_queue_timeout.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordSingleFlightLeader() {
    m_singleflight_leader.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordSingleFlightFollower() {
    m_singleflight_follower.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordRedirectHandled() {
    m_redirects_handled.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordRedirectAvoided(const std::string& reason, double delay_seconds) {
    if (reason == "quarantine") {
        m_redirects_avoided_quarantine.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_redirects_avoided_negative_cache.fetch_add(1, std::memory_order_relaxed);
    }
    if (delay_seconds >= 0) RecordRedirectDelay(delay_seconds, DelayOutcome::Avoided);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordRedirectVerifyFinished(bool success, double delay_seconds) {
    RecordRedirectDelay(delay_seconds, success ? DelayOutcome::VerifySuccess : DelayOutcome::VerifyFailure);
}

void OpenVerifyMetrics::RecordCmsdStall(int seconds) {
    if (seconds <= 0) return;
    m_cmsd_stall_events.fetch_add(1, std::memory_order_relaxed);
    m_cmsd_stall_seconds_sum.fetch_add(static_cast<uint64_t>(seconds), std::memory_order_relaxed);

    // Reuse delay histogram bucketing for stall duration distribution.
    const double stall_s = static_cast<double>(seconds);
    size_t bucket = DelayHistogram::kBoundCount;  // +Inf
    for (size_t i = 0; i < DelayHistogram::kBoundCount; ++i) {
        if (stall_s <= DelayHistogram::kBounds[i]) {
            bucket = i;
            break;
        }
    }
    m_cmsd_stall_hist.buckets[bucket].fetch_add(1, std::memory_order_relaxed);
    m_cmsd_stall_hist.count.fetch_add(1, std::memory_order_relaxed);
    m_cmsd_stall_hist.sum_micros.fetch_add(static_cast<uint64_t>(stall_s * 1e6), std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordCmsdStallBudgetExhausted() {
    m_cmsd_stall_budget_exhausted.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

OpenVerifyMetrics::RedirectTimer::RedirectTimer(OpenVerifyMetrics& metrics)
    : m_metrics(metrics), m_t0(std::chrono::steady_clock::now()) {
    m_metrics.RecordRedirectHandled();
}

double OpenVerifyMetrics::RedirectTimer::ElapsedSeconds() const {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - m_t0).count();
}

void OpenVerifyMetrics::RedirectTimer::CacheHitPositive() {
    if (m_done) return;
    m_done = true;
    m_metrics.RecordCacheHitPositive(ElapsedSeconds());
}

void OpenVerifyMetrics::RedirectTimer::CacheHitNegative(bool count_as_avoided) {
    if (m_done) return;
    m_done = true;
    m_metrics.RecordCacheHitNegative(ElapsedSeconds());
    if (count_as_avoided) {
        // Counter only — delay already attributed to cache_hit_negative.
        m_metrics.RecordRedirectAvoided("negative_cache");
    }
}

void OpenVerifyMetrics::RedirectTimer::Avoided(const std::string& reason) {
    if (m_done) return;
    m_done = true;
    m_metrics.RecordRedirectAvoided(reason, ElapsedSeconds());
}

void OpenVerifyMetrics::RedirectTimer::VerifyFinished(bool success) {
    if (m_done) return;
    m_done = true;
    m_metrics.RecordRedirectVerifyFinished(success, ElapsedSeconds());
}

void OpenVerifyMetrics::RecordRedirectDelay(double seconds, DelayOutcome outcome) {
    if (seconds < 0) seconds = 0;
    const int oi = static_cast<int>(outcome);
    if (oi < 0 || oi >= static_cast<int>(DelayOutcome::Count)) return;

    DelayHistogram& h = m_delay[oi];
    size_t bucket = DelayHistogram::kBoundCount;  // +Inf
    for (size_t i = 0; i < DelayHistogram::kBoundCount; ++i) {
        if (seconds <= DelayHistogram::kBounds[i]) {
            bucket = i;
            break;
        }
    }
    h.buckets[bucket].fetch_add(1, std::memory_order_relaxed);
    h.count.fetch_add(1, std::memory_order_relaxed);
    h.sum_micros.fetch_add(static_cast<uint64_t>(seconds * 1e6), std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::Flush() {
    const std::string content = BuildExpositionBody();
    const std::string tmp_path = m_path + ".tmp";

    std::lock_guard<std::mutex> lock(m_write_mtx);

    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) return;
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!out.flush()) return;
    }

    if (std::rename(tmp_path.c_str(), m_path.c_str()) != 0) {
        (void)std::remove(tmp_path.c_str());
    }
}
