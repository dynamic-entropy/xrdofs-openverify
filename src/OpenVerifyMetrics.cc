#include "OpenVerifyMetrics.hh"

#include "OpenVerifyHostReliability.hh"
#include "OpenVerifyStaticFallback.hh"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

const char* kEnvPath = "XRD_OPENVERIFY_METRICS_PATH";
const char* kEnvInstance = "XRD_OPENVERIFY_METRICS_INSTANCE";

std::string PortLabelForMetrics(int port) { return port >= 0 ? std::to_string(port) : "none"; }

std::string FailureMapKey(const std::string& source, const std::string& host, int port,
                          const std::string& reason) {
    return source + '\x1e' + host + '\x1e' + PortLabelForMetrics(port) + '\x1e' + reason;
}

std::string ProbeMapKey(const std::string& source, const std::string& host, int port,
                        const std::string& result) {
    return source + '\x1e' + host + '\x1e' + PortLabelForMetrics(port) + '\x1e' + result;
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
        case OpenVerifyMetrics::DelayOutcome::QueueTimeout:
            return "queue_timeout";
        case OpenVerifyMetrics::DelayOutcome::QueueFull:
            return "queue_full";
        case OpenVerifyMetrics::DelayOutcome::HostBusy:
            return "host_busy";
        case OpenVerifyMetrics::DelayOutcome::Passthrough:
            return "passthrough";
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

OpenVerifyMetrics::~OpenVerifyMetrics() {
    {
        std::lock_guard<std::mutex> lk(m_flush_mtx);
        m_flush_stop = true;
    }
    m_flush_cv.notify_all();
    if (m_flush_thread.joinable()) m_flush_thread.join();
    if (m_flush_needed.exchange(false, std::memory_order_relaxed) && !m_path.empty()) {
        Flush();
    }
}

void OpenVerifyMetrics::NoteUpdate() {
    if (m_path.empty()) return;
    m_flush_needed.store(true, std::memory_order_relaxed);
    // Start the writer on the first update, after init has published m_sites.
    if (m_flush_started.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(m_flush_mtx);
    if (m_flush_stop || m_flush_started.load(std::memory_order_relaxed)) return;
    m_flush_thread = std::thread(&OpenVerifyMetrics::FlushLoop, this);
    m_flush_started.store(true, std::memory_order_release);
}

void OpenVerifyMetrics::FlushNow() {
    if (m_path.empty()) return;
    m_flush_needed.store(false, std::memory_order_relaxed);
    Flush();
}

void OpenVerifyMetrics::FlushLoop() {
    std::unique_lock<std::mutex> lk(m_flush_mtx);
    while (!m_flush_stop) {
        m_flush_cv.wait_for(lk, std::chrono::seconds(1), [&] { return m_flush_stop; });
        if (m_flush_stop) break;
        if (!m_flush_needed.exchange(false, std::memory_order_relaxed)) continue;
        lk.unlock();
        Flush();
        lk.lock();
    }
}

OpenVerifyMetrics::PerFailureMetrics& OpenVerifyMetrics::EnsureFailure(const std::string& source,
                                                                       const std::string& host, int port,
                                                                       const std::string& reason) {
    const std::string src = source.empty() ? std::string("unknown") : source;
    std::string h = host.empty() ? std::string("unknown") : host;
    const std::string pl = PortLabelForMetrics(port);

    std::lock_guard<std::mutex> lock(m_failure_mtx);
    if (m_failures_by_target_reason.size() >= 4096 &&
        !m_failures_by_target_reason.count(FailureMapKey(src, h, port, reason))) {
        h = "other";
    }
    const std::string key = FailureMapKey(src, h, port, reason);
    std::unique_ptr<PerFailureMetrics>& slot = m_failures_by_target_reason[key];
    if (!slot) {
        slot = std::make_unique<PerFailureMetrics>();
        slot->source_esc = EscapeLabelValue(src);
        slot->host_esc = EscapeLabelValue(h);
        slot->port_lbl = pl;
        slot->reason_esc = EscapeLabelValue(reason);
    }
    return *slot;
}

OpenVerifyMetrics::PerProbeMetrics& OpenVerifyMetrics::EnsureProbe(const std::string& source,
                                                                   const std::string& host, int port,
                                                                   const std::string& result) {
    std::string src = source.empty() ? std::string("unknown") : source;
    std::string h = host.empty() ? std::string("unknown") : host;
    const std::string res = result.empty() ? std::string("unknown") : result;
    const std::string pl = PortLabelForMetrics(port);
    {
        std::lock_guard<std::mutex> lock(m_probe_mtx);
        if (m_probes_by_target_result.size() >= 4096 &&
            !m_probes_by_target_result.count(ProbeMapKey(src, h, port, res))) {
            h = "other";
        }
        const std::string key = ProbeMapKey(src, h, port, res);
        std::unique_ptr<PerProbeMetrics>& slot = m_probes_by_target_result[key];
        if (!slot) {
            slot = std::make_unique<PerProbeMetrics>();
            slot->source_esc = EscapeLabelValue(src);
            slot->host_esc = EscapeLabelValue(h);
            slot->port_lbl = pl;
            slot->result_esc = EscapeLabelValue(res);
        }
        return *slot;
    }
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
            "xrootd_openverify_queue_admissions_total{result=\"host_busy\""
         << lbl << "} " << m_queue_host_busy.load(std::memory_order_relaxed) << "\n"
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
            "xrootd_openverify_redirects_avoided_total{reason=\"host_busy\""
         << lbl << "} " << m_redirects_avoided_host_busy.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_cmsd_stalls_total cmsd SFS_STALL responses passed through to the client.\n"
            "# TYPE xrootd_openverify_cmsd_stalls_total counter\n"
            "xrootd_openverify_cmsd_stalls_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_cmsd_stall_events.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_cmsd_stall_seconds_total Sum of cmsd stall seconds requested.\n"
            "# TYPE xrootd_openverify_cmsd_stall_seconds_total counter\n"
            "xrootd_openverify_cmsd_stall_seconds_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_cmsd_stall_seconds_sum.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_accepted_total Opens that accepted a redirect: "
            "rucio=verify succeeded on Nth ordered replica; cmsd=Nth redirect candidate; "
            "xrootd=static xrootd.redirect fallback (no verify); "
            "skip=XRD_OPENVERIFY_SKIP_PREFIX passthrough (no Rucio, no verify).\n"
            "# TYPE xrootd_openverify_accepted_total counter\n";
    {
        std::lock_guard<std::mutex> lock(m_rucio_accept_mtx);
        for (int a = 1; a <= kMaxRucioReplicaLabel; ++a) {
            const auto it = m_accepted_rucio_by_replica.find(a);
            const uint64_t n = (it != m_accepted_rucio_by_replica.end()) ? it->second : 0;
            const bool overflow = (a >= kMaxRucioReplicaLabel);
            // Label still "attempt" for scrape compatibility; means replica index for rucio.
            body << "xrootd_openverify_accepted_total{source=\"rucio\",attempt=\"" << a
                 << (overflow ? "+" : "") << "\"" << lbl << "} " << n << "\n";
        }
    }
    for (int a = 0; a < kMaxCmsdAcceptAttempts; ++a) {
        body << "xrootd_openverify_accepted_total{source=\"cmsd\",attempt=\"" << (a + 1) << "\"" << lbl << "} "
             << m_accepted_cmsd_by_attempt[a].load(std::memory_order_relaxed) << "\n";
    }
    body << "xrootd_openverify_accepted_total{source=\"xrootd\",attempt=\"1\"" << lbl << "} "
         << m_accepted_xrootd.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_accepted_total{source=\"skip\",attempt=\"1\""
         << lbl << "} " << m_accepted_skip.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_static_fallback_total Successful static xrootd.redirect "
            "pass-throughs (no verify). Not an error — e.g. cms-xrd-transit ENOENT fallback.\n"
            "# TYPE xrootd_openverify_static_fallback_total counter\n"
            "xrootd_openverify_static_fallback_total{fallback=\"transit\""
         << lbl << "} " << m_static_fallback_transit.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_skip_prefix_total Opens matching XRD_OPENVERIFY_SKIP_PREFIX: "
            "cmsd locate, no Rucio, no verify probe. reason=matched prefix.\n"
            "# TYPE xrootd_openverify_skip_prefix_total counter\n";
    {
        std::lock_guard<std::mutex> lock(m_skip_prefix_mtx);
        for (const auto& kv : m_skip_prefix_by_reason) {
            const PerSkipReasonMetrics* e = kv.second.get();
            if (!e) continue;
            body << "xrootd_openverify_skip_prefix_total{reason=\"" << e->reason_esc << "\"" << lbl << "} "
                 << e->count.load(std::memory_order_relaxed) << "\n";
        }
    }
    body << "# HELP xrootd_openverify_retry_exhausted_total Enforce mode: opens that hit max site attempts without a verify success.\n"
            "# TYPE xrootd_openverify_retry_exhausted_total counter\n"
            "xrootd_openverify_retry_exhausted_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_retry_exhausted.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_lookups_total Rucio list_replicas outcomes (Rucio-first locate).\n"
            "# TYPE xrootd_openverify_rucio_lookups_total counter\n"
            "xrootd_openverify_rucio_lookups_total{result=\"ok\""
         << lbl << "} " << m_rucio_lookup_ok.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_rucio_lookups_total{result=\"empty\""
         << lbl << "} " << m_rucio_lookup_empty.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_rucio_lookups_total{result=\"auth_error\""
         << lbl << "} " << m_rucio_lookup_auth_error.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_rucio_lookups_total{result=\"timeout\""
         << lbl << "} " << m_rucio_lookup_timeout.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_rucio_lookups_total{result=\"error\""
         << lbl << "} " << m_rucio_lookup_error.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_rucio_lookups_total{result=\"skipped\""
         << lbl << "} " << m_rucio_lookup_skipped.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_skipped_total Rucio ignore-prefix skips by matched prefix (reason).\n"
            "# TYPE xrootd_openverify_rucio_skipped_total counter\n";
    {
        std::lock_guard<std::mutex> lock(m_rucio_skip_mtx);
        for (const auto& kv : m_rucio_skipped_by_reason) {
            const PerSkipReasonMetrics* e = kv.second.get();
            if (!e) continue;
            body << "xrootd_openverify_rucio_skipped_total{reason=\"" << e->reason_esc << "\"" << lbl << "} "
                 << e->count.load(std::memory_order_relaxed) << "\n";
        }
    }
    body << "# HELP xrootd_openverify_rucio_list_cache_total Rucio list_replicas LRU lookups (lfn+scheme).\n"
            "# TYPE xrootd_openverify_rucio_list_cache_total counter\n"
            "xrootd_openverify_rucio_list_cache_total{result=\"hit\""
         << lbl << "} " << m_rucio_list_cache_hit.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_rucio_list_cache_total{result=\"miss\""
         << lbl << "} " << m_rucio_list_cache_miss.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_list_cache_entries Current Rucio list_replicas LRU occupancy.\n"
            "# TYPE xrootd_openverify_rucio_list_cache_entries gauge\n"
            "xrootd_openverify_rucio_list_cache_entries"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_rucio_list_cache_entries.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_candidates_total PFN candidates returned by successful Rucio lookups.\n"
            "# TYPE xrootd_openverify_rucio_candidates_total counter\n"
            "xrootd_openverify_rucio_candidates_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_rucio_candidates.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_exhausted_total Rucio returned PFNs but none accepted; fall through to cmsd.\n"
            "# TYPE xrootd_openverify_rucio_exhausted_total counter\n"
            "xrootd_openverify_rucio_exhausted_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_rucio_exhausted.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_exhausted_recovered_total Rucio PFN list exhausted then cmsd openverify accepted.\n"
            "# TYPE xrootd_openverify_rucio_exhausted_recovered_total counter\n"
            "xrootd_openverify_rucio_exhausted_recovered_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_rucio_exhausted_recovered.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_cmsd_compare_total After Rucio exhaust, cmsd accept vs Rucio PFN host list.\n"
            "# TYPE xrootd_openverify_rucio_cmsd_compare_total counter\n"
            "xrootd_openverify_rucio_cmsd_compare_total{result=\"overlap\""
         << lbl << "} " << m_rucio_cmsd_compare_overlap.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_rucio_cmsd_compare_total{result=\"catalog_disagree\""
         << lbl << "} " << m_rucio_cmsd_compare_catalog_disagree.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_location_source_total Accepted opens by locate path "
            "(rucio / cmsd verify, static xrootd.redirect pass-through, or SKIP_PREFIX). "
            "source=xrootd and source=skip are not errors.\n"
            "# TYPE xrootd_openverify_location_source_total counter\n"
            "xrootd_openverify_location_source_total{source=\"rucio\""
         << lbl << "} " << m_location_source_rucio.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_location_source_total{source=\"cmsd\""
         << lbl << "} " << m_location_source_cmsd.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_location_source_total{source=\"xrootd\""
         << lbl << "} " << m_location_source_xrootd.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_location_source_total{source=\"skip\""
         << lbl << "} " << m_location_source_skip.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_curl_tcp_total Rucio HTTP transfers by TCP reuse "
            "(CURLINFO_NUM_CONNECTS: reused=0 new connections, new>=1).\n"
            "# TYPE xrootd_openverify_rucio_curl_tcp_total counter\n"
            "xrootd_openverify_rucio_curl_tcp_total{result=\"reused\""
         << lbl << "} " << m_rucio_curl_tcp_reused.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_rucio_curl_tcp_total{result=\"new\""
         << lbl << "} " << m_rucio_curl_tcp_new.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_curl_handle_total Rucio transfers by libcurl easy-handle reuse "
            "(reused=from idle pool, new=curl_easy_init under load).\n"
            "# TYPE xrootd_openverify_rucio_curl_handle_total counter\n"
            "xrootd_openverify_rucio_curl_handle_total{result=\"reused\""
         << lbl << "} " << m_rucio_curl_handle_reused.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_rucio_curl_handle_total{result=\"new\""
         << lbl << "} " << m_rucio_curl_handle_new.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_curl_pool_handles Current libcurl easy handles in the Rucio pool.\n"
            "# TYPE xrootd_openverify_rucio_curl_pool_handles gauge\n"
            "xrootd_openverify_rucio_curl_pool_handles"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_rucio_curl_pool_handles.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_curl_pool_idle Idle easy handles in the Rucio pool.\n"
            "# TYPE xrootd_openverify_rucio_curl_pool_idle gauge\n"
            "xrootd_openverify_rucio_curl_pool_idle"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_rucio_curl_pool_idle.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_curl_pool_inflight Checked-out easy handles in the Rucio pool.\n"
            "# TYPE xrootd_openverify_rucio_curl_pool_inflight gauge\n"
            "xrootd_openverify_rucio_curl_pool_inflight"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_rucio_curl_pool_inflight.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_curl_pool_grows_total Times the Rucio curl pool created a handle above warm min.\n"
            "# TYPE xrootd_openverify_rucio_curl_pool_grows_total counter\n"
            "xrootd_openverify_rucio_curl_pool_grows_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_rucio_curl_pool_grows.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_rucio_curl_pool_shrinks_total Times the Rucio curl pool destroyed an idle extra handle.\n"
            "# TYPE xrootd_openverify_rucio_curl_pool_shrinks_total counter\n"
            "xrootd_openverify_rucio_curl_pool_shrinks_total"
         << (m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}")) << " "
         << m_rucio_curl_pool_shrinks.load(std::memory_order_relaxed) << "\n";

    body << "# HELP xrootd_openverify_redirect_delay_seconds OpenVerify handling time per redirect target "
            "(queue wait + verify RTT for miss path).\n"
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

    auto emit_labeled_delay_hist = [&](const char* name, const char* help, const char* label_name,
                                       const char* label_a, const DelayHistogram& ha, const char* label_b,
                                       const DelayHistogram& hb) {
        body << "# HELP " << name << " " << help << "\n"
             << "# TYPE " << name << " histogram\n";
        const DelayHistogram* histos[] = {&ha, &hb};
        const char* labels[] = {label_a, label_b};
        for (int i = 0; i < 2; ++i) {
            const DelayHistogram& h = *histos[i];
            uint64_t cumulative = 0;
            for (size_t b = 0; b < DelayHistogram::kBucketCount; ++b) {
                cumulative += h.buckets[b].load(std::memory_order_relaxed);
                body << name << "_bucket{" << label_name << "=\"" << labels[i] << "\",le=\"";
                if (b < DelayHistogram::kBoundCount) {
                    body << DelayHistogram::kBounds[b];
                } else {
                    body << "+Inf";
                }
                body << "\"" << lbl << "} " << cumulative << "\n";
            }
            const double sum_s = static_cast<double>(h.sum_micros.load(std::memory_order_relaxed)) / 1e6;
            body << name << "_sum{" << label_name << "=\"" << labels[i] << "\"" << lbl << "} " << sum_s << "\n"
                 << name << "_count{" << label_name << "=\"" << labels[i] << "\"" << lbl << "} "
                 << h.count.load(std::memory_order_relaxed) << "\n";
        }
    };

    emit_labeled_delay_hist(
        "xrootd_openverify_queue_wait_seconds",
        "FIFO wait for a verify slot (leaders only; excludes queue_full immediate rejects).", "result", "admitted",
        m_queue_wait_admitted, "timeout", m_queue_wait_timeout);
    emit_labeled_delay_hist("xrootd_openverify_verify_rtt_seconds",
                            "open_verify wall time after FIFO admission (excludes queue wait).", "result", "success",
                            m_verify_rtt_success, "failure", m_verify_rtt_failure);
    {
        const char* name = "xrootd_openverify_locate_rtt_seconds";
        body << "# HELP " << name << " Wall time of one Rucio list_replicas (cache miss; excludes verify).\n"
             << "# TYPE " << name << " histogram\n";
        const DelayHistogram& h = m_locate_rtt_rucio;
        uint64_t cumulative = 0;
        for (size_t b = 0; b < DelayHistogram::kBucketCount; ++b) {
            cumulative += h.buckets[b].load(std::memory_order_relaxed);
            body << name << "_bucket{source=\"rucio\",le=\"";
            if (b < DelayHistogram::kBoundCount) {
                body << DelayHistogram::kBounds[b];
            } else {
                body << "+Inf";
            }
            body << "\"" << lbl << "} " << cumulative << "\n";
        }
        const double sum_s = static_cast<double>(h.sum_micros.load(std::memory_order_relaxed)) / 1e6;
        body << name << "_sum{source=\"rucio\"" << lbl << "} " << sum_s << "\n"
             << name << "_count{source=\"rucio\"" << lbl << "} " << h.count.load(std::memory_order_relaxed) << "\n";
    }

    body << "# HELP xrootd_openverify_verify_failures_total OpenVerify verify failures by locate source, "
            "redirect target and reason.\n"
            "# TYPE xrootd_openverify_verify_failures_total counter\n";

    {
        std::lock_guard<std::mutex> lock(m_failure_mtx);
        for (const auto& kv : m_failures_by_target_reason) {
            const PerFailureMetrics* e = kv.second.get();
            if (!e) continue;
            body << "xrootd_openverify_verify_failures_total{source=\"" << e->source_esc << "\",host=\""
                 << e->host_esc << "\",port=\"" << e->port_lbl << "\",reason=\"" << e->reason_esc << "\"" << lbl
                 << "} " << e->count.load(std::memory_order_relaxed) << "\n";
        }
    }

    body << "# HELP xrootd_openverify_verify_probes_total Actual open_verify runs by locate source, "
            "redirect target and result (success|failure). Cache hits are not probes.\n"
            "# TYPE xrootd_openverify_verify_probes_total counter\n";
    {
        std::lock_guard<std::mutex> lock(m_probe_mtx);
        for (const auto& kv : m_probes_by_target_result) {
            const PerProbeMetrics* e = kv.second.get();
            if (!e) continue;
            body << "xrootd_openverify_verify_probes_total{source=\"" << e->source_esc << "\",host=\""
                 << e->host_esc << "\",port=\"" << e->port_lbl << "\",result=\"" << e->result_esc << "\"" << lbl
                 << "} " << e->count.load(std::memory_order_relaxed) << "\n";
        }
    }

    body << "# HELP xrootd_openverify_host_busy_total Leaders rejected because this host already "
            "held the per-host inflight cap (default 50% of MAX_INFLIGHT).\n"
            "# TYPE xrootd_openverify_host_busy_total counter\n";
    {
        std::lock_guard<std::mutex> lock(m_host_busy_mtx);
        for (const auto& kv : m_host_busy) {
            const PerHostBusyMetrics* e = kv.second.get();
            if (!e) continue;
            body << "xrootd_openverify_host_busy_total{host=\"" << e->host_esc << "\",port=\"" << e->port_lbl << "\""
                 << lbl << "} " << e->count.load(std::memory_order_relaxed) << "\n";
        }
    }

    OpenVerifyHostReliability* sites_src = m_sites.load(std::memory_order_acquire);
    if (sites_src) {
        const auto fs = sites_src->GetFailSafeSnapshot();
        const std::string inst =
            m_instance_label.empty() ? std::string() : ("{xrootd_instance=\"" + m_instance_label + "\"}");
        body << "# HELP xrootd_openverify_failsafe_active 1 if mass-quarantine circuit breaker is open "
                "(site skip disabled).\n"
                "# TYPE xrootd_openverify_failsafe_active gauge\n"
                "xrootd_openverify_failsafe_active"
             << inst << " " << (fs.active ? 1 : 0) << "\n"
             << "# HELP xrootd_openverify_failsafe_trips_total Times the mass-quarantine circuit breaker opened.\n"
                "# TYPE xrootd_openverify_failsafe_trips_total counter\n"
                "xrootd_openverify_failsafe_trips_total"
             << inst << " " << fs.trips << "\n"
             << "# HELP xrootd_openverify_failsafe_recent_sites Unique sites that entered quarantine in the "
                "fail-safe window.\n"
                "# TYPE xrootd_openverify_failsafe_recent_sites gauge\n"
                "xrootd_openverify_failsafe_recent_sites"
             << inst << " " << fs.recent_sites << "\n"
             << "# HELP xrootd_openverify_failsafe_max_sites Unique sites in the window that trip the fail-safe "
                "(0 disables).\n"
                "# TYPE xrootd_openverify_failsafe_max_sites gauge\n"
                "xrootd_openverify_failsafe_max_sites"
             << inst << " " << fs.max_sites << "\n";

        const auto sites = sites_src->Snapshot();
        body << "# HELP xrootd_openverify_site_ewma_health EWMA badness score (0=healthy, higher=worse).\n"
                "# TYPE xrootd_openverify_site_ewma_health gauge\n"
                "# HELP xrootd_openverify_site_healthy 1 if site is not quarantined, else 0.\n"
                "# TYPE xrootd_openverify_site_healthy gauge\n"
                "# HELP xrootd_openverify_site_verify_successes_total Per-site verify successes.\n"
                "# TYPE xrootd_openverify_site_verify_successes_total counter\n"
                "# HELP xrootd_openverify_site_verify_failures_total Per-site verify failures.\n"
                "# TYPE xrootd_openverify_site_verify_failures_total counter\n";
        for (const auto& s : sites) {
            // Static xrootd.redirect fallbacks are not site gateways — do not export
            // health/failure gauges that would classify transit as an unhealthy site.
            if (IsStaticXrootdFallbackHost(s.host)) continue;
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
    NoteUpdate();
}

void OpenVerifyMetrics::RecordCacheHitPositive(double delay_seconds) {
    m_cache_hit_positive.fetch_add(1, std::memory_order_relaxed);
    if (delay_seconds >= 0) RecordRedirectDelay(delay_seconds, DelayOutcome::CacheHitPositive);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordCacheHitNegative(double delay_seconds) {
    m_cache_hit_negative.fetch_add(1, std::memory_order_relaxed);
    if (delay_seconds >= 0) RecordRedirectDelay(delay_seconds, DelayOutcome::CacheHitNegative);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordVerifySuccess(const std::string& source, const std::string& host, int port) {
    m_verify_success.fetch_add(1, std::memory_order_relaxed);
    EnsureProbe(source, host, port, "success").count.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordVerifyFailure(const std::string& source, const std::string& host, int port,
                                            const std::string& reason) {
    const std::string r = reason.empty() ? std::string("unknown") : reason;
    m_verify_failure.fetch_add(1, std::memory_order_relaxed);
    EnsureFailure(source, host, port, r).count.fetch_add(1, std::memory_order_relaxed);
    EnsureProbe(source, host, port, "failure").count.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordQueueAdmissionAdmitted() {
    m_queue_admitted.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordQueueAdmissionFull() {
    m_queue_full.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordQueueAdmissionTimeout() {
    m_queue_timeout.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordQueueAdmissionHostBusy() {
    m_queue_host_busy.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordHostBusy(const std::string& host, int port) {
    std::string h = host.empty() ? std::string("unknown") : host;
    const std::string pl = PortLabelForMetrics(port);
    {
        std::lock_guard<std::mutex> lock(m_host_busy_mtx);
        const std::string raw_key = h + '\x1e' + pl;
        if (m_host_busy.size() >= 4096 && !m_host_busy.count(raw_key)) {
            h = "other";
        }
        const std::string key = h + '\x1e' + pl;
        std::unique_ptr<PerHostBusyMetrics>& slot = m_host_busy[key];
        if (!slot) {
            slot = std::make_unique<PerHostBusyMetrics>();
            slot->host_esc = EscapeLabelValue(h);
            slot->port_lbl = pl;
        }
        slot->count.fetch_add(1, std::memory_order_relaxed);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::RecordQueueWait(double seconds, bool timed_out) {
    ObserveHistogram(timed_out ? m_queue_wait_timeout : m_queue_wait_admitted, seconds);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordVerifyRtt(double seconds, bool success) {
    ObserveHistogram(success ? m_verify_rtt_success : m_verify_rtt_failure, seconds);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordSingleFlightLeader() {
    m_singleflight_leader.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordSingleFlightFollower() {
    m_singleflight_follower.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRedirectHandled() {
    m_redirects_handled.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRedirectAvoided(const std::string& reason, double delay_seconds) {
    if (reason == "quarantine") {
        m_redirects_avoided_quarantine.fetch_add(1, std::memory_order_relaxed);
        if (delay_seconds >= 0) RecordRedirectDelay(delay_seconds, DelayOutcome::Avoided);
    } else if (reason == "host_busy") {
        m_redirects_avoided_host_busy.fetch_add(1, std::memory_order_relaxed);
        if (delay_seconds >= 0) RecordRedirectDelay(delay_seconds, DelayOutcome::HostBusy);
    } else {
        m_redirects_avoided_negative_cache.fetch_add(1, std::memory_order_relaxed);
        if (delay_seconds >= 0) RecordRedirectDelay(delay_seconds, DelayOutcome::Avoided);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRedirectVerifyFinished(bool success, double delay_seconds) {
    RecordRedirectDelay(delay_seconds, success ? DelayOutcome::VerifySuccess : DelayOutcome::VerifyFailure);
}

void OpenVerifyMetrics::RecordRedirectQueueRejected(const std::string& kind, double delay_seconds) {
    if (kind == "queue_full") {
        RecordRedirectDelay(delay_seconds, DelayOutcome::QueueFull);
    } else {
        // Default / "queue_timeout"
        RecordRedirectDelay(delay_seconds, DelayOutcome::QueueTimeout);
    }
}

void OpenVerifyMetrics::RecordCmsdStall(int seconds) {
    if (seconds <= 0) return;
    m_cmsd_stall_events.fetch_add(1, std::memory_order_relaxed);
    m_cmsd_stall_seconds_sum.fetch_add(static_cast<uint64_t>(seconds), std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordOpenAccepted(int attempt, const std::string& source) {
    if (attempt < 1) attempt = 1;
    if (source == "rucio") {
        if (attempt > kMaxRucioReplicaLabel) attempt = kMaxRucioReplicaLabel;
        {
            std::lock_guard<std::mutex> lock(m_rucio_accept_mtx);
            m_accepted_rucio_by_replica[attempt] += 1;
        }
    } else if (source == "xrootd") {
        m_accepted_xrootd.fetch_add(1, std::memory_order_relaxed);
    } else if (source == "skip") {
        m_accepted_skip.fetch_add(1, std::memory_order_relaxed);
    } else {
        if (attempt > kMaxCmsdAcceptAttempts) attempt = kMaxCmsdAcceptAttempts;
        m_accepted_cmsd_by_attempt[attempt - 1].fetch_add(1, std::memory_order_relaxed);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::RecordStaticFallback(const std::string& fallback) {
    if (fallback == "transit") {
        m_static_fallback_transit.fetch_add(1, std::memory_order_relaxed);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::RecordSkipPrefix(const std::string& reason_in) {
    std::string reason = reason_in.empty() ? std::string("unknown") : reason_in;
    {
        std::lock_guard<std::mutex> lock(m_skip_prefix_mtx);
        if (m_skip_prefix_by_reason.size() >= 64 && !m_skip_prefix_by_reason.count(reason)) {
            reason = "other";
        }
        std::unique_ptr<PerSkipReasonMetrics>& slot = m_skip_prefix_by_reason[reason];
        if (!slot) {
            slot = std::make_unique<PerSkipReasonMetrics>();
            slot->reason_esc = EscapeLabelValue(reason);
        }
        slot->count.fetch_add(1, std::memory_order_relaxed);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::RecordOpenRetryExhausted() {
    m_retry_exhausted.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRucioLookup(const std::string& result, const std::string& skip_reason) {
    if (result == "ok") {
        m_rucio_lookup_ok.fetch_add(1, std::memory_order_relaxed);
    } else if (result == "empty") {
        m_rucio_lookup_empty.fetch_add(1, std::memory_order_relaxed);
    } else if (result == "auth_error") {
        m_rucio_lookup_auth_error.fetch_add(1, std::memory_order_relaxed);
    } else if (result == "timeout") {
        m_rucio_lookup_timeout.fetch_add(1, std::memory_order_relaxed);
    } else if (result == "skipped") {
        m_rucio_lookup_skipped.fetch_add(1, std::memory_order_relaxed);
        std::string reason = skip_reason.empty() ? std::string("unknown") : skip_reason;
        {
            std::lock_guard<std::mutex> lock(m_rucio_skip_mtx);
            if (m_rucio_skipped_by_reason.size() >= 64 && !m_rucio_skipped_by_reason.count(reason)) {
                reason = "other";
            }
            std::unique_ptr<PerSkipReasonMetrics>& slot = m_rucio_skipped_by_reason[reason];
            if (!slot) {
                slot = std::make_unique<PerSkipReasonMetrics>();
                slot->reason_esc = EscapeLabelValue(reason);
            }
            slot->count.fetch_add(1, std::memory_order_relaxed);
        }
    } else {
        m_rucio_lookup_error.fetch_add(1, std::memory_order_relaxed);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRucioListCache(const std::string& result) {
    if (result == "hit") {
        m_rucio_list_cache_hit.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_rucio_list_cache_miss.fetch_add(1, std::memory_order_relaxed);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::SetRucioListCacheEntries(std::size_t n) {
    m_rucio_list_cache_entries.store(static_cast<uint64_t>(n), std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRucioCandidates(size_t count) {
    if (count == 0) return;
    m_rucio_candidates.fetch_add(static_cast<uint64_t>(count), std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRucioExhausted() {
    m_rucio_exhausted.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRucioExhaustedRecovered() {
    m_rucio_exhausted_recovered.fetch_add(1, std::memory_order_relaxed);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRucioCmsdCompare(const std::string& result) {
    if (result == "overlap") {
        m_rucio_cmsd_compare_overlap.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_rucio_cmsd_compare_catalog_disagree.fetch_add(1, std::memory_order_relaxed);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::RecordLocationSource(const std::string& source) {
    if (source == "rucio") {
        m_location_source_rucio.fetch_add(1, std::memory_order_relaxed);
    } else if (source == "xrootd") {
        m_location_source_xrootd.fetch_add(1, std::memory_order_relaxed);
    } else if (source == "skip") {
        m_location_source_skip.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_location_source_cmsd.fetch_add(1, std::memory_order_relaxed);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::RecordLocateLatency(const std::string& source, double seconds) {
    if (seconds < 0 || source != "rucio") return;
    ObserveHistogram(m_locate_rtt_rucio, seconds);
    NoteUpdate();
}

void OpenVerifyMetrics::RecordRucioCurlTransfer(bool handle_reused, bool tcp_reused) {
    if (handle_reused) {
        m_rucio_curl_handle_reused.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_rucio_curl_handle_new.fetch_add(1, std::memory_order_relaxed);
    }
    if (tcp_reused) {
        m_rucio_curl_tcp_reused.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_rucio_curl_tcp_new.fetch_add(1, std::memory_order_relaxed);
    }
    NoteUpdate();
}

void OpenVerifyMetrics::SetRucioCurlPool(std::size_t handles, std::size_t idle, std::size_t inflight,
                                         std::uint64_t grows, std::uint64_t shrinks) {
    m_rucio_curl_pool_handles.store(static_cast<uint64_t>(handles), std::memory_order_relaxed);
    m_rucio_curl_pool_idle.store(static_cast<uint64_t>(idle), std::memory_order_relaxed);
    m_rucio_curl_pool_inflight.store(static_cast<uint64_t>(inflight), std::memory_order_relaxed);
    m_rucio_curl_pool_grows.store(grows, std::memory_order_relaxed);
    m_rucio_curl_pool_shrinks.store(shrinks, std::memory_order_relaxed);
    NoteUpdate();
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

void OpenVerifyMetrics::RedirectTimer::QueueRejected(const std::string& kind) {
    if (m_done) return;
    m_done = true;
    m_metrics.RecordRedirectQueueRejected(kind, ElapsedSeconds());
}

void OpenVerifyMetrics::RedirectTimer::Passthrough() {
    if (m_done) return;
    m_done = true;
    m_metrics.RecordRedirectDelay(ElapsedSeconds(), DelayOutcome::Passthrough);
}

void OpenVerifyMetrics::RecordRedirectDelay(double seconds, DelayOutcome outcome) {
    const int oi = static_cast<int>(outcome);
    if (oi < 0 || oi >= static_cast<int>(DelayOutcome::Count)) return;
    ObserveHistogram(m_delay[oi], seconds);
    NoteUpdate();
}

void OpenVerifyMetrics::ObserveHistogram(DelayHistogram& h, double seconds) {
    if (seconds < 0) seconds = 0;
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
}

void OpenVerifyMetrics::Flush() {
    const std::string tmp_path = m_path + ".tmp";

    // Snapshot under the write lock: a body built earlier must never be renamed over a newer one,
    // or Prometheus sees counters decrease and treats it as a reset.
    std::lock_guard<std::mutex> lock(m_write_mtx);
    const std::string content = BuildExpositionBody();

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
