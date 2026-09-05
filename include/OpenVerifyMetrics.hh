#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class OpenVerifyHostReliability;

// In-memory counters for OpenVerify cache / verify runs; optional text file mirror (Prometheus text format).
//
// XRD_OPENVERIFY_METRICS_PATH: absolute path of the .prom file to write. For node_exporter, use
// one file per daemon under the textfile directory (distinct basenames per writer). If unset,
// falls back to <getcwd()>/openverify_metrics.prom. Set to an empty string to disable file export.
// On startup the file is rewritten from current counters (zeros) so disk cannot lag after restart.
//
// XRD_OPENVERIFY_METRICS_INSTANCE: optional xrootd_instance label value (recommended when several
// daemons write into one collector dir). If unset, defaults to the basename of getcwd(); if set
// but empty, the label is omitted.
//
// XRD_OPENVERIFY_OBSERVE: if set to exactly 1, OpenVerify records cache
// miss/hit metrics and runs open_verify only on cache miss (same as enforce), but does not
// inject tried=, or retry; the first SFS_REDIRECT from the wrapped OFS is
// returned unchanged.
//
// XRD_OPENVERIFY_DIRECT_SERVER: if set to exactly 1, after a successful verify
// (or positive-cache hit that recorded a data server), rewrite the client
// SFS_REDIRECT host/port to that final data server instead of the cmsd next hop
// (typically a site / lower redirector). Applies to the cmsd path only — unsafe
// for EOS when pointing at an FST (missing MGM-signed opaque). Rucio-first
// redirects always use the site gateway from the PFN.
//
// XRD_OPENVERIFY_RUCIO=1: try CMS Rucio replica lookup before cmsd (see OpenVerifyRucio.hh).
// XRD_OPENVERIFY_RUCIO_CACHE_TTL / XRD_OPENVERIFY_RUCIO_CACHE_SIZE: list_replicas LRU.
// XRD_OPENVERIFY_RUCIO_POOL_MIN / _MAX: elastic libcurl handle pool (default 1–500; raise MIN via puppet).
// XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX: skip list_replicas only; cmsd locate is still verified.
// XRD_OPENVERIFY_SKIP_PREFIX: skip Rucio *and* verify; one cmsd open, pass the redirect through
// (same idea as transit). Use for SAM AAA `/store/test/xrootd` — ignore-prefix alone still
// verify-opens regional hops from the global host. See README.
//
// Static xrootd.redirect fallbacks (cms-xrd-transit.cern.ch) are accepted without
// verify and counted as location_source=xrootd / static_fallback=transit.
//
// XRD_OPENVERIFY_VERIFY_TIMEOUT: outbound probe timeout in seconds (default 15).
// FIFO wait defaults to twice that (30s); override with XRD_OPENVERIFY_QUEUE_TIMEOUT_MS.
// XRD_OPENVERIFY_MAX_INFLIGHT / XRD_OPENVERIFY_MAX_INFLIGHT_PER_HOST (default 50% of inflight).
//
// Site EWMA quarantine (see OpenVerifyHostReliability.hh): XRD_OPENVERIFY_EWMA_ALPHA_FAIL
// (default 0.05), XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS (0.10), XRD_OPENVERIFY_MIN_ATTEMPTS (20),
// XRD_OPENVERIFY_QUARANTINE_THRESHOLD (0.6), XRD_OPENVERIFY_RECOVER_THRESHOLD (0.4),
// XRD_OPENVERIFY_PROBE_COOLDOWN seconds (60). Mass-quarantine fail-safe:
// XRD_OPENVERIFY_FAILSAFE_MAX_SITES (default 8; 0 disables), XRD_OPENVERIFY_FAILSAFE_WINDOW
// seconds (300).
//
class OpenVerifyMetrics {
   public:
    // Outcome label for redirect-handling delay histogram (plugin time after OFS returns SFS_REDIRECT).
    enum class DelayOutcome : int {
        CacheHitPositive = 0,
        CacheHitNegative,
        VerifySuccess,
        VerifyFailure,
        Avoided,
        QueueTimeout,  // FIFO wait hit QUEUE_TIMEOUT; open_verify never ran
        QueueFull,     // wait queue full; open_verify never ran
        HostBusy,      // host already at 50% of MAX_INFLIGHT; skipped via tried=
        Passthrough,   // static xrootd.redirect fallback or SKIP_PREFIX; no verify
        Count
    };

    OpenVerifyMetrics();
    OpenVerifyMetrics(const OpenVerifyMetrics&) = delete;
    OpenVerifyMetrics& operator=(const OpenVerifyMetrics&) = delete;

    // Optional: export per-site EWMA gauges from HostReliability on each Flush.
    void SetSiteSource(OpenVerifyHostReliability* sites) { m_sites = sites; }

    void RecordCacheMiss();
    // delay_seconds >= 0 also updates redirect_delay_seconds histogram for this outcome.
    void RecordCacheHitPositive(double delay_seconds = -1);
    void RecordCacheHitNegative(double delay_seconds = -1);
    void RecordVerifySuccess();
    // After a cache miss, open_verify failed; reason is a stable snake_case label (e.g. permission_denied).
    // source is the locate path: "rucio" or "cmsd".
    void RecordVerifyFailure(const std::string& source, const std::string& host, int port, const std::string& reason);
    // Queue admission outcomes around main semaphore acquisition.
    void RecordQueueAdmissionAdmitted();
    void RecordQueueAdmissionFull();
    void RecordQueueAdmissionTimeout();
    void RecordQueueAdmissionHostBusy();
    // Leader rejected because this host:port already held the per-host inflight cap.
    void RecordHostBusy(const std::string& host, int port);
    // FIFO wait before a verify slot (leaders only). timed_out=true when wait hit QUEUE_TIMEOUT.
    void RecordQueueWait(double seconds, bool timed_out);
    // Wall time inside open_verify (leaders that were admitted and ran fn).
    void RecordVerifyRtt(double seconds, bool success);
    // Single-flight request role split.
    void RecordSingleFlightLeader();
    void RecordSingleFlightFollower();

    // One SFS_REDIRECT observed (before avoid/cache/verify decision).
    void RecordRedirectHandled();
    // Bad redirect skipped: reason quarantine | negative_cache | host_busy.
    void RecordRedirectAvoided(const std::string& reason, double delay_seconds = -1);
    // Wall time for a verify miss path after single-flight returns (counters already recorded).
    // Only for paths that reached open_verify (or shared a leader that did).
    void RecordRedirectVerifyFinished(bool success, double delay_seconds);
    // Miss path ended in FIFO reject before open_verify. kind: queue_timeout | queue_full.
    void RecordRedirectQueueRejected(const std::string& kind, double delay_seconds);

    // cmsd returned SFS_STALL (rc > 0 seconds). Passed through to the client/bridge.
    // No host label: stall is pre-redirect lookup delay.
    void RecordCmsdStall(int seconds);

    // Open accepted a verified/cached-positive redirect after `attempt` candidate
    // sites within `source` ("rucio", "cmsd", "xrootd", or "skip"). Counters are
    // separate per source.
    // cmsd: which redirect candidate (1..kMaxCmsdAcceptAttempts) was accepted.
    // rucio: which ordered PFN/replica (1..kMaxRucioReplicaLabel) passed verify;
    // overflow label is "N+" (CMS files do not have dozens of replicas).
    // xrootd: static xrootd.redirect ENOENT fallback (attempt always 1).
    // skip: XRD_OPENVERIFY_SKIP_PREFIX passthrough (attempt always 1; no verify).
    // Observe: only replica/attempt 1.
    void RecordOpenAccepted(int attempt, const std::string& source);
    // Static xrootd.redirect fallback accepted without verify (fallback=transit, …).
    void RecordStaticFallback(const std::string& fallback);
    // LFN matched XRD_OPENVERIFY_SKIP_PREFIX: cmsd locate, no Rucio, no verify.
    // reason is the matched prefix (e.g. /store/test/xrootd).
    void RecordSkipPrefix(const std::string& reason);
    // Enforce mode only: cmsd retry budget fully spent with no accepted verify;
    // last redirect returned best-effort. Never recorded in observe mode.
    void RecordOpenRetryExhausted();

    // Rucio list_replicas outcome: ok | empty | auth_error | timeout | error | skipped.
    // empty = no replicas (soft-fail to cmsd); auth/timeout/error also soft-fail.
    // skipped = LFN matched XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX (no REST call).
    // skip_reason is the matched prefix when result==skipped (e.g. /store/user).
    void RecordRucioLookup(const std::string& result, const std::string& skip_reason = {});
    // list_replicas LRU: hit | miss (not recorded for disabled/skipped).
    void RecordRucioListCache(const std::string& result);
    void SetRucioListCacheEntries(std::size_t n);
    // Number of PFN candidates returned by a successful Rucio lookup.
    void RecordRucioCandidates(size_t count);
    // Lookup was ok (PFNs returned) but none accepted; fall through to cmsd.
    // Distinct from soft-fail (empty/auth/timeout/error) and from cmsd retry_exhausted.
    void RecordRucioExhausted();
    // After rucio exhaust, cmsd openverify accepted (recovery). Subset of exhausted;
    // excludes soft-fail→cmsd and exhaust where cmsd also fails.
    void RecordRucioExhaustedRecovered();
    // After rucio exhaust, cmsd accepted: was that host already in the Rucio PFN list?
    // result: overlap | catalog_disagree (diagnostic; sum equals recovered).
    void RecordRucioCmsdCompare(const std::string& result);
    // Accepted open locate path: rucio | cmsd | xrootd (static redirect fallback) | skip.
    void RecordLocationSource(const std::string& source);
    // Wall time of one Rucio list_replicas (cache miss).
    void RecordLocateLatency(const std::string& source, double seconds);
    // After one Rucio HTTP transfer: easy-handle reuse + TCP reuse (CURLINFO_NUM_CONNECTS==0).
    void RecordRucioCurlTransfer(bool handle_reused, bool tcp_reused);
    // Curl pool snapshot (gauges + lifetime grow/shrink counters).
    void SetRucioCurlPool(std::size_t handles, std::size_t idle, std::size_t inflight, std::uint64_t grows,
                          std::uint64_t shrinks);

    // cmsd / wrapped-OFS candidate budget (enforce).
    static constexpr int kMaxCmsdAcceptAttempts = 3;
    // Rucio replica-index label cap; above this → "N+" (e.g. "5+").
    static constexpr int kMaxRucioReplicaLabel = 5;
    // Backward-compatible alias used by cmsd open loop.
    static constexpr int kMaxAcceptAttempts = kMaxCmsdAcceptAttempts;

    // Starts at construction (records redirects_handled). Call exactly one terminal method.
    class RedirectTimer {
       public:
        explicit RedirectTimer(OpenVerifyMetrics& metrics);
        RedirectTimer(const RedirectTimer&) = delete;
        RedirectTimer& operator=(const RedirectTimer&) = delete;

        void CacheHitPositive();
        void CacheHitNegative(bool count_as_avoided);
        void Avoided(const std::string& reason);
        void VerifyFinished(bool success);
        // kind: queue_timeout | queue_full (must match SingleFlight error messages without prefix).
        void QueueRejected(const std::string& kind);
        // Static xrootd.redirect fallback or SKIP_PREFIX: return redirect unchanged.
        void Passthrough();

       private:
        double ElapsedSeconds() const;

        OpenVerifyMetrics& m_metrics;
        std::chrono::steady_clock::time_point m_t0;
        bool m_done{false};
    };

    bool FileExportEnabled() const { return !m_path.empty(); }

   private:
    struct PerFailureMetrics {
        std::string source_esc;
        std::string host_esc;
        std::string port_lbl;
        std::string reason_esc;
        std::atomic<uint64_t> count{0};
    };

    struct DelayHistogram {
        // Upper bounds in seconds; final bucket is +Inf.
        // Fine bins for cache hits; coarser above 1s for queue wait / verify RTT / timeouts.
        static constexpr double kBounds[] = {0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 7.5, 10.0, 15.0, 30.0};
        static constexpr size_t kBoundCount = sizeof(kBounds) / sizeof(kBounds[0]);
        static constexpr size_t kBucketCount = kBoundCount + 1;  // +Inf

        std::atomic<uint64_t> buckets[kBucketCount]{};
        std::atomic<uint64_t> count{0};
        std::atomic<uint64_t> sum_micros{0};
    };

    PerFailureMetrics& EnsureFailure(const std::string& source, const std::string& host, int port,
                                     const std::string& reason);
    void RecordRedirectDelay(double seconds, DelayOutcome outcome);
    static void ObserveHistogram(DelayHistogram& h, double seconds);
    std::string BuildExpositionBody() const;
    void Flush();

    std::string m_path;
    std::string m_instance_label;  // optional "xrootd_instance" label value (from env)
    std::mutex m_write_mtx;
    OpenVerifyHostReliability* m_sites{nullptr};

    std::atomic<uint64_t> m_cache_miss{0};
    std::atomic<uint64_t> m_cache_hit_positive{0};
    std::atomic<uint64_t> m_cache_hit_negative{0};
    std::atomic<uint64_t> m_verify_success{0};
    std::atomic<uint64_t> m_verify_failure{0};
    std::atomic<uint64_t> m_queue_admitted{0};
    std::atomic<uint64_t> m_queue_full{0};
    std::atomic<uint64_t> m_queue_timeout{0};
    std::atomic<uint64_t> m_queue_host_busy{0};
    std::atomic<uint64_t> m_singleflight_leader{0};
    std::atomic<uint64_t> m_singleflight_follower{0};
    std::atomic<uint64_t> m_redirects_handled{0};
    std::atomic<uint64_t> m_redirects_avoided_quarantine{0};
    std::atomic<uint64_t> m_redirects_avoided_negative_cache{0};
    std::atomic<uint64_t> m_redirects_avoided_host_busy{0};
    std::atomic<uint64_t> m_cmsd_stall_events{0};
    std::atomic<uint64_t> m_cmsd_stall_seconds_sum{0};
    std::atomic<uint64_t> m_accepted_cmsd_by_attempt[kMaxCmsdAcceptAttempts]{};
    std::atomic<uint64_t> m_accepted_xrootd{0};
    std::atomic<uint64_t> m_accepted_skip{0};
    std::atomic<uint64_t> m_static_fallback_transit{0};
    std::atomic<uint64_t> m_retry_exhausted{0};

    std::atomic<uint64_t> m_rucio_lookup_ok{0};
    std::atomic<uint64_t> m_rucio_lookup_empty{0};
    std::atomic<uint64_t> m_rucio_lookup_auth_error{0};
    std::atomic<uint64_t> m_rucio_lookup_timeout{0};
    std::atomic<uint64_t> m_rucio_lookup_error{0};
    std::atomic<uint64_t> m_rucio_lookup_skipped{0};
    std::atomic<uint64_t> m_rucio_list_cache_hit{0};
    std::atomic<uint64_t> m_rucio_list_cache_miss{0};
    std::atomic<uint64_t> m_rucio_list_cache_entries{0};
    std::atomic<uint64_t> m_rucio_candidates{0};
    std::atomic<uint64_t> m_rucio_exhausted{0};
    std::atomic<uint64_t> m_rucio_exhausted_recovered{0};
    std::atomic<uint64_t> m_rucio_cmsd_compare_overlap{0};
    std::atomic<uint64_t> m_rucio_cmsd_compare_catalog_disagree{0};
    std::atomic<uint64_t> m_location_source_rucio{0};
    std::atomic<uint64_t> m_location_source_cmsd{0};
    std::atomic<uint64_t> m_location_source_xrootd{0};
    std::atomic<uint64_t> m_location_source_skip{0};
    std::atomic<uint64_t> m_rucio_curl_tcp_reused{0};
    std::atomic<uint64_t> m_rucio_curl_tcp_new{0};
    std::atomic<uint64_t> m_rucio_curl_handle_reused{0};
    std::atomic<uint64_t> m_rucio_curl_handle_new{0};
    std::atomic<uint64_t> m_rucio_curl_pool_handles{0};
    std::atomic<uint64_t> m_rucio_curl_pool_idle{0};
    std::atomic<uint64_t> m_rucio_curl_pool_inflight{0};
    std::atomic<uint64_t> m_rucio_curl_pool_grows{0};
    std::atomic<uint64_t> m_rucio_curl_pool_shrinks{0};

    DelayHistogram m_delay[static_cast<int>(DelayOutcome::Count)];
    // Leaders that entered the FIFO: wait until admit or timeout.
    DelayHistogram m_queue_wait_admitted;
    DelayHistogram m_queue_wait_timeout;
    // Leaders that ran open_verify after admission.
    DelayHistogram m_verify_rtt_success;
    DelayHistogram m_verify_rtt_failure;
    // Rucio list_replicas RTT (cache miss).
    DelayHistogram m_locate_rtt_rucio;

    mutable std::mutex m_failure_mtx;
    mutable std::unordered_map<std::string, std::unique_ptr<PerFailureMetrics>> m_failures_by_target_reason;

    struct PerHostBusyMetrics {
        std::string host_esc;
        std::string port_lbl;
        std::atomic<uint64_t> count{0};
    };
    mutable std::mutex m_host_busy_mtx;
    mutable std::unordered_map<std::string, std::unique_ptr<PerHostBusyMetrics>> m_host_busy;

    struct PerSkipReasonMetrics {
        std::string reason_esc;
        std::atomic<uint64_t> count{0};
    };
    mutable std::mutex m_rucio_skip_mtx;
    mutable std::unordered_map<std::string, std::unique_ptr<PerSkipReasonMetrics>> m_rucio_skipped_by_reason;
    mutable std::mutex m_skip_prefix_mtx;
    mutable std::unordered_map<std::string, std::unique_ptr<PerSkipReasonMetrics>> m_skip_prefix_by_reason;

    // Rucio: replica index in try-order that passed verify → count (N or kMaxRucioReplicaLabel).
    mutable std::mutex m_rucio_accept_mtx;
    std::unordered_map<int, uint64_t> m_accepted_rucio_by_replica;
};
