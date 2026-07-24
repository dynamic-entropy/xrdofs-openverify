#pragma once

#include <atomic>
#include <chrono>
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
// (typically a site / lower redirector).
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
    void RecordVerifyFailure(const std::string& host, int port, const std::string& reason);
    // Queue admission outcomes around main semaphore acquisition.
    void RecordQueueAdmissionAdmitted();
    void RecordQueueAdmissionFull();
    void RecordQueueAdmissionTimeout();
    // FIFO wait before a verify slot (leaders only). timed_out=true when wait hit QUEUE_TIMEOUT.
    void RecordQueueWait(double seconds, bool timed_out);
    // Wall time inside open_verify (leaders that were admitted and ran fn).
    void RecordVerifyRtt(double seconds, bool success);
    // Single-flight request role split.
    void RecordSingleFlightLeader();
    void RecordSingleFlightFollower();

    // One SFS_REDIRECT observed (before avoid/cache/verify decision).
    void RecordRedirectHandled();
    // Bad redirect skipped: reason quarantine | negative_cache.
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
    // sites (1 = first cmsd target succeeded). attempt is clamped to [1, kMaxAcceptAttempts].
    // In observe mode only attempt=1 is possible (no retry).
    void RecordOpenAccepted(int attempt);
    // Enforce mode only: retry budget fully spent (retry_count >= max_retries)
    // with no accepted verify; last redirect returned best-effort.
    // Never recorded in observe mode (observe does not retry).
    void RecordOpenRetryExhausted();

    static constexpr int kMaxAcceptAttempts = 3;

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

       private:
        double ElapsedSeconds() const;

        OpenVerifyMetrics& m_metrics;
        std::chrono::steady_clock::time_point m_t0;
        bool m_done{false};
    };

    bool FileExportEnabled() const { return !m_path.empty(); }

   private:
    struct PerFailureMetrics {
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

    // cmsd SFS_STALL is whole seconds; use coarser bounds than DelayHistogram.
    struct StallHistogram {
        static constexpr double kBounds[] = {1, 2, 3, 5, 10, 15, 30, 60};
        static constexpr size_t kBoundCount = sizeof(kBounds) / sizeof(kBounds[0]);
        static constexpr size_t kBucketCount = kBoundCount + 1;  // +Inf

        std::atomic<uint64_t> buckets[kBucketCount]{};
        std::atomic<uint64_t> count{0};
        std::atomic<uint64_t> sum_micros{0};
    };

    PerFailureMetrics& EnsureFailure(const std::string& host, int port, const std::string& reason);
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
    std::atomic<uint64_t> m_singleflight_leader{0};
    std::atomic<uint64_t> m_singleflight_follower{0};
    std::atomic<uint64_t> m_redirects_handled{0};
    std::atomic<uint64_t> m_redirects_avoided_quarantine{0};
    std::atomic<uint64_t> m_redirects_avoided_negative_cache{0};
    std::atomic<uint64_t> m_cmsd_stall_events{0};
    std::atomic<uint64_t> m_cmsd_stall_seconds_sum{0};
    std::atomic<uint64_t> m_accepted_by_attempt[kMaxAcceptAttempts]{};
    std::atomic<uint64_t> m_retry_exhausted{0};

    DelayHistogram m_delay[static_cast<int>(DelayOutcome::Count)];
    // Leaders that entered the FIFO: wait until admit or timeout.
    DelayHistogram m_queue_wait_admitted;
    DelayHistogram m_queue_wait_timeout;
    // Leaders that ran open_verify after admission.
    DelayHistogram m_verify_rtt_success;
    DelayHistogram m_verify_rtt_failure;
    StallHistogram m_cmsd_stall_hist;  // individual cmsd stall durations (seconds)

    mutable std::mutex m_failure_mtx;
    mutable std::unordered_map<std::string, std::unique_ptr<PerFailureMetrics>> m_failures_by_target_reason;
};
