#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

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
// xrootd_openverify_verify_failures_total counts failed verify runs (after a cache miss) with
// labels host, port (or "none"), and reason. Until the first failure, exposition uses a zero
// placeholder with host/port/reason "_" so Prometheus registers the metric (omit "_" in sums).
//
class OpenVerifyMetrics {
   public:
    OpenVerifyMetrics();
    OpenVerifyMetrics(const OpenVerifyMetrics&) = delete;
    OpenVerifyMetrics& operator=(const OpenVerifyMetrics&) = delete;

    void RecordCacheMiss();
    void RecordCacheHitPositive();
    void RecordCacheHitNegative();
    void RecordVerifySuccess();
    // After a cache miss, open_verify failed; reason is a stable snake_case label (e.g. permission_denied).
    void RecordVerifyFailure(const std::string& host, int port, const std::string& reason);

    bool FileExportEnabled() const { return !m_path.empty(); }

   private:
    struct PerFailureMetrics {
        std::string host_esc;
        std::string port_lbl;
        std::string reason_esc;
        std::atomic<uint64_t> count{0};
    };

    PerFailureMetrics& EnsureFailure(const std::string& host, int port, const std::string& reason);
    std::string BuildExpositionBody() const;
    void Flush();

    std::string m_path;
    std::string m_instance_label;  // optional "xrootd_instance" label value (from env)
    std::mutex m_write_mtx;

    std::atomic<uint64_t> m_cache_miss{0};
    std::atomic<uint64_t> m_cache_hit_positive{0};
    std::atomic<uint64_t> m_cache_hit_negative{0};
    std::atomic<uint64_t> m_verify_success{0};
    std::atomic<uint64_t> m_verify_failure{0};

    mutable std::mutex m_failure_mtx;
    mutable std::unordered_map<std::string, std::unique_ptr<PerFailureMetrics>> m_failures_by_target_reason;
};
