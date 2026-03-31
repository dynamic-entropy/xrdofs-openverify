#include "OpenVerifyMetrics.hh"

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
            "# HELP open_verify_calls_total Total number of open_verify() executions.\n"
            "# TYPE open_verify_calls_total counter\n"
            "open_verify_calls_total"
         << (m_instance_label.empty() ? std::string() : std::string("{xrootd_instance=\"") + m_instance_label + "\"")
         << (m_instance_label.empty() ? "" : "}")
         << " " << m_open_verify_calls.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_verify_runs_total OpenVerify executions after a cache miss.\n"
            "# TYPE xrootd_openverify_verify_runs_total counter\n"
            "xrootd_openverify_verify_runs_total{result=\"success\""
         << lbl << "} " << m_verify_success.load(std::memory_order_relaxed) << "\n"
            "xrootd_openverify_verify_runs_total{result=\"failure\""
         << lbl << "} " << m_verify_failure.load(std::memory_order_relaxed) << "\n"
            "# HELP xrootd_openverify_verify_failures_total OpenVerify verify failures by redirect target and reason.\n"
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

    return body.str();
}

void OpenVerifyMetrics::RecordCacheMiss() {
    m_cache_miss.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordCacheHitPositive() {
    m_cache_hit_positive.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordCacheHitNegative() {
    m_cache_hit_negative.fetch_add(1, std::memory_order_relaxed);
    if (!m_path.empty()) Flush();
}

void OpenVerifyMetrics::RecordOpenVerifyCall() {
    m_open_verify_calls.fetch_add(1, std::memory_order_relaxed);
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
