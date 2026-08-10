#pragma once

#include <memory>
#include <string>

#include "XrdSys/XrdSysError.hh"
#include "XrdSys/XrdSysLogger.hh"

// Optional dedicated text log for live OpenVerify probe failures.
//
// XRD_OPENVERIFY_FAILURE_LOG: absolute path of the failure log file. When unset
// or empty, logging is disabled. When set, OpenVerify binds a private
// XrdSysLogger to that path (no midnight rotate; use system logrotate). Prefer an
// instance log dir (e.g. /var/log/xrootd/fed/openverify-failures.log).
//
// Only live open_verify failures are recorded (one line per single-flight
// leader). Negative-cache hits, quarantine skips, queue rejections, and Rucio
// lookup soft-fails are not written here. Existing daemon WARN lines and
// Prometheus counters are unchanged.
//
struct OpenVerifyFailureRecord {
    std::string source;    // "rucio" or "cmsd"
    int attempt{-1};       // 1-based ordered candidate index for the source path
    std::string host;      // original gateway / cmsd next-hop (not final DS)
    int port{-1};
    std::string path;      // LFN / request path
    std::string pfn;       // Rucio replica PFN, or synthesized root/https URL for cmsd
    std::string protocol;  // "root" or "http"
    std::string stage;     // key | credential_setup | open | stat | empty_file | vector_read
    std::string reason;    // stable classified reason (Prometheus-compatible)
    int status_code{-1};   // XrdCl Status::code
    int err_no{-1};        // XrdCl Status::errNo
    std::string detail;    // low-level Status::ToString() (no URL / credentials)
};

class OpenVerifyFailureLog {
   public:
    OpenVerifyFailureLog() = default;
    OpenVerifyFailureLog(const OpenVerifyFailureLog&) = delete;
    OpenVerifyFailureLog& operator=(const OpenVerifyFailureLog&) = delete;
    ~OpenVerifyFailureLog() = default;

    // Read XRD_OPENVERIFY_FAILURE_LOG and bind when set. Bind failures warn on
    // daemon_log and leave the campaign log disabled.
    void Configure(XrdSysError& daemon_log);

    bool Enabled() const { return m_err != nullptr; }

    void Log(const OpenVerifyFailureRecord& rec);

    // Pure helpers (unit-tested).
    static std::string EscapeValue(const std::string& value);
    static std::string FormatRecord(const OpenVerifyFailureRecord& rec);
    // Credential-free PFN for cmsd redirects: root://host:port//path or https://host:port/path.
    static std::string SynthesizePfn(const std::string& protocol, const std::string& host, int port,
                                     const std::string& path);

   private:
    std::string m_path;
    std::unique_ptr<XrdSysLogger> m_logger;
    std::unique_ptr<XrdSysError> m_err;
};
