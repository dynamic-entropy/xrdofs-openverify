#pragma once

#include <cstdio>
#include <mutex>
#include <string>

#include "XrdSys/XrdSysError.hh"

// Optional dedicated text log for live OpenVerify probe failures.
//
// XRD_OPENVERIFY_FAILURE_LOG: absolute path of the failure log file. When unset
// or empty, logging is disabled. When set, OpenVerify opens that path for
// append-only writes (private FILE*; not XrdSysLogger). Prefer an instance log
// dir (e.g. /var/log/xrootd/fed/openverify-failures.log). Rotate with system
// logrotate using copytruncate.
//
// Only live open_verify failures are recorded (one line per single-flight
// leader). Normal plugin/daemon INFO/WARN traffic stays on the main xrootd log.
// Negative-cache hits, quarantine skips, queue rejections, and Rucio lookup
// soft-fails are not written here.
//
struct OpenVerifyFailureRecord {
    std::string source;    // "rucio" or "cmsd"
    int attempt{-1};       // 1-based ordered candidate index for the source path
    std::string host;      // original gateway / cmsd next-hop (not final DS)
    int port{-1};
    std::string path;       // LFN / request path
    std::string pfn;        // Rucio replica PFN, or synthesized root/https URL for cmsd
    std::string probe;      // credential-free URL actually passed to XrdCl::Open
    std::string probe_path; // path component of that probe URL (xrdfs-stat comparable)
    std::string protocol;   // "root" or "http"
    std::string stage;      // key | credential_setup | open | stat | empty_file | vector_read
    std::string reason;     // stable classified reason (Prometheus-compatible)
    int status_code{-1};    // XrdCl Status::code
    int err_no{-1};         // XrdCl Status::errNo
    std::string detail;     // low-level Status::ToString() (no URL / credentials)
};

class OpenVerifyFailureLog {
   public:
    OpenVerifyFailureLog() = default;
    OpenVerifyFailureLog(const OpenVerifyFailureLog&) = delete;
    OpenVerifyFailureLog& operator=(const OpenVerifyFailureLog&) = delete;
    ~OpenVerifyFailureLog();

    // Read XRD_OPENVERIFY_FAILURE_LOG and open when set. Open failures warn on
    // daemon_log and leave the campaign log disabled.
    void Configure(XrdSysError& daemon_log);

    bool Enabled() const;

    void Log(const OpenVerifyFailureRecord& rec);

    // Pure helpers (unit-tested).
    static std::string EscapeValue(const std::string& value);
    static std::string FormatRecord(const OpenVerifyFailureRecord& rec);
    // Credential-free PFN for cmsd redirects: root://host:port//path or https://host:port/path.
    static std::string SynthesizePfn(const std::string& protocol, const std::string& host, int port,
                                     const std::string& path);
    // Drop ?query (opaque/token/cert CGI) from an XrdCl open URL for safe logging.
    static std::string StripUrlQuery(const std::string& url);
    // Path after authority (keeps leading '/' or '//'); empty if URL has no path.
    static std::string PathFromUrl(const std::string& url);

   private:
    static std::string FormatTimestamp();

    mutable std::mutex m_mtx;
    std::string m_path;
    FILE* m_fp{nullptr};
};
