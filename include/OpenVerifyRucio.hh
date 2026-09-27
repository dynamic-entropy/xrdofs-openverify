#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "XrdSys/XrdSysError.hh"

#include "OpenVerifyRucioCurlPool.hh"

class OpenVerifyRucioSelector;

// Feature-flagged CMS Rucio replica lookup for OpenVerify.
//
// XRD_OPENVERIFY_RUCIO=1               enable Rucio-first locate
// XRD_OPENVERIFY_RUCIO_URL             default https://cms-rucio.cern.ch
// XRD_OPENVERIFY_RUCIO_AUTH_URL        default https://cms-rucio-auth.cern.ch
// XRD_OPENVERIFY_RUCIO_ACCOUNT         required when enabled
// XRD_OPENVERIFY_RUCIO_TIMEOUT         HTTP timeout seconds (default 10)
// XRD_OPENVERIFY_RUCIO_SELECT          try-order: rucio (default) | random | priority | geoip
// XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX   comma-separated LFN prefixes to skip (no list_replicas);
//                                      fall through to cmsd *with verify still on*. CMS user
//                                      files are not in Rucio: /store/user,/tmp
//                                      Distinct from XRD_OPENVERIFY_SKIP_PREFIX (File/Metrics):
//                                      that skips Rucio *and* the verify probe.
// XRD_OPENVERIFY_RUCIO_CACHE_TTL       list_replicas LRU TTL seconds (default 60; 0 disables)
// XRD_OPENVERIFY_RUCIO_CACHE_SIZE      max (lfn, scheme) entries (default 8192; 0 disables)
// XRD_OPENVERIFY_RUCIO_POOL_MIN        warm libcurl easy handles (default 1; raise via puppet)
// XRD_OPENVERIFY_RUCIO_POOL_MAX        cap; pool grows/shrinks in [min,max] (default 500)
// XRD_OPENVERIFY_RUCIO_POOL_SIZE       optional alias for POOL_MIN
// X509_USER_PROXY                      proxy for /auth/x509_proxy
//
struct OpenVerifyRucioCandidate {
    std::string host;
    int port{-1};
    std::string pfn;
    std::string rse;
    std::string type;  // Rucio PFN type when present (DISK / TAPE)
    int priority{0};
};

enum class OpenVerifyRucioLookupResult {
    Ok = 0,
    Empty,
    AuthError,
    Timeout,
    Error,
    Disabled,
    Skipped,  // LFN matched XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX; no REST call
};

struct OpenVerifyRucioListResult {
    OpenVerifyRucioLookupResult status{OpenVerifyRucioLookupResult::Disabled};
    std::vector<OpenVerifyRucioCandidate> candidates;
    bool from_cache{false};
    std::string skip_reason;  // matched ignore prefix when status==Skipped
};

class OpenVerifyRucioListCache;
class OpenVerifyMetrics;

// Testable helpers (no network).
std::string OpenVerifyRucioSchemeFromProt(const char* prot);
// Map client/wire aliases to the Rucio protocol id: http/https → davs, xroot → root.
// Rucio does not understand scheme "http"; CMS HTTP replicas are registered as davs.
std::string OpenVerifyRucioNormalizeScheme(const std::string& scheme);
bool OpenVerifyRucioParsePfn(const std::string& pfn, std::string& host, int& port);
// True for tape RSEs: PFN type TAPE (case-insensitive) or RSE name ending in _Tape.
// Tape PFNs must not be verified or redirected to (often same gateway host as Disk).
bool OpenVerifyRucioIsTapeCandidate(const OpenVerifyRucioCandidate& c);
std::vector<OpenVerifyRucioCandidate> OpenVerifyRucioParseReplicasJson(const std::string& body,
                                                                      const std::string& want_scheme);
// Comma-separated LFN prefixes from XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX.
std::vector<std::string> OpenVerifyRucioParseIgnorePrefixes(const std::string& spec);
// Matching ignore prefix, or empty if the LFN is not skipped. Path-component match after
// collapsing leading slashes: `/store/user` matches `/store/user/a` but not `/store/userdata`.
std::string OpenVerifyRucioMatchedIgnorePrefix(const std::string& lfn, const std::vector<std::string>& prefixes);
bool OpenVerifyRucioShouldIgnoreLfn(const std::string& lfn, const std::vector<std::string>& prefixes);

class OpenVerifyRucio {
   public:
    explicit OpenVerifyRucio(XrdSysError& log);
    ~OpenVerifyRucio();

    OpenVerifyRucio(const OpenVerifyRucio&) = delete;
    OpenVerifyRucio& operator=(const OpenVerifyRucio&) = delete;

    bool Enabled() const { return m_enabled; }

    // Optional Prometheus counters for curl TCP / easy-handle reuse.
    void SetMetrics(OpenVerifyMetrics* metrics) { m_metrics = metrics; }

    // Call after XrdSysError logger is attached.
    void LogConfig();

    // List site-gateway candidates for LFN. Soft-fails (Empty/AuthError/Timeout/Error)
    // and Skipped (ignore-prefix) so the caller can fall back to cmsd.
    OpenVerifyRucioListResult ListReplicas(const std::string& lfn, const std::string& scheme,
                                           const std::string& client_ip);

    std::size_t ListCacheSize() const;
    bool ListCacheEnabled() const;

   private:
    bool EnsureAuthToken(bool force_refresh);
    OpenVerifyRucioListResult DoListReplicas(const std::string& lfn, const std::string& scheme,
                                             const std::string& client_ip, const std::string& token);
    void ApplySelector(OpenVerifyRucioListResult& result, const std::string& client_ip) const;
    // After curl_easy_perform: TCP/handle reuse + pool size snapshot.
    void ObserveCurl(const OpenVerifyRucioCurlPool::Handle& handle);

    XrdSysError& m_log;
    OpenVerifyMetrics* m_metrics{nullptr};
    bool m_enabled{false};
    std::string m_rucio_url;
    std::string m_auth_url;
    std::string m_account;
    long m_timeout_s{10};
    std::vector<std::string> m_ignore_prefixes;
    std::unique_ptr<OpenVerifyRucioSelector> m_selector;
    std::unique_ptr<OpenVerifyRucioListCache> m_list_cache;
    std::unique_ptr<OpenVerifyRucioCurlPool> m_curl_pool;

    std::mutex m_token_mtx;
    std::string m_token;
    std::chrono::steady_clock::time_point m_token_expiry{};
};
