#pragma once

#include <chrono>
#include <mutex>
#include <string>
#include <vector>

#include "XrdSys/XrdSysError.hh"

// Feature-flagged CMS Rucio replica lookup for OpenVerify.
//
// XRD_OPENVERIFY_RUCIO=1          enable Rucio-first locate
// XRD_OPENVERIFY_RUCIO_URL        default https://cms-rucio.cern.ch
// XRD_OPENVERIFY_RUCIO_AUTH_URL   default https://cms-rucio-auth.cern.ch
// XRD_OPENVERIFY_RUCIO_ACCOUNT    required when enabled
// XRD_OPENVERIFY_RUCIO_TIMEOUT    HTTP timeout seconds (default 10)
// X509_USER_PROXY                 proxy for /auth/x509_proxy
//
struct OpenVerifyRucioCandidate {
    std::string host;
    int port{-1};
    std::string pfn;
    std::string rse;
    int priority{0};
};

enum class OpenVerifyRucioLookupResult {
    Ok = 0,
    Empty,
    AuthError,
    Timeout,
    Error,
    Disabled,
};

struct OpenVerifyRucioListResult {
    OpenVerifyRucioLookupResult status{OpenVerifyRucioLookupResult::Disabled};
    std::vector<OpenVerifyRucioCandidate> candidates;
};

// Testable helpers (no network).
std::string OpenVerifyRucioSchemeFromProt(const char* prot);
bool OpenVerifyRucioParsePfn(const std::string& pfn, std::string& host, int& port);
std::vector<OpenVerifyRucioCandidate> OpenVerifyRucioParseReplicasJson(const std::string& body,
                                                                      const std::string& want_scheme);

class OpenVerifyRucio {
   public:
    explicit OpenVerifyRucio(XrdSysError& log);

    bool Enabled() const { return m_enabled; }

    // Call after XrdSysError logger is attached.
    void LogConfig();

    // List site-gateway candidates for LFN. Soft-fails (Empty/AuthError/Timeout/Error)
    // so the caller can fall back to cmsd.
    OpenVerifyRucioListResult ListReplicas(const std::string& lfn, const std::string& scheme,
                                           const std::string& client_ip);

   private:
    bool EnsureAuthToken(bool force_refresh);
    OpenVerifyRucioListResult DoListReplicas(const std::string& lfn, const std::string& scheme,
                                             const std::string& client_ip, const std::string& token);

    XrdSysError& m_log;
    bool m_enabled{false};
    std::string m_rucio_url;
    std::string m_auth_url;
    std::string m_account;
    long m_timeout_s{10};

    std::mutex m_token_mtx;
    std::string m_token;
    std::chrono::steady_clock::time_point m_token_expiry{};
};
