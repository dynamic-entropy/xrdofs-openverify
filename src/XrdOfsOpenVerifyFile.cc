#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <random>
#include <string>
#include <unordered_set>
#include <vector>

#include "OpenVerifyCacheKey.hh"
#include "OpenVerifyStaticFallback.hh"
#include "OpenVerifyTimeout.hh"
#include "OpenVerifyUrl.hh"
#include "XrdOfsOpenVerify.hh"
#include "XrdSfs/XrdSfsInterface.hh"

namespace {

// Redirect targets may use IPv6 loopback ("[::1]"); XrdCl rejects root://[::1]:port/... ("Invalid address").
// Later will fix in upstream xrootd later
std::string NormalizeHostForXrdCl(const std::string& host) {
    if (host == "[::1]" || host == "::1") {
        return "127.0.0.1";
    }
    return host;
}

// Parse client/plugin `tried=` CGI (comma-separated host or host:port entries).
std::unordered_set<std::string> ParseTriedHosts(const char* opaque) {
    std::unordered_set<std::string> out;
    if (!opaque || !*opaque) return out;

    std::string s = opaque;
    if (!s.empty() && s.front() == '?') s.erase(s.begin());

    const size_t pos = s.find("tried=");
    if (pos == std::string::npos) return out;
    size_t start = pos + 6;
    size_t end = s.find('&', start);
    if (end == std::string::npos) end = s.size();
    const std::string list = s.substr(start, end - start);

    size_t i = 0;
    while (i < list.size()) {
        size_t j = list.find(',', i);
        if (j == std::string::npos) j = list.size();
        std::string entry = list.substr(i, j - i);
        // trim whitespace
        while (!entry.empty() && (entry.front() == ' ' || entry.front() == '\t')) entry.erase(entry.begin());
        while (!entry.empty() && (entry.back() == ' ' || entry.back() == '\t')) entry.pop_back();
        if (!entry.empty()) out.insert(std::move(entry));
        i = j + 1;
    }
    return out;
}

// True if host or host:port appears in the client's tried= list.
bool IsInTriedList(const std::unordered_set<std::string>& tried, const std::string& host, int port) {
    if (tried.empty() || host.empty()) return false;
    if (tried.count(host)) return true;
    if (port >= 0) {
        const std::string hostPort = host + ":" + std::to_string(port);
        if (tried.count(hostPort)) return true;
    }
    return false;
}

bool ShouldBypassOpenVerify(const XrdSfsFileOpenMode openMode) {
    constexpr int kAccessModeMask = 0x3;
    const int accessMode = (openMode & kAccessModeMask);
    const bool writeAccess = (accessMode == SFS_O_WRONLY || accessMode == SFS_O_RDWR);
    const bool createOrTruncate = (openMode & SFS_O_CREAT) || (openMode & SFS_O_CREATAT) || (openMode & SFS_O_TRUNC);
    return writeAccess || createOrTruncate;
}

// Returns base_s ± (fraction * base_s)
std::chrono::seconds JitteredNegativeTTL(int base_s, float fraction = 0.2f) {
    static thread_local std::mt19937 rng{std::random_device{}()};
    const int delta = static_cast<int>(base_s * fraction);
    std::uniform_int_distribution<int> dist(-delta, +delta);
    return std::chrono::seconds(base_s + dist(rng));
}

bool IsQueueCapacityReject(const XrdCl::XRootDStatus& st) {
    const std::string& e = st.GetErrorMessage();
    return e == "openverify_queue_timeout" || e == "openverify_queue_full";
}

bool IsHostInflightBusy(const XrdCl::XRootDStatus& st) {
    return st.GetErrorMessage() == "openverify_host_busy";
}

// One extra FIFO wait on global queue_timeout / queue_full so a slow generation of
// probes can free a slot. Does not requeue host_busy (that site is at its cap).
XrdCl::XRootDStatus RunWithQueueRequeue(OpenVerifySingleFlight& sf, const std::string& key, const std::string& host,
                                        int port, const std::function<XrdCl::XRootDStatus()>& fn) {
    auto st = sf.Run(key, host, port, fn);
    if (IsQueueCapacityReject(st)) {
        st = sf.Run(key, host, port, fn);
    }
    return st;
}

void FinishVerifyHop(OpenVerifyMetrics::RedirectTimer& hop, const XrdCl::XRootDStatus& st) {
    const std::string& err = st.GetErrorMessage();
    if (err == "openverify_queue_timeout") {
        hop.QueueRejected("queue_timeout");
    } else if (err == "openverify_queue_full") {
        hop.QueueRejected("queue_full");
    } else if (err == "openverify_host_busy") {
        hop.Avoided("host_busy");
    } else {
        hop.VerifyFinished(st.IsOK());
    }
}

// Rewrite SFS_REDIRECT ErrInfo to the verified data server when known.
// cmsd path only — do not use for Rucio gateway redirects (EOS FST lacks MGM opaque).
void MaybeRewriteRedirectToFinalServer(XrdOucErrInfo& err, bool enabled, const std::string& final_host, int final_port,
                                       XrdSysError& log) {
    if (!enabled || final_host.empty() || final_port < 0) {
        return;
    }
    err.setErrInfo(final_port, final_host.c_str());
    const std::string msg = final_host + ":" + std::to_string(final_port);
    log.Emsg(" INFO", "direct-server rewrite redirect to", msg.c_str());
}

bool ClientIsHttp(const XrdSecEntity* client) {
    return client && client->prot[0] &&
           (std::strcmp(client->prot, "http") == 0 || std::strcmp(client->prot, "https") == 0);
}

// Apply Rucio gateway redirect: both dialects get a full URL with the catalog PFN path
// (SFS port -1), so neither XrdCl nor XrdHttp re-appends the original resource path.
void ApplyRucioRedirect(XrdOucErrInfo& err, const XrdSecEntity* client, const std::string& host, int port,
                        const std::string& pfn, const std::string& path, XrdSysError& log) {
    const auto target = OpenVerifyUrl::MakeRucioRedirect(ClientIsHttp(client), host, port, pfn, path);
    err.setErrInfo(target.code, target.text.c_str());
    log.Emsg(" INFO", "rucio redirecting to", target.text.c_str());
}

void AppendTriedHost(std::string& tried_hosts, const std::string& hostPort) {
    tried_hosts = tried_hosts.empty() ? hostPort : tried_hosts + "," + hostPort;
}

// Index Rucio PFN hosts for later cmsd-accept compare (bare host + host:port).
void IndexRucioHosts(const std::vector<OpenVerifyRucioCandidate>& candidates,
                     std::unordered_set<std::string>& out) {
    for (const auto& cand : candidates) {
        const std::string host = NormalizeHostForXrdCl(cand.host);
        if (host.empty()) continue;
        out.insert(host);
        if (cand.port >= 0) {
            out.insert(host + ":" + std::to_string(cand.port));
        }
    }
}

std::string JoinRucioHostPorts(const std::vector<OpenVerifyRucioCandidate>& candidates) {
    std::string out;
    for (const auto& cand : candidates) {
        const std::string host = NormalizeHostForXrdCl(cand.host);
        if (host.empty()) continue;
        const std::string hp =
            (cand.port < 0) ? host : (host + ":" + std::to_string(cand.port));
        out = out.empty() ? hp : out + "," + hp;
    }
    return out;
}

// After Rucio exhaust + cmsd accept: overlap = cmsd host was in Rucio list (skipped /
// tried= / quarantine / cmsd ignored tried=); catalog_disagree = cmsd host absent from list.
void RecordCmsdAfterRucioExhaust(OpenVerifyMetrics& metrics, XrdSysError& log, const std::string& path,
                                 const std::string& cmsd_host, int cmsd_port,
                                 const std::unordered_set<std::string>& rucio_hosts, const std::string& rucio_list) {
    // Durable: cmsd openverify succeeded after every Rucio PFN failed/was skipped.
    metrics.RecordRucioExhaustedRecovered();
    // Temporary diagnostic: hostname overlap vs Rucio list (redirector vs direct site).
    const bool overlap = IsInTriedList(rucio_hosts, cmsd_host, cmsd_port);
    const char* result = overlap ? "overlap" : "catalog_disagree";
    metrics.RecordRucioCmsdCompare(result);
    const std::string cmsd_hp =
        (cmsd_port < 0) ? cmsd_host : (cmsd_host + ":" + std::to_string(cmsd_port));
    // One greppable line: LFN + cmsd host that worked + Rucio list that failed.
    const std::string msg = std::string("path=") + path + " cmsd=" + cmsd_hp + " result=" + result + " rucio=[" +
                            rucio_list + "]";
    log.Emsg(" INFO", "openverify cmsd after rucio exhaust:", msg.c_str());
}

std::string MergeTriedOpaque(const char* opaque, const std::string& tried_hosts, bool observe) {
    std::string opaque_str = opaque ? opaque : "";
    if (observe || tried_hosts.empty()) return opaque_str;

    if (opaque_str.empty()) {
        return "tried=" + tried_hosts;
    }
    size_t tried_pos = opaque_str.find("tried=");
    if (tried_pos != std::string::npos) {
        size_t end_pos = opaque_str.find('&', tried_pos);
        if (end_pos == std::string::npos) {
            opaque_str += "," + tried_hosts;
        } else {
            opaque_str.insert(end_pos, "," + tried_hosts);
        }
    } else {
        opaque_str += "&tried=" + tried_hosts;
    }
    return opaque_str;
}

const char* RucioLookupResultLabel(OpenVerifyRucioLookupResult status) {
    switch (status) {
        case OpenVerifyRucioLookupResult::Ok:
            return "ok";
        case OpenVerifyRucioLookupResult::Empty:
            return "empty";
        case OpenVerifyRucioLookupResult::AuthError:
            return "auth_error";
        case OpenVerifyRucioLookupResult::Timeout:
            return "timeout";
        case OpenVerifyRucioLookupResult::Error:
            return "error";
        case OpenVerifyRucioLookupResult::Disabled:
            return "error";
    }
    return "error";
}

std::string StatusReason(const XrdCl::XRootDStatus& st) {
    const std::string& e = st.GetErrorMessage();
    return e.empty() ? "openverify_failure" : e;
}

void AppendHostReason(std::string& notes, const std::string& hostPort, const std::string& reason) {
    if (!notes.empty()) notes += ",";
    notes += hostPort;
    notes += "=";
    notes += reason;
}

// One-line daemon record: grep openverify_fail / reason=operation_expired / path=
void LogOpenVerifyFail(XrdSysError& log, const char* source, const std::string& hostPort, const std::string& reason,
                       const std::string& path, const std::string& stage = {}) {
    std::string msg = std::string("source=") + source + " host=" + hostPort + " reason=" + reason + " path=" + path;
    if (!stage.empty()) {
        msg += " stage=";
        msg += stage;
    }
    log.Emsg(" WARN", "openverify_fail", msg.c_str());
}

}  // namespace

OpenVerifyFile::OpenVerifyFile(std::unique_ptr<XrdSfsFile> wrapF, XrdSysError& log, OpenVerifyCache& cache,
                               OpenVerifyMetrics& metrics, OpenVerifySingleFlight& single_flight,
                               OpenVerifyHostReliability& host_reliability, OpenVerifyRucio& rucio, bool observe,
                               bool direct_server, std::string ov_cert, std::string ov_key)
    : XrdSfsFile(*wrapF),  // share ErrInfo with the wrapped OFS file
      m_wrapped(std::move(wrapF)),
      m_log(log),
      m_cache(cache),
      m_metrics(metrics),
      m_single_flight(single_flight),
      m_host_reliability(host_reliability),
      m_rucio(rucio),
      m_observe(observe),
      m_direct_server(direct_server),
      m_ov_cert(std::move(ov_cert)),
      m_ov_key(std::move(ov_key)) {}

OpenVerifyFile::~OpenVerifyFile() { m_log.Emsg(" INFO", "FileWrapper::~FileWrapper"); }

int OpenVerifyFile::open(const char* fileName, XrdSfsFileOpenMode openMode, mode_t createMode,
                         const XrdSecEntity* client, const char* opaque) {
    m_log.Emsg(" INFO", "FileWrapper::open");

    // PUT/CREATE-style requests should not go through open-verify.
    if (ShouldBypassOpenVerify(openMode)) {
        m_log.Emsg(" INFO", "Skipping open-verify for write/create open mode");
        return m_wrapped->open(fileName, openMode, createMode, client, opaque);
    }

    int rc = 0;
    std::string tried_hosts;
    int retry_count{0};
    const int max_retries = m_observe ? 1 : OpenVerifyMetrics::kMaxAcceptAttempts;
    bool retry = true;
    bool accepted = false;
    int rucio_sites_tried = 0;
    int cmsd_sites_tried = 0;
    bool accepted_from_rucio = false;
    bool accepted_from_xrootd = false;
    bool after_rucio_exhaust = false;
    std::unordered_set<std::string> rucio_host_index;
    std::string rucio_host_list;
    std::string rucio_errors;  // host:port=reason,... for the exhaust line
    const std::string pathStr = fileName ? fileName : "";
    // Client-supplied tried= (and any prior plugin injections on retries).
    const auto client_tried = ParseTriedHosts(opaque);

    // --- Rucio-first locate (feature-flagged) ---------------------------------
    if (m_rucio.Enabled() && !pathStr.empty()) {
        const char* prot = (client && client->prot[0]) ? client->prot : "";
        const std::string scheme = OpenVerifyRucioSchemeFromProt(prot);
        const std::string client_ip = (client && client->host) ? client->host : "";

        const auto rucio_t0 = std::chrono::steady_clock::now();
        const auto listed = m_rucio.ListReplicas(pathStr, scheme, client_ip);
        if (listed.status != OpenVerifyRucioLookupResult::Disabled) {
            const double rucio_s =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - rucio_t0).count();
            m_metrics.RecordLocateLatency("rucio", rucio_s);
            m_metrics.RecordRucioLookup(RucioLookupResultLabel(listed.status));
        }
        if (listed.status == OpenVerifyRucioLookupResult::Ok) {
            m_metrics.RecordRucioCandidates(listed.candidates.size());
            IndexRucioHosts(listed.candidates, rucio_host_index);
            rucio_host_list = JoinRucioHostPorts(listed.candidates);
            m_log.Emsg(" INFO", "openverify rucio candidates", std::to_string(listed.candidates.size()).c_str(),
                       rucio_host_list.c_str());

            for (const auto& cand : listed.candidates) {
                // Observe: single candidate only. Enforce: walk every Rucio PFN (no 3-cap).
                if (m_observe && rucio_sites_tried >= 1) break;

                std::string hostStr = NormalizeHostForXrdCl(cand.host);
                const int portVal = cand.port;
                const std::string hostPort =
                    (portVal < 0) ? hostStr : (hostStr + ":" + std::to_string(portVal));

                // Honour client tried= (bare host or host:port) before counting an attempt.
                if (IsInTriedList(client_tried, hostStr, portVal)) {
                    m_log.Emsg(" INFO", "skipping rucio host in client tried=:", hostPort.c_str());
                    AppendTriedHost(tried_hosts, hostPort);
                    AppendHostReason(rucio_errors, hostPort, "tried");
                    continue;
                }

                // Open/verify and redirect with the catalog PFN path (may include a site
                // prefix such as /dcache/uscmsdisk/store/...), not the client LFN. Disk
                // doors often require that prefix; redirectors typically accept the LFN
                // alone.
                std::string verify_path = pathStr;
                if (!cand.pfn.empty()) {
                    const std::string pfn_path = OpenVerifyUrl::PathFromUrl(cand.pfn);
                    if (!pfn_path.empty()) verify_path = pfn_path;
                }

                ApplyRucioRedirect(error, client, hostStr, portVal, cand.pfn, verify_path, m_log);
                rc = SFS_REDIRECT;
                ++rucio_sites_tried;
                OpenVerifyMetrics::RedirectTimer hop(m_metrics);

                if (!m_observe && m_host_reliability.AvoidSite(hostStr, portVal)) {
                    AppendTriedHost(tried_hosts, hostPort);
                    hop.Avoided("quarantine");
                    AppendHostReason(rucio_errors, hostPort, "quarantine");
                    m_log.Emsg(" WARN", "skipping unhealthy rucio host:", hostPort.c_str());
                    continue;
                }
                const auto key = MakeOpenVerifyCacheKey(verify_path, hostStr, portVal);
                const auto cached = m_cache.Get(key);
                // Opaque is only for bearer extraction inside open_verify — never put on the
                // probe URL (Rucio verifies a concrete PFN; client tried=/gsiusrpxy must not apply).

                switch (cached.status) {
                    case OpenVerifyCache::Status::Miss: {
                        m_metrics.RecordCacheMiss();
                        m_log.Emsg(" INFO", "openverify cache miss for", key.c_str());
                        std::string last_fail_stage;
                        const auto verify_result = RunWithQueueRequeue(m_single_flight, key, hostStr, portVal, [&]() {
                            std::string final_host;
                            int final_port = -1;
                            std::string fail_stage;
                            const auto st =
                                open_verify(key, opaque, client, OpenVerifyTimeoutSeconds(), &final_host,
                                            &final_port, &fail_stage);
                            if (st.IsOK()) {
                                m_metrics.RecordVerifySuccess();
                                m_host_reliability.RecordVerifySuccess(hostStr, portVal);
                                // Store DS for metrics/cache completeness; do not rewrite Rucio redirect to it.
                                m_cache.PutPositive(key, std::chrono::seconds(120), std::move(final_host), final_port);
                            } else {
                                last_fail_stage = fail_stage;
                                const std::string failure_reason = st.GetErrorMessage().empty()
                                                                       ? "openverify_failure"
                                                                       : st.GetErrorMessage();
                                m_metrics.RecordVerifyFailure("rucio", hostStr, portVal, failure_reason);
                                m_host_reliability.RecordVerifyFailure(hostStr, portVal, st.code);
                                m_cache.PutNegative(key, JitteredNegativeTTL(15));
                            }
                            return st;
                        });

                        FinishVerifyHop(hop, verify_result);
                        if (verify_result.IsOK()) {
                            accepted = true;
                            accepted_from_rucio = true;
                            // Keep Rucio gateway redirect already in error (no DIRECT_SERVER rewrite).
                            m_log.Emsg(" INFO", "openverify succeeded (rucio) for", key.c_str());
                        } else if (IsQueueCapacityReject(verify_result)) {
                            // Global FIFO congestion: do not tried= / EWMA / negative-cache this site.
                            // Pass through the current Rucio redirect; attempt index stays this replica.
                            accepted = true;
                            accepted_from_rucio = true;
                            m_log.Emsg(" INFO", "openverify queue congested after requeue; passing through (rucio)",
                                       key.c_str());
                        } else if (IsHostInflightBusy(verify_result)) {
                            AppendTriedHost(tried_hosts, hostPort);
                            AppendHostReason(rucio_errors, hostPort, "host_busy");
                            m_log.Emsg(" WARN", "openverify host inflight cap; skipping (rucio)", key.c_str());
                        } else {
                            AppendTriedHost(tried_hosts, hostPort);
                            const std::string reason = StatusReason(verify_result);
                            AppendHostReason(rucio_errors, hostPort, reason);
                            LogOpenVerifyFail(m_log, "rucio", hostPort, reason, pathStr, last_fail_stage);
                        }
                        break;
                    }
                    case OpenVerifyCache::Status::Positive:
                        hop.CacheHitPositive();
                        accepted = true;
                        accepted_from_rucio = true;
                        m_log.Emsg(" INFO", "openverify succeeded (rucio cached) for", key.c_str());
                        break;
                    case OpenVerifyCache::Status::Negative:
                        hop.CacheHitNegative(/*count_as_avoided=*/!m_observe);
                        AppendTriedHost(tried_hosts, hostPort);
                        AppendHostReason(rucio_errors, hostPort, "negative_cache");
                        LogOpenVerifyFail(m_log, "rucio", hostPort, "negative_cache", pathStr);
                        break;
                }

                if (accepted) break;
            }
            // PFNs were returned but none accepted (verify fail / cache-neg / quarantine / tried=).
            if (!accepted) {
                after_rucio_exhaust = true;
                m_metrics.RecordRucioExhausted();
                std::string msg = std::string("path=") + pathStr + " rucio=[" + rucio_host_list + "]";
                if (!rucio_errors.empty()) {
                    msg += " errors=";
                    msg += rucio_errors;
                }
                m_log.Emsg(" INFO", "openverify rucio_exhausted", msg.c_str());
            }
        } else if (listed.status != OpenVerifyRucioLookupResult::Disabled) {
            const char* label = RucioLookupResultLabel(listed.status);
            const std::string msg = std::string("result=") + label + " path=" + pathStr;
            if (listed.status == OpenVerifyRucioLookupResult::Empty) {
                m_log.Emsg(" INFO", "openverify rucio_empty", msg.c_str());
            } else {
                m_log.Emsg(" INFO", "openverify rucio_lookup", msg.c_str());
            }
        }
    }

    // --- cmsd fallback (base OFS) ---------------------------------------------
    // Fresh attempt budget for cmsd (Rucio failures still feed tried=).
    if (!accepted) {
        retry_count = 0;
        cmsd_sites_tried = 0;
        retry = true;
    } else {
        retry = false;
    }

    while (retry && retry_count < max_retries) {
        // if max_retries exhausts and open_verify fail on all of them
        // currently we return the last redirect, thus only performing a best effort verify
        // another approach is we change this and return SFS_ERROR instead

        // cmsd locate needs tried= (client + failed Rucio/cmsd hops) to return the next site.
        std::string opaque_str = MergeTriedOpaque(opaque, tried_hosts, m_observe);

        m_log.Emsg("INFO", "Retrying with opaque = ", opaque_str.c_str());

        const auto cmsd_t0 = std::chrono::steady_clock::now();
        rc = m_wrapped->open(fileName, openMode, createMode, client, opaque_str.c_str());
        {
            const double cmsd_s =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - cmsd_t0).count();
            m_metrics.RecordLocateLatency("cmsd", cmsd_s);
        }
        m_log.Emsg("INFO", "returned from open with rc =", std::to_string(rc).c_str(), "\n");

        // SFS_STALL: pass through to the protocol layer (kXR_wait for root; Bridge
        // redrive for HTTP). Do not sleep here — that holds an open worker for the
        // stall duration and prevents the client/bridge from owning the delay.
        if (rc > 0) {
            m_metrics.RecordCmsdStall(rc);
            m_log.Emsg("INFO", "cmsd stall; returning to client for", std::to_string(rc).c_str(), "sec");
            return rc;
        }
        retry_count++;

        if (rc != SFS_REDIRECT) break;

        OpenVerifyMetrics::RedirectTimer hop(m_metrics);

        int port;
        const char* host = m_wrapped->error.getErrText(port);
        std::string hostStr = host ? host : "";
        hostStr = NormalizeHostForXrdCl(hostStr);
        const int portVal = (port >= 0) ? port : -1;

        const std::string hostPort = (port < 0) ? hostStr : (hostStr + ":" + std::to_string(port));
        m_log.Emsg(" INFO", "redirecting to", hostPort.c_str());

        // Static xrootd.redirect ENOENT fallback (cms-xrd-transit) — not a site gateway.
        // Pass through without verify, quarantine, or cache; label as source=xrootd.
        if (IsStaticXrootdFallbackHost(hostStr)) {
            hop.Passthrough();
            accepted = true;
            accepted_from_xrootd = true;
            retry = false;
            m_log.Emsg(" INFO", "openverify passthrough static xrootd fallback", hostPort.c_str());
            break;
        }

        ++cmsd_sites_tried;

        // Decide if the host should be added to the tried list
        // based on past error patterns
        if (!m_observe && m_host_reliability.AvoidSite(hostStr, portVal)) {
            AppendTriedHost(tried_hosts, hostPort);
            hop.Avoided("quarantine");
            m_log.Emsg(" WARN", "skipping unhealthy host:", hostPort.c_str());
            continue;
        }

        const auto key = MakeOpenVerifyCacheKey(pathStr, hostStr, portVal);
        const auto cached = m_cache.Get(key);

        // Verify probe: opaque only for bearer extraction (not forwarded onto the URL).
        // tried= already did its job on m_wrapped->open above.
        const char* verify_opaque = opaque;

        switch (cached.status) {
            case OpenVerifyCache::Status::Miss: {
                m_metrics.RecordCacheMiss();
                m_log.Emsg(" INFO", "openverify cache miss for", key.c_str());
                std::string last_fail_stage;
                const auto verify_result =
                    RunWithQueueRequeue(m_single_flight, key, hostStr, portVal, [&]() {
                    std::string final_host;
                    int final_port = -1;
                    std::string fail_stage;
                    const auto st =
                        open_verify(key, verify_opaque, client, OpenVerifyTimeoutSeconds(), &final_host, &final_port,
                                    &fail_stage);
                    if (st.IsOK()) {
                        m_metrics.RecordVerifySuccess();
                        m_host_reliability.RecordVerifySuccess(hostStr, portVal);
                        m_cache.PutPositive(key, std::chrono::seconds(120), std::move(final_host), final_port);
                    } else {
                        last_fail_stage = fail_stage;
                        const std::string failure_reason = st.GetErrorMessage().empty() ? "openverify_failure"
                                                                                         : st.GetErrorMessage();
                        m_metrics.RecordVerifyFailure("cmsd", hostStr, portVal, failure_reason);
                        m_host_reliability.RecordVerifyFailure(hostStr, portVal, st.code);
                        m_cache.PutNegative(key, JitteredNegativeTTL(15));
                    }
                    return st;
                });

                FinishVerifyHop(hop, verify_result);
                if (verify_result.IsOK()) {
                    accepted = true;
                    accepted_from_rucio = false;
                    retry = false;
                    m_log.Emsg(" INFO", "openverify succeeded for", key.c_str());
                    if (after_rucio_exhaust) {
                        RecordCmsdAfterRucioExhaust(m_metrics, m_log, pathStr, hostStr, portVal, rucio_host_index,
                                                    rucio_host_list);
                    }
                    // Leader and followers both read the DS from cache after put.
                    if (m_direct_server) {
                        const auto after = m_cache.Get(key);
                        MaybeRewriteRedirectToFinalServer(error, true, after.final_host, after.final_port, m_log);
                    }
                } else if (IsQueueCapacityReject(verify_result)) {
                    // Global FIFO congestion: do not tried= / EWMA this site. Pass through
                    // the current cmsd redirect; accepted attempt stays this cmsd hop.
                    accepted = true;
                    accepted_from_rucio = false;
                    retry = false;
                    m_log.Emsg(" INFO", "openverify queue congested after requeue; passing through", key.c_str());
                } else if (IsHostInflightBusy(verify_result)) {
                    AppendTriedHost(tried_hosts, hostPort);
                    m_log.Emsg(" WARN", "openverify host inflight cap; skipping", key.c_str());
                } else {
                    AppendTriedHost(tried_hosts, hostPort);
                    LogOpenVerifyFail(m_log, "cmsd", hostPort, StatusReason(verify_result), pathStr, last_fail_stage);
                }
                break;
            }
            case OpenVerifyCache::Status::Positive:
                hop.CacheHitPositive();
                accepted = true;
                accepted_from_rucio = false;
                m_log.Emsg(" INFO", "openverify succeeded (cached) for", key.c_str());
                if (after_rucio_exhaust) {
                    RecordCmsdAfterRucioExhaust(m_metrics, m_log, pathStr, hostStr, portVal, rucio_host_index,
                                                rucio_host_list);
                }
                MaybeRewriteRedirectToFinalServer(error, m_direct_server, cached.final_host, cached.final_port, m_log);
                retry = false;
                break;
            case OpenVerifyCache::Status::Negative:
                hop.CacheHitNegative(/*count_as_avoided=*/!m_observe);
                AppendTriedHost(tried_hosts, hostPort);
                LogOpenVerifyFail(m_log, "cmsd", hostPort, "negative_cache", pathStr);
                break;
        }
    }

    if (accepted) {
        const char* source =
            accepted_from_rucio ? "rucio" : (accepted_from_xrootd ? "xrootd" : "cmsd");
        const int attempt =
            accepted_from_rucio ? rucio_sites_tried : (accepted_from_xrootd ? 1 : cmsd_sites_tried);
        m_metrics.RecordOpenAccepted(attempt, source);
        m_metrics.RecordLocationSource(source);
        if (accepted_from_xrootd) {
            m_metrics.RecordStaticFallback("transit");
        }
        if (accepted_from_rucio) {
            rc = SFS_REDIRECT;
        }
    } else if (!m_observe && rc == SFS_REDIRECT && retry_count >= max_retries) {
        // Enforce only: the retry budget was fully spent with no accept.
        // Observe uses max_retries=1 and must not record exhausted — that would
        // just mean "first candidate failed verify" while still returning it.
        m_metrics.RecordOpenRetryExhausted();
    }

    return rc;
}

int OpenVerifyFile::close() {
    m_log.Emsg(" INFO", "FileWrapper::close");
    return m_wrapped->close();
}

int OpenVerifyFile::checkpoint(cpAct act, struct iov* range, int n) {
    m_log.Emsg(" INFO", "FileWrapper::checkpoint");
    return m_wrapped->checkpoint(act, range, n);
}

int OpenVerifyFile::fctl(const int cmd, const char* args, XrdOucErrInfo& out_error) {
    m_log.Emsg(" INFO", "FileWrapper::fctl");
    return m_wrapped->fctl(cmd, args, out_error);
}

const char* OpenVerifyFile::FName() {
    m_log.Emsg(" INFO", "FileWrapper::FName");
    return m_wrapped->FName();
}

int OpenVerifyFile::getMmap(void** Addr, off_t& Size) {
    m_log.Emsg(" INFO", "FileWrapper::getMmap");
    return m_wrapped->getMmap(Addr, Size);
}

XrdSfsXferSize OpenVerifyFile::pgRead(XrdSfsFileOffset offset, char* buffer, XrdSfsXferSize rdlen, uint32_t* csvec,
                                      uint64_t opts) {
    m_log.Emsg(" INFO", "FileWrapper::pgRead(offset, buffer)");
    return m_wrapped->pgRead(offset, buffer, rdlen, csvec, opts);
}

XrdSfsXferSize OpenVerifyFile::pgRead(XrdSfsAio* aioparm, uint64_t opts) {
    m_log.Emsg(" INFO", "FileWrapper::pgRead(aioparm)");
    return m_wrapped->pgRead(aioparm, opts);
}

XrdSfsXferSize OpenVerifyFile::pgWrite(XrdSfsFileOffset offset, char* buffer, XrdSfsXferSize rdlen, uint32_t* csvec,
                                       uint64_t opts) {
    m_log.Emsg(" INFO", "FileWrapper::pgWrite(offset, buffer)");
    return m_wrapped->pgWrite(offset, buffer, rdlen, csvec, opts);
}

XrdSfsXferSize OpenVerifyFile::pgWrite(XrdSfsAio* aioparm, uint64_t opts) {
    m_log.Emsg(" INFO", "FileWrapper::pgWrite(aioparm)");
    return m_wrapped->pgWrite(aioparm, opts);
}

int OpenVerifyFile::read(XrdSfsFileOffset fileOffset, XrdSfsXferSize amount) {
    m_log.Emsg(" INFO", "FileWrapper::read(offset, amount)");
    return m_wrapped->read(fileOffset, amount);
}

XrdSfsXferSize OpenVerifyFile::read(XrdSfsFileOffset fileOffset, char* buffer, XrdSfsXferSize buffer_size) {
    m_log.Emsg(" INFO", "FileWrapper::read(offset, buffer)");
    return m_wrapped->read(fileOffset, buffer, buffer_size);
}

int OpenVerifyFile::read(XrdSfsAio* aioparm) {
    m_log.Emsg(" INFO", "FileWrapper::read(aioparm)");
    return m_wrapped->read(aioparm);
}

XrdSfsXferSize OpenVerifyFile::write(XrdSfsFileOffset fileOffset, const char* buffer, XrdSfsXferSize buffer_size) {
    m_log.Emsg(" INFO", "FileWrapper::write(offset, buffer)");
    return m_wrapped->write(fileOffset, buffer, buffer_size);
}

int OpenVerifyFile::write(XrdSfsAio* aioparm) {
    m_log.Emsg(" INFO", "FileWrapper::write(aioparm)");
    return m_wrapped->write(aioparm);
}

int OpenVerifyFile::sync() {
    m_log.Emsg(" INFO", "FileWrapper::sync");
    return m_wrapped->sync();
}

int OpenVerifyFile::sync(XrdSfsAio* aiop) {
    m_log.Emsg(" INFO", "FileWrapper::sync(aiop)");
    return m_wrapped->sync(aiop);
}

int OpenVerifyFile::stat(struct stat* buf) {
    m_log.Emsg(" INFO", "FileWrapper::stat");
    return m_wrapped->stat(buf);
}

int OpenVerifyFile::truncate(XrdSfsFileOffset fileOffset) {
    m_log.Emsg(" INFO", "FileWrapper::truncate");
    return m_wrapped->truncate(fileOffset);
}

int OpenVerifyFile::getCXinfo(char cxtype[4], int& cxrsz) {
    m_log.Emsg(" INFO", "FileWrapper::getCXinfo");
    return m_wrapped->getCXinfo(cxtype, cxrsz);
}

int OpenVerifyFile::SendData(XrdSfsDio* sfDio, XrdSfsFileOffset offset, XrdSfsXferSize size) {
    m_log.Emsg(" INFO", "FileWrapper::SendData");
    return m_wrapped->SendData(sfDio, offset, size);
}
