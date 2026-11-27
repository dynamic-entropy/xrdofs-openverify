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
#include "OpenVerifyTried.hh"
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

bool IsHostInflightBusy(const XrdCl::XRootDStatus& st) { return st.GetErrorMessage() == "openverify_host_busy"; }

bool IsCleartextBearerReject(const XrdCl::XRootDStatus& st) {
    return st.GetErrorMessage() == "openverify_cleartext_bearer";
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
// Leading slashes only. A full-URL path of //store/a matches the inbound /store/a.
bool SameVerifyPath(const std::string& a, const std::string& b) {
    auto strip = [](const std::string& s) {
        size_t i = 0;
        while (i < s.size() && s[i] == '/') ++i;
        return s.substr(i);
    };
    return strip(a) == strip(b);
}

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
    const std::string prot = OpenVerifyClientWireProt(client);
    return prot == "http" || prot == "https";
}

// Apply Rucio gateway redirect: full URL with the catalog PFN path (or LFN fallback).
void ApplyRucioRedirect(XrdOucErrInfo& err, const XrdSecEntity* client, const std::string& host, int port,
                        const std::string& pfn, const std::string& path) {
    const auto target = OpenVerifyUrl::MakeRucioRedirect(ClientIsHttp(client), host, port, pfn, path);
    err.setErrInfo(target.code, target.text.c_str());
}

// Index Rucio PFN hosts for later cmsd-accept compare (bare host + host:port).
void IndexRucioHosts(const std::vector<OpenVerifyRucioCandidate>& candidates, std::unordered_set<std::string>& out) {
    for (const auto& cand : candidates) {
        const std::string host = BracketIpv6Host(NormalizeHostForXrdCl(cand.host));
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
        const std::string shown = BracketIpv6Host(host);
        const std::string hp = (cand.port < 0) ? shown : (shown + ":" + std::to_string(cand.port));
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
    const std::string cmsd_hp = (cmsd_port < 0) ? cmsd_host : (cmsd_host + ":" + std::to_string(cmsd_port));
    // One greppable line: LFN + cmsd host that worked + Rucio list that failed.
    const std::string msg =
        std::string("path=") + path + " cmsd=" + cmsd_hp + " result=" + result + " rucio=[" + rucio_list + "]";
    log.Emsg(" INFO", "openverify cmsd after rucio exhaust:", msg.c_str());
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
        case OpenVerifyRucioLookupResult::Skipped:
            return "skipped";
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

std::string HostPortFromErrInfo(XrdOucErrInfo& err) {
    int port = 0;
    const char* host = err.getErrText(port);
    std::string hostStr = host ? host : "";
    if (hostStr.empty()) return {};
    return (port < 0) ? hostStr : (hostStr + ":" + std::to_string(port));
}

}  // namespace

OpenVerifyFile::OpenVerifyFile(std::unique_ptr<XrdSfsFile> wrapF, XrdSysError& log, OpenVerifyCache& cache,
                               OpenVerifyMetrics& metrics, OpenVerifySingleFlight& single_flight,
                               OpenVerifyHostReliability& host_reliability, OpenVerifyRucio& rucio, bool observe,
                               bool direct_server, std::string ov_cert, std::string ov_key,
                               std::vector<std::string> skip_prefixes)
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
      m_ov_key(std::move(ov_key)),
      m_skip_prefixes(std::move(skip_prefixes)) {}

int OpenVerifyFile::open(const char* fileName, XrdSfsFileOpenMode openMode, mode_t createMode,
                         const XrdSecEntity* client, const char* opaque) {
    // PUT/CREATE-style requests should not go through open-verify.
    if (ShouldBypassOpenVerify(openMode)) {
        m_log.Emsg(" INFO", "openverify skip write/create", fileName ? fileName : "");
        return m_wrapped->open(fileName, openMode, createMode, client, opaque);
    }

    int rc = 0;
    std::string tried_hosts;  // hosts OpenVerify added this open; merged into cgi `tried=`
    int retry_count{0};
    const int max_retries = m_observe ? 1 : OpenVerifyMetrics::kMaxAcceptAttempts;
    bool retry = true;
    bool accepted = false;
    int rucio_sites_tried = 0;
    int cmsd_sites_tried = 0;
    bool accepted_from_rucio = false;
    bool accepted_from_xrootd = false;
    bool accepted_from_skip = false;
    bool after_rucio_exhaust = false;
    std::unordered_set<std::string> rucio_host_index;
    std::string rucio_host_list;
    std::string rucio_errors;  // host:port=reason,... for the exhaust line
    // Sanitize inbound path once to CMS LFN for Rucio list_replicas and cmsd open.
    // Clients that bounce after a PFN redirect (xrootd#2394) otherwise reopen
    // /eos/cms/store/... here and get Rucio http=400. Outbound redirects still use
    // the catalog/cmsd PFN path.
    const std::string pathStr = OpenVerifyUrl::CmsLfnFromPath(fileName ? fileName : "");
    const std::string skip_reason = OpenVerifyRucioMatchedIgnorePrefix(pathStr, m_skip_prefixes);
    const auto client_tried = ParseTriedHosts(opaque);
    const std::string client_tried_cgi = TriedCgiValue(opaque);
    auto appendTriedLog = [&](std::string& msg) {
        if (!client_tried_cgi.empty()) {
            msg += " client_tried=";
            msg += client_tried_cgi;
        }
        if (!tried_hosts.empty()) {
            msg += " ov_tried=";
            msg += tried_hosts;
        }
    };

    // --- Rucio-first locate (feature-flagged) ---------------------------------
    // SKIP_PREFIX: no REST and no verify; cmsd still locates (see skip_prefix hop).
    // Observe: no Rucio either, so the client always gets the unchanged cmsd redirect.
    if (!m_observe && skip_reason.empty() && m_rucio.Enabled() && !pathStr.empty()) {
        const std::string scheme = OpenVerifyRucioSchemeFromProt(OpenVerifyClientWireProt(client).c_str());
        const std::string client_ip = (client && client->host) ? client->host : "";

        const auto rucio_t0 = std::chrono::steady_clock::now();
        const auto listed = m_rucio.ListReplicas(pathStr, scheme, client_ip);
        if (listed.status != OpenVerifyRucioLookupResult::Disabled) {
            if (listed.status != OpenVerifyRucioLookupResult::Skipped) {
                if (m_rucio.ListCacheEnabled()) {
                    if (listed.from_cache) {
                        m_metrics.RecordRucioListCache("hit");
                    } else {
                        m_metrics.RecordRucioListCache("miss");
                    }
                    m_metrics.SetRucioListCacheEntries(m_rucio.ListCacheSize());
                }
                if (!listed.from_cache) {
                    const double rucio_s =
                        std::chrono::duration<double>(std::chrono::steady_clock::now() - rucio_t0).count();
                    m_metrics.RecordLocateLatency("rucio", rucio_s);
                }
            }
            m_metrics.RecordRucioLookup(RucioLookupResultLabel(listed.status), listed.skip_reason);
        }
        if (listed.status == OpenVerifyRucioLookupResult::Ok) {
            m_metrics.RecordRucioCandidates(listed.candidates.size());
            IndexRucioHosts(listed.candidates, rucio_host_index);
            rucio_host_list = JoinRucioHostPorts(listed.candidates);
            // Walk every Rucio PFN (no 3-cap).
            for (const auto& cand : listed.candidates) {
                // One spelling for quarantine, the inflight cap, and tried=.
                // [::1] is rewritten to 127.0.0.1 before brackets are applied.
                std::string hostStr = BracketIpv6Host(NormalizeHostForXrdCl(cand.host));
                const int portVal = cand.port;
                const std::string shownHost = BracketIpv6Host(hostStr);
                const std::string hostPort = (portVal < 0) ? shownHost : (shownHost + ":" + std::to_string(portVal));

                // Honour client tried= (bare host or host:port) before counting an attempt.
                if (IsInTriedList(client_tried, hostStr, portVal)) {
                    m_log.Emsg(" INFO", "openverify skip client_tried", hostPort.c_str(), pathStr.c_str());
                    AppendHostReason(rucio_errors, hostPort, "tried");
                    continue;
                }

                // Verify and redirect with the catalog PFN path (site prefix);
                // `pathStr` is only the sanitized inbound name for Rucio/cmsd.
                std::string verify_path = pathStr;
                if (!cand.pfn.empty()) {
                    const std::string pfn_path = OpenVerifyUrl::PathFromUrl(cand.pfn);
                    if (!pfn_path.empty()) verify_path = pfn_path;
                }

                ApplyRucioRedirect(error, client, hostStr, portVal, cand.pfn, verify_path);
                rc = SFS_REDIRECT;
                ++rucio_sites_tried;
                OpenVerifyMetrics::RedirectTimer hop(m_metrics);

                const auto key = MakeOpenVerifyCacheKey(verify_path, hostStr, portVal);
                const auto cached = m_cache.Get(key);
                // Opaque is only for bearer extraction inside open_verify — never put on the
                // probe URL (Rucio verifies a concrete PFN; client tried=/gsiusrpxy must not apply).

                switch (cached.status) {
                    case OpenVerifyCache::Status::Miss: {
                        // A fresh positive/negative result is cheaper and more specific than
                        // the site EWMA. Quarantine only applies when we would actually probe.
                        if (m_host_reliability.AvoidSite(hostStr, portVal)) {
                            AppendTriedHost(tried_hosts, hostPort);
                            hop.Avoided("quarantine");
                            AppendHostReason(rucio_errors, hostPort, "quarantine");
                            m_log.Emsg(" WARN", "openverify skip quarantine", hostPort.c_str(), pathStr.c_str());
                            break;
                        }
                        m_metrics.RecordCacheMiss();
                        std::string last_fail_stage;
                        const auto verify_result = RunWithQueueRequeue(m_single_flight, key, hostStr, portVal, [&]() {
                            std::string final_host;
                            int final_port = -1;
                            std::string fail_stage;
                            const auto st = open_verify(key, opaque, client, OpenVerifyTimeoutSeconds(), &final_host,
                                                        &final_port, &fail_stage);
                            if (st.IsOK()) {
                                m_metrics.RecordVerifySuccess("rucio", hostStr, portVal);
                                m_host_reliability.RecordVerifySuccess(hostStr, portVal);
                                // Store DS for metrics/cache completeness; do not rewrite Rucio redirect to it.
                                m_cache.PutPositive(key, std::chrono::seconds(120), std::move(final_host), final_port);
                            } else if (IsCleartextBearerReject(st)) {
                                last_fail_stage = fail_stage;
                                m_metrics.RecordVerifyFailure("rucio", hostStr, portVal, "openverify_cleartext_bearer");
                            } else {
                                last_fail_stage = fail_stage;
                                const std::string failure_reason =
                                    st.GetErrorMessage().empty() ? "openverify_failure" : st.GetErrorMessage();
                                m_metrics.RecordVerifyFailure("rucio", hostStr, portVal, failure_reason);
                                if (OpenVerifyFailureAffectsSiteHealth(failure_reason)) {
                                    m_host_reliability.RecordVerifyFailure(hostStr, portVal, st.code);
                                }
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
                        } else if (IsCleartextBearerReject(verify_result)) {
                            accepted = true;
                            accepted_from_rucio = true;
                            m_log.Emsg(" WARN", "openverify refusing cleartext bearer probe; passing through (rucio)",
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
                        hop.CacheHitNegative(/*count_as_avoided=*/true);
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
                appendTriedLog(msg);
                m_log.Emsg(" INFO", "openverify rucio_exhausted", msg.c_str());
            }
        } else if (listed.status != OpenVerifyRucioLookupResult::Disabled) {
            const char* label = RucioLookupResultLabel(listed.status);
            std::string msg = std::string("result=") + label;
            if (listed.status == OpenVerifyRucioLookupResult::Skipped && !listed.skip_reason.empty()) {
                msg += " reason=";
                msg += listed.skip_reason;
            }
            msg += " path=";
            msg += pathStr;
            if (listed.status == OpenVerifyRucioLookupResult::Empty) {
                m_log.Emsg(" INFO", "openverify rucio_empty", msg.c_str());
            } else if (listed.status == OpenVerifyRucioLookupResult::Skipped) {
                m_log.Emsg(" INFO", "openverify rucio_skipped", msg.c_str());
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

        // cmsd locate needs tried= (client CGI + failed Rucio/cmsd hops) to return the next site.
        std::string opaque_str = MergeTriedOpaque(opaque, tried_hosts, m_observe);

        if (retry_count > 0) {
            std::string msg = std::string("path=") + pathStr;
            appendTriedLog(msg);
            m_log.Emsg(" INFO", "openverify cmsd retry", msg.c_str());
        }

        rc = m_wrapped->open(pathStr.c_str(), openMode, createMode, client, opaque_str.c_str());

        // SFS_STALL: pass through to the protocol layer (kXR_wait for root; Bridge
        // redrive for HTTP). Do not sleep here — that holds an open worker for the
        // stall duration and prevents the client/bridge from owning the delay.
        if (rc > 0) {
            m_metrics.RecordCmsdStall(rc);
            const std::string msg = std::string("path=") + pathStr + " sec=" + std::to_string(rc);
            m_log.Emsg(" INFO", "openverify cmsd stall", msg.c_str());
            return rc;
        }
        retry_count++;

        if (rc != SFS_REDIRECT) {
            if (rc == SFS_ERROR) {
                int ecode = 0;
                const char* etxt = m_wrapped->error.getErrText(ecode);
                std::string msg = std::string("path=") + pathStr + " ecode=" + std::to_string(ecode);
                if (etxt && *etxt) {
                    msg += " msg=";
                    msg += etxt;
                }
                m_log.Emsg(" WARN", "openverify cmsd_error", msg.c_str());
            } else if (rc != SFS_OK) {
                const std::string msg = std::string("path=") + pathStr + " rc=" + std::to_string(rc);
                m_log.Emsg(" INFO", "openverify cmsd returned", msg.c_str());
            }
            break;
        }

        OpenVerifyMetrics::RedirectTimer hop(m_metrics);

        int port;
        const char* host = m_wrapped->error.getErrText(port);
        std::string hostStr = host ? host : "";
        hostStr = NormalizeHostForXrdCl(hostStr);
        int portVal = (port >= 0) ? port : -1;

        std::string hostPort =
            (port < 0) ? BracketIpv6Host(hostStr) : (BracketIpv6Host(hostStr) + ":" + std::to_string(port));

        // Configured skip: cmsd located a next hop; do not verify-open it from here.
        // SAM AAA `/store/test/xrootd/<SITE>/...` is a TFC pin, not a DID — probing
        // the regional with the global host cert hammers the federation (see README).
        if (!skip_reason.empty()) {
            hop.Passthrough();
            accepted = true;
            accepted_from_skip = true;
            retry = false;
            m_metrics.RecordSkipPrefix(skip_reason);
            std::string msg = std::string("reason=") + skip_reason + " host=" + hostPort + " path=" + pathStr;
            m_log.Emsg(" INFO", "openverify skip_prefix", msg.c_str());
            break;
        }

        // Static xrootd.redirect ENOENT fallback (cms-xrd-transit) — not a site gateway.
        // Pass through without verify, quarantine, or cache; label as source=xrootd.
        if (IsStaticXrootdFallbackHost(hostStr)) {
            hop.Passthrough();
            accepted = true;
            accepted_from_xrootd = true;
            retry = false;
            m_log.Emsg(" INFO", "openverify passthrough static xrootd fallback", hostPort.c_str(), pathStr.c_str());
            break;
        }

        ++cmsd_sites_tried;

        std::string verify_path = pathStr;
        std::string redirect_scheme;
        if (port < 0 && hostStr.find("://") != std::string::npos) {
            // Full-URL redirect: the client will open that URL, including its
            // scheme and path. Probe that endpoint. An unparseable URL is passed
            // through rather than turned into root://root://...
            const auto parts = OpenVerifyUrl::DescribeRedirect(hostStr, port);
            if (parts.host.empty()) {
                hop.Passthrough();
                accepted = true;
                retry = false;
                m_log.Emsg(" WARN", "openverify unparsed redirect", hostPort.c_str(), pathStr.c_str());
                break;
            }
            hostStr = NormalizeHostForXrdCl(parts.host);
            portVal = parts.port;
            redirect_scheme = parts.scheme;
            // No path in the URL means the client opens "/". Do not keep the inbound LFN.
            verify_path = OpenVerifyUrl::VerifyPathForRedirect(pathStr, parts, true);
        }
        hostStr = BracketIpv6Host(hostStr);
        hostPort = (portVal < 0) ? hostStr : (hostStr + ":" + std::to_string(portVal));

        const auto key = MakeOpenVerifyCacheKey(verify_path, hostStr, portVal, redirect_scheme);
        // Host-only direct-server rewrite drops the URL path. Skip it when the
        // client would then open a different path from the one we probed.
        const bool direct_same_path = m_direct_server && SameVerifyPath(pathStr, verify_path);
        const auto cached = m_cache.Get(key);

        // Verify probe: opaque only for bearer extraction (not forwarded onto the URL).
        // tried= already did its job on m_wrapped->open above.
        const char* verify_opaque = opaque;

        switch (cached.status) {
            case OpenVerifyCache::Status::Miss: {
                if (!m_observe && m_host_reliability.AvoidSite(hostStr, portVal)) {
                    AppendTriedHost(tried_hosts, hostPort);
                    hop.Avoided("quarantine");
                    m_log.Emsg(" WARN", "openverify skip quarantine", hostPort.c_str(), pathStr.c_str());
                    break;
                }
                m_metrics.RecordCacheMiss();
                std::string last_fail_stage;
                const auto verify_result = RunWithQueueRequeue(m_single_flight, key, hostStr, portVal, [&]() {
                    std::string final_host;
                    int final_port = -1;
                    std::string fail_stage;
                    const auto st = open_verify(key, verify_opaque, client, OpenVerifyTimeoutSeconds(), &final_host,
                                                &final_port, &fail_stage);
                    if (st.IsOK()) {
                        m_metrics.RecordVerifySuccess("cmsd", hostStr, portVal);
                        m_host_reliability.RecordVerifySuccess(hostStr, portVal);
                        m_cache.PutPositive(key, std::chrono::seconds(120), std::move(final_host), final_port);
                    } else {
                        last_fail_stage = fail_stage;
                        const std::string failure_reason =
                            st.GetErrorMessage().empty() ? "openverify_failure" : st.GetErrorMessage();
                        m_metrics.RecordVerifyFailure("cmsd", hostStr, portVal, failure_reason);
                        if (OpenVerifyFailureAffectsSiteHealth(failure_reason)) {
                            m_host_reliability.RecordVerifyFailure(hostStr, portVal, st.code);
                        }
                        // A refused cleartext probe was not a result for this URL.
                        if (failure_reason != "openverify_cleartext_bearer") {
                            m_cache.PutNegative(key, JitteredNegativeTTL(15));
                        }
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
                    if (direct_same_path) {
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
                } else if (IsCleartextBearerReject(verify_result)) {
                    accepted = true;
                    accepted_from_rucio = false;
                    retry = false;
                    m_log.Emsg(" WARN", "openverify refusing cleartext bearer probe; passing through", key.c_str());
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
                MaybeRewriteRedirectToFinalServer(error, direct_same_path, cached.final_host, cached.final_port, m_log);
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
        const char* source = accepted_from_rucio     ? "rucio"
                             : accepted_from_xrootd  ? "xrootd"
                             : accepted_from_skip    ? "skip"
                                                     : "cmsd";
        const int attempt = accepted_from_rucio                              ? rucio_sites_tried
                            : (accepted_from_xrootd || accepted_from_skip)   ? 1
                                                                             : cmsd_sites_tried;
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
        std::string msg = std::string("path=") + pathStr + " last=" + HostPortFromErrInfo(error);
        appendTriedLog(msg);
        m_log.Emsg(" WARN", "openverify cmsd_exhausted", msg.c_str());
    } else if (m_observe && rc == SFS_REDIRECT && !accepted) {
        const std::string msg = std::string("path=") + pathStr + " host=" + HostPortFromErrInfo(error);
        m_log.Emsg(" INFO", "openverify observe passthrough", msg.c_str());
    }

    return rc;
}

int OpenVerifyFile::close() { return m_wrapped->close(); }

int OpenVerifyFile::checkpoint(cpAct act, struct iov* range, int n) { return m_wrapped->checkpoint(act, range, n); }

int OpenVerifyFile::fctl(const int cmd, const char* args, XrdOucErrInfo& out_error) {
    return m_wrapped->fctl(cmd, args, out_error);
}

const char* OpenVerifyFile::FName() { return m_wrapped->FName(); }

int OpenVerifyFile::getMmap(void** Addr, off_t& Size) { return m_wrapped->getMmap(Addr, Size); }

XrdSfsXferSize OpenVerifyFile::pgRead(XrdSfsFileOffset offset, char* buffer, XrdSfsXferSize rdlen, uint32_t* csvec,
                                      uint64_t opts) {
    return m_wrapped->pgRead(offset, buffer, rdlen, csvec, opts);
}

XrdSfsXferSize OpenVerifyFile::pgRead(XrdSfsAio* aioparm, uint64_t opts) { return m_wrapped->pgRead(aioparm, opts); }

XrdSfsXferSize OpenVerifyFile::pgWrite(XrdSfsFileOffset offset, char* buffer, XrdSfsXferSize rdlen, uint32_t* csvec,
                                       uint64_t opts) {
    return m_wrapped->pgWrite(offset, buffer, rdlen, csvec, opts);
}

XrdSfsXferSize OpenVerifyFile::pgWrite(XrdSfsAio* aioparm, uint64_t opts) { return m_wrapped->pgWrite(aioparm, opts); }

int OpenVerifyFile::read(XrdSfsFileOffset fileOffset, XrdSfsXferSize amount) {
    return m_wrapped->read(fileOffset, amount);
}

XrdSfsXferSize OpenVerifyFile::read(XrdSfsFileOffset fileOffset, char* buffer, XrdSfsXferSize buffer_size) {
    return m_wrapped->read(fileOffset, buffer, buffer_size);
}

int OpenVerifyFile::read(XrdSfsAio* aioparm) { return m_wrapped->read(aioparm); }

XrdSfsXferSize OpenVerifyFile::write(XrdSfsFileOffset fileOffset, const char* buffer, XrdSfsXferSize buffer_size) {
    return m_wrapped->write(fileOffset, buffer, buffer_size);
}

int OpenVerifyFile::write(XrdSfsAio* aioparm) { return m_wrapped->write(aioparm); }

int OpenVerifyFile::sync() { return m_wrapped->sync(); }

int OpenVerifyFile::sync(XrdSfsAio* aiop) { return m_wrapped->sync(aiop); }

int OpenVerifyFile::stat(struct stat* buf) { return m_wrapped->stat(buf); }

int OpenVerifyFile::truncate(XrdSfsFileOffset fileOffset) { return m_wrapped->truncate(fileOffset); }

int OpenVerifyFile::getCXinfo(char cxtype[4], int& cxrsz) { return m_wrapped->getCXinfo(cxtype, cxrsz); }

int OpenVerifyFile::SendData(XrdSfsDio* sfDio, XrdSfsFileOffset offset, XrdSfsXferSize size) {
    return m_wrapped->SendData(sfDio, offset, size);
}
