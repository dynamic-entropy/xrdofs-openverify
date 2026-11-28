#include "OpenVerifyRucio.hh"

#include <curl/curl.h>

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <nlohmann/json.hpp>
#include <sstream>

#include "OpenVerifyMetrics.hh"
#include "OpenVerifyRucioCurlPool.hh"
#include "OpenVerifyRucioListCache.hh"
#include "OpenVerifyRucioSelector.hh"
#include "XrdNet/XrdNetAddrInfo.hh"
#include "XrdSec/XrdSecEntity.hh"

namespace {

constexpr const char* kDefaultRucioUrl = "https://cms-rucio.cern.ch";
constexpr const char* kDefaultAuthUrl = "https://cms-rucio-auth.cern.ch";
constexpr auto kTokenTtl = std::chrono::minutes(50);

bool EnvFlagEnabled(const char* name) {
    const char* p = std::getenv(name);
    return p && std::strcmp(p, "1") == 0;
}

std::string EnvOrDefault(const char* name, const char* def) {
    const char* p = std::getenv(name);
    if (p && *p) return p;
    return def;
}

long EnvLongOrDefault(const char* name, long def) {
    const char* p = std::getenv(name);
    if (!p || !*p) return def;
    const long v = std::strtol(p, nullptr, 10);
    return v > 0 ? v : def;
}

// A hostile or huge list_replicas body must not grow without a bound.
constexpr size_t kMaxRucioBody = 8 * 1024 * 1024;

size_t CurlWriteToString(char* ptr, size_t size, size_t nmemb, void* userdata) {
    if (size != 0 && nmemb > (static_cast<size_t>(-1) / size)) return 0;
    const size_t n = size * nmemb;
    auto* out = static_cast<std::string*>(userdata);
    if (n > kMaxRucioBody || out->size() > kMaxRucioBody - n) return 0;
    out->append(ptr, n);
    return n;
}

size_t CurlHeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    const size_t total = size * nitems;
    auto* token = static_cast<std::string*>(userdata);
    const std::string line(buffer, total);
    // Header names are case-insensitive. Match only at the start of the line.
    static constexpr const char* kHdr = "x-rucio-auth-token:";
    constexpr size_t kHdrLen = sizeof("x-rucio-auth-token:") - 1;
    if (line.size() < kHdrLen) return total;
    for (size_t i = 0; i < kHdrLen; ++i) {
        if (std::tolower(static_cast<unsigned char>(line[i])) != kHdr[i]) return total;
    }
    std::string value = line.substr(kHdrLen);
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ')) {
        value.pop_back();
    }
    while (!value.empty() && value.front() == ' ') value.erase(value.begin());
    *token = std::move(value);
    return total;
}

// One token, no CR/LF or comma, so it cannot inject extra HTTP headers.
bool IsSafeForwardedClient(const std::string& ip) {
    if (ip.empty() || ip.size() > 128) return false;
    for (unsigned char c : ip) {
        if (c <= 0x20 || c >= 0x7f || c == ',') return false;
    }
    return true;
}

int DefaultPortForScheme(const std::string& scheme) {
    if (scheme == "root" || scheme == "xroot") return 1094;
    if (scheme == "davs" || scheme == "https" || scheme == "http") return 443;
    return -1;
}

// Authority may be host, host:port, [ipv6], or [ipv6]:port.
bool SplitAuthority(const std::string& authority, std::string& host, int& port, int default_port) {
    host.clear();
    port = default_port;
    if (authority.empty()) return false;

    if (authority.front() == '[') {
        const auto end = authority.find(']');
        if (end == std::string::npos) return false;
        host = authority.substr(1, end - 1);
        if (end + 1 < authority.size()) {
            if (authority[end + 1] != ':') return false;
            port = static_cast<int>(std::strtol(authority.c_str() + end + 2, nullptr, 10));
            if (port <= 0) return false;
        }
        return !host.empty();
    }

    const auto colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
        host = authority.substr(0, colon);
        port = static_cast<int>(std::strtol(authority.c_str() + colon + 1, nullptr, 10));
        if (port <= 0 || host.empty()) return false;
        return true;
    }
    host = authority;
    return !host.empty();
}

std::string TrimCopy(const std::string& s) {
    size_t a = 0;
    size_t b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

// Collapse leading slashes to one; drop a trailing slash except for "/".
std::string NormalizeLfnPrefix(const std::string& raw) {
    const std::string t = TrimCopy(raw);
    if (t.empty()) return {};
    size_t start = 0;
    while (start < t.size() && t[start] == '/') ++start;
    std::string out = "/" + t.substr(start);
    while (out.size() > 1 && out.back() == '/') out.pop_back();
    return out;
}

// want_scheme is already normalized (davs|root|…). For davs, also accept https:// / http://
// PFN keys some catalogs emit interchangeably with davs://.
bool PfnMatchesWantScheme(const std::string& pfn, const std::string& want_scheme) {
    if (pfn.rfind(want_scheme + "://", 0) == 0) return true;
    if (want_scheme == "davs") {
        return pfn.rfind("https://", 0) == 0 || pfn.rfind("http://", 0) == 0;
    }
    return false;
}

}  // namespace

std::string OpenVerifyClientWireProt(const XrdSecEntity* client) {
    if (!client) return {};
    if (client->addrInfo) {
        const char* wire = client->addrInfo->Dialect();
        if (wire && wire[0] != '\0') return wire;
    }
    return client->prot;
}

std::string OpenVerifyRucioSchemeFromProt(const char* prot) {
    if (prot && (std::strcmp(prot, "http") == 0 || std::strcmp(prot, "https") == 0)) {
        return "davs";  // Rucio protocol id; not wire "http"/"https"
    }
    return "root";
}

std::string OpenVerifyRucioNormalizeScheme(const std::string& scheme) {
    // Rucio protocol ids: CMS HTTP/WebDAV replicas are "davs", not "http"/"https".
    if (scheme == "http" || scheme == "https" || scheme == "davs") return "davs";
    if (scheme == "xroot" || scheme == "root") return "root";
    return scheme;
}

bool OpenVerifyRucioParsePfn(const std::string& pfn, std::string& host, int& port) {
    host.clear();
    port = -1;

    const auto scheme_end = pfn.find("://");
    if (scheme_end == std::string::npos || scheme_end == 0) return false;
    const std::string scheme = pfn.substr(0, scheme_end);
    const std::string rest = pfn.substr(scheme_end + 3);
    if (rest.empty()) return false;

    // Authority ends at first '/' (path). root PFNs often use '//' before path.
    const auto slash = rest.find('/');
    const std::string authority = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    return SplitAuthority(authority, host, port, DefaultPortForScheme(scheme));
}

bool OpenVerifyRucioIsTapeCandidate(const OpenVerifyRucioCandidate& c) {
    if (!c.type.empty()) {
        static constexpr const char kTape[] = "TAPE";
        if (c.type.size() == sizeof(kTape) - 1) {
            bool match = true;
            for (size_t i = 0; i < sizeof(kTape) - 1; ++i) {
                if (std::toupper(static_cast<unsigned char>(c.type[i])) != kTape[i]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    }
    // CMS RSE names: T1_FR_CCIN2P3_Tape, T1_US_FNAL_Tape, …
    static constexpr const char kTapeSuffix[] = "_Tape";
    constexpr size_t kTapeSuffixLen = sizeof(kTapeSuffix) - 1;
    if (c.rse.size() >= kTapeSuffixLen &&
        c.rse.compare(c.rse.size() - kTapeSuffixLen, kTapeSuffixLen, kTapeSuffix) == 0) {
        return true;
    }
    return false;
}

std::vector<OpenVerifyRucioCandidate> OpenVerifyRucioParseReplicasJson(const std::string& body,
                                                                       const std::string& want_scheme) {
    std::vector<OpenVerifyRucioCandidate> out;
    if (body.empty()) return out;

    const std::string scheme = OpenVerifyRucioNormalizeScheme(want_scheme);

    // ordered_json keeps the pfns key order Rucio returned (sort=geoip); plain json sorts keys.
    auto consume_object = [&](const nlohmann::ordered_json& obj) {
        if (!obj.is_object() || !obj.contains("pfns") || !obj["pfns"].is_object()) return;
        for (auto it = obj["pfns"].begin(); it != obj["pfns"].end(); ++it) {
            const std::string pfn = it.key();
            if (!PfnMatchesWantScheme(pfn, scheme)) continue;

            OpenVerifyRucioCandidate c;
            c.pfn = pfn;
            if (!OpenVerifyRucioParsePfn(pfn, c.host, c.port)) continue;

            if (it.value().is_object()) {
                if (it.value().contains("rse") && it.value()["rse"].is_string()) {
                    c.rse = it.value()["rse"].get<std::string>();
                }
                if (it.value().contains("type") && it.value()["type"].is_string()) {
                    c.type = it.value()["type"].get<std::string>();
                }
                if (it.value().contains("priority") && it.value()["priority"].is_number_integer()) {
                    c.priority = it.value()["priority"].get<int>();
                }
            }
            // Never verify-open or redirect to tape replicas (same gateway as Disk is common).
            if (OpenVerifyRucioIsTapeCandidate(c)) continue;
            out.push_back(std::move(c));
        }
    };

    try {
        const auto trimmed_start = body.find_first_not_of(" \t\r\n");
        if (trimmed_start == std::string::npos) return out;
        if (body[trimmed_start] == '[') {
            const auto j = nlohmann::ordered_json::parse(body);
            if (j.is_array()) {
                for (const auto& el : j) consume_object(el);
            }
        } else {
            // NDJSON / x-json-stream: one object per line.
            std::istringstream iss(body);
            std::string line;
            while (std::getline(iss, line)) {
                const auto s = line.find_first_not_of(" \t\r\n");
                if (s == std::string::npos) continue;
                consume_object(nlohmann::ordered_json::parse(line));
            }
        }
    } catch (const nlohmann::json::exception&) {
        return {};
    }

    // Try-order is applied by OpenVerifyRucioSelector after ListReplicas.
    return out;
}

std::vector<std::string> OpenVerifyRucioParseIgnorePrefixes(const std::string& spec) {
    std::vector<std::string> out;
    std::string cur;
    auto flush = [&]() {
        const std::string p = NormalizeLfnPrefix(cur);
        if (p.size() > 1) out.push_back(p);  // ignore empty / "/"
        cur.clear();
    };
    for (char c : spec) {
        if (c == ',') {
            flush();
        } else {
            cur.push_back(c);
        }
    }
    flush();
    return out;
}

std::string OpenVerifyRucioMatchedIgnorePrefix(const std::string& lfn, const std::vector<std::string>& prefixes) {
    if (prefixes.empty() || lfn.empty()) return {};
    const std::string n = NormalizeLfnPrefix(lfn);
    if (n.size() <= 1) return {};
    for (const auto& p : prefixes) {
        if (p.empty()) continue;
        if (n == p) return p;
        if (n.size() > p.size() && n.compare(0, p.size(), p) == 0 && n[p.size()] == '/') return p;
    }
    return {};
}

bool OpenVerifyRucioShouldIgnoreLfn(const std::string& lfn, const std::vector<std::string>& prefixes) {
    return !OpenVerifyRucioMatchedIgnorePrefix(lfn, prefixes).empty();
}

OpenVerifyRucio::OpenVerifyRucio(XrdSysError& log) : m_log(log) {
    m_enabled = EnvFlagEnabled("XRD_OPENVERIFY_RUCIO");
    m_rucio_url = EnvOrDefault("XRD_OPENVERIFY_RUCIO_URL", kDefaultRucioUrl);
    while (!m_rucio_url.empty() && m_rucio_url.back() == '/') m_rucio_url.pop_back();
    m_auth_url = EnvOrDefault("XRD_OPENVERIFY_RUCIO_AUTH_URL", kDefaultAuthUrl);
    while (!m_auth_url.empty() && m_auth_url.back() == '/') m_auth_url.pop_back();
    m_account = EnvOrDefault("XRD_OPENVERIFY_RUCIO_ACCOUNT", "");
    m_timeout_s = EnvLongOrDefault("XRD_OPENVERIFY_RUCIO_TIMEOUT", 10);
    m_ignore_prefixes = OpenVerifyRucioParseIgnorePrefixes(EnvOrDefault("XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX", ""));
    m_selector = OpenVerifyRucioMakeSelector(OpenVerifyRucioSelectorNameFromEnv());
    m_list_cache = std::make_unique<OpenVerifyRucioListCache>(OpenVerifyRucioListCacheConfig::FromEnv());
    if (m_enabled) {
        m_curl_pool = std::make_unique<OpenVerifyRucioCurlPool>(OpenVerifyRucioCurlPoolConfig::FromEnv());
    }
}

OpenVerifyRucio::~OpenVerifyRucio() = default;

void OpenVerifyRucio::LogConfig() {
    if (!m_enabled) return;
    if (m_account.empty()) {
        m_log.Emsg(" WARN",
                   "openverify rucio enabled but XRD_OPENVERIFY_RUCIO_ACCOUNT unset; lookups will soft-fail to cmsd");
        return;
    }
    const char* select = (m_selector) ? m_selector->Name() : "random";
    std::string ignore;
    for (size_t i = 0; i < m_ignore_prefixes.size(); ++i) {
        if (i) ignore += ",";
        ignore += m_ignore_prefixes[i];
    }
    std::string msg = std::string("openverify rucio enabled url=") + m_rucio_url + " auth=" + m_auth_url +
                      " account=" + m_account + " select=" + select;
    if (!ignore.empty()) {
        msg += " ignore_prefix=" + ignore;
    }
    if (m_list_cache && m_list_cache->Enabled()) {
        msg += " list_cache_ttl=" + std::to_string(m_list_cache->Ttl().count()) +
               " list_cache_size=" + std::to_string(m_list_cache->MaxEntries());
    } else {
        msg += " list_cache=off";
    }
    if (m_curl_pool) {
        msg += " curl_pool_min=" + std::to_string(m_curl_pool->MinSize()) +
               " curl_pool_max=" + std::to_string(m_curl_pool->MaxSize()) +
               " curl_pool=" + std::to_string(m_curl_pool->Size());
    }
    m_log.Emsg(" INFO", msg.c_str());
}

void OpenVerifyRucio::ObserveCurl(const OpenVerifyRucioCurlPool::Handle& handle) {
    if (!m_metrics || !handle) return;

    long num_connects = -1;
    curl_easy_getinfo(handle.get(), CURLINFO_NUM_CONNECTS, &num_connects);
    // NUM_CONNECTS == 0 means libcurl reused an existing TCP connection.
    m_metrics->RecordRucioCurlTransfer(handle.Reused(), num_connects == 0);

    if (m_curl_pool) {
        const auto s = m_curl_pool->GetStats();
        m_metrics->SetRucioCurlPool(s.handles, s.idle, s.inflight, s.grows, s.shrinks);
    }
}

bool OpenVerifyRucio::EnsureAuthToken(bool force_refresh) {
    std::unique_lock<std::mutex> lock(m_token_mtx);
    auto token_fresh = [&] {
        return !m_token.empty() && std::chrono::steady_clock::now() < m_token_expiry;
    };
    if (!force_refresh && token_fresh()) return true;

    // Another thread is already on the wire. Wait for it instead of stacking auths.
    if (m_auth_refreshing) {
        m_auth_cv.wait(lock, [&] { return !m_auth_refreshing; });
        if (token_fresh()) return true;
        if (!force_refresh) return false;
    }

    if (m_account.empty()) {
        m_log.Emsg(" WARN", "openverify rucio auth skipped: no account");
        return false;
    }
    const char* proxy_env = std::getenv("X509_USER_PROXY");
    if (!proxy_env || !*proxy_env) {
        m_log.Emsg(" WARN", "openverify rucio auth skipped: X509_USER_PROXY unset");
        return false;
    }

    // Copy what the HTTP call needs, then drop the lock. list_replicas must not
    // block on the token mutex for the whole auth RTT.
    const std::string proxy = proxy_env;
    const std::string account = m_account;
    const std::string url = m_auth_url + "/auth/x509_proxy";
    const long timeout_s = m_timeout_s;
    m_auth_refreshing = true;
    lock.unlock();

    std::string token;
    std::string body;
    bool ok = false;
    try {
        if (!m_curl_pool) {
            m_log.Emsg(" WARN", "openverify rucio auth: curl pool not initialized");
        } else {
            auto handle = m_curl_pool->Acquire();
            CURL* curl = handle.get();
            if (!curl) {
                m_log.Emsg(" WARN", "openverify rucio auth: curl pool acquire failed");
            } else {
                struct curl_slist* headers = nullptr;
                const std::string acct_hdr = std::string("X-Rucio-Account: ") + account;
                headers = curl_slist_append(headers, acct_hdr.c_str());

                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
                curl_easy_setopt(curl, CURLOPT_SSLCERT, proxy.c_str());
                curl_easy_setopt(curl, CURLOPT_SSLKEY, proxy.c_str());
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
                curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlHeaderCallback);
                curl_easy_setopt(curl, CURLOPT_HEADERDATA, &token);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteToString);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_s);
                curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout_s);
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

                const CURLcode rc = curl_easy_perform(curl);
                ObserveCurl(handle);
                long http_code = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                curl_slist_free_all(headers);
                handle = {};

                if (rc == CURLE_OPERATION_TIMEDOUT) {
                    m_log.Emsg(" WARN", "openverify rucio auth timed out");
                } else if (rc != CURLE_OK || http_code != 200 || token.empty()) {
                    const std::string msg = std::string("openverify rucio auth failed curl=") + curl_easy_strerror(rc) +
                                            " http=" + std::to_string(http_code);
                    m_log.Emsg(" WARN", msg.c_str());
                } else {
                    ok = true;
                }
            }
        }
    } catch (...) {
        lock.lock();
        m_token.clear();
        m_auth_refreshing = false;
        m_auth_cv.notify_all();
        throw;
    }

    lock.lock();
    if (ok) {
        m_token = std::move(token);
        m_token_expiry = std::chrono::steady_clock::now() + kTokenTtl;
        m_log.Emsg(" INFO", "openverify rucio auth token acquired");
    } else {
        m_token.clear();
    }
    m_auth_refreshing = false;
    m_auth_cv.notify_all();
    return ok;
}

OpenVerifyRucioListResult OpenVerifyRucio::DoListReplicas(const std::string& lfn, const std::string& scheme,
                                                          const std::string& client_ip, const std::string& token) {
    OpenVerifyRucioListResult result;
    result.status = OpenVerifyRucioLookupResult::Error;

    // Always send Rucio protocol ids (davs|root), never wire aliases like http/https.
    const std::string rucio_scheme = OpenVerifyRucioNormalizeScheme(scheme);

    nlohmann::json body = {{"dids", nlohmann::json::array({{{"scope", "cms"}, {"name", lfn}}})},
                           {"schemes", nlohmann::json::array({rucio_scheme})},
                           {"sort", "geoip"},
                           {"domain", "wan"}};

    const std::string payload = body.dump();
    const std::string url = m_rucio_url + "/replicas/list";
    std::string response;

    if (!m_curl_pool) {
        m_log.Emsg(" WARN", "openverify rucio list: curl pool not initialized", lfn.c_str());
        return result;
    }
    auto handle = m_curl_pool->Acquire();
    CURL* curl = handle.get();
    if (!curl) {
        m_log.Emsg(" WARN", "openverify rucio list: curl pool acquire failed", lfn.c_str());
        return result;
    }

    struct curl_slist* headers = nullptr;
    const std::string token_hdr = std::string("X-Rucio-Auth-Token: ") + token;
    headers = curl_slist_append(headers, token_hdr.c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    // Disable Expect: 100-continue (libcurl default can wait up to 1s on POST).
    headers = curl_slist_append(headers, "Expect:");
    if (IsSafeForwardedClient(client_ip)) {
        const std::string xff = std::string("X-Forwarded-For: ") + client_ip;
        headers = curl_slist_append(headers, xff.c_str());
    } else if (!client_ip.empty()) {
        // Do not log the raw value: it may contain CR/LF.
        m_log.Emsg(" WARN", "openverify rucio: ignoring client address that is not a single token");
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, m_timeout_s);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, m_timeout_s);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    const CURLcode rc = curl_easy_perform(curl);
    ObserveCurl(handle);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    handle = {};

    if (rc == CURLE_OPERATION_TIMEDOUT) {
        result.status = OpenVerifyRucioLookupResult::Timeout;
        const std::string msg = std::string("openverify rucio list_replicas timed out path=") + lfn;
        m_log.Emsg(" WARN", msg.c_str());
        return result;
    }
    if (rc != CURLE_OK) {
        const std::string msg =
            std::string("openverify rucio list_replicas curl error: ") + curl_easy_strerror(rc) + " path=" + lfn;
        m_log.Emsg(" WARN", msg.c_str());
        result.status = OpenVerifyRucioLookupResult::Error;
        return result;
    }
    if (http_code == 401 || http_code == 403) {
        result.status = OpenVerifyRucioLookupResult::AuthError;
        const std::string msg = std::string("openverify rucio list_replicas auth rejected path=") + lfn;
        m_log.Emsg(" WARN", msg.c_str());
        return result;
    }
    if (http_code == 404) {
        result.status = OpenVerifyRucioLookupResult::Empty;
        return result;
    }
    if (http_code != 200) {
        const std::string msg =
            std::string("openverify rucio list_replicas http=") + std::to_string(http_code) + " path=" + lfn;
        m_log.Emsg(" WARN", msg.c_str());
        result.status = OpenVerifyRucioLookupResult::Error;
        return result;
    }

    result.candidates = OpenVerifyRucioParseReplicasJson(response, rucio_scheme);
    result.status = result.candidates.empty() ? OpenVerifyRucioLookupResult::Empty : OpenVerifyRucioLookupResult::Ok;
    return result;
}

void OpenVerifyRucio::ApplySelector(OpenVerifyRucioListResult& result, const std::string& client_ip) const {
    if (result.status == OpenVerifyRucioLookupResult::Ok && m_selector && !result.candidates.empty()) {
        OpenVerifyRucioSelectContext ctx;
        ctx.client_ip = client_ip;
        m_selector->Order(result.candidates, ctx);
    }
}

OpenVerifyRucioListResult OpenVerifyRucio::ListReplicas(const std::string& lfn, const std::string& scheme,
                                                        const std::string& client_ip) {
    OpenVerifyRucioListResult result;
    if (!m_enabled) {
        result.status = OpenVerifyRucioLookupResult::Disabled;
        return result;
    }
    result.skip_reason = OpenVerifyRucioMatchedIgnorePrefix(lfn, m_ignore_prefixes);
    if (!result.skip_reason.empty()) {
        result.status = OpenVerifyRucioLookupResult::Skipped;
        return result;
    }
    if (lfn.empty() || scheme.empty()) {
        result.status = OpenVerifyRucioLookupResult::Error;
        return result;
    }
    if (m_account.empty()) {
        result.status = OpenVerifyRucioLookupResult::AuthError;
        return result;
    }

    if (m_list_cache && m_list_cache->Enabled()) {
        const auto cached = m_list_cache->Get(lfn, scheme);
        if (cached.hit) {
            result.status = cached.status;
            result.candidates = cached.candidates;
            result.from_cache = true;
            ApplySelector(result, client_ip);
            return result;
        }
    }

    if (!EnsureAuthToken(false)) {
        result.status = OpenVerifyRucioLookupResult::AuthError;
        return result;
    }

    std::string token;
    {
        std::lock_guard<std::mutex> lock(m_token_mtx);
        token = m_token;
    }

    result = DoListReplicas(lfn, scheme, client_ip, token);
    if (result.status == OpenVerifyRucioLookupResult::AuthError) {
        if (EnsureAuthToken(true)) {
            {
                std::lock_guard<std::mutex> lock(m_token_mtx);
                token = m_token;
            }
            result = DoListReplicas(lfn, scheme, client_ip, token);
        }
    }
    if (m_list_cache &&
        (result.status == OpenVerifyRucioLookupResult::Ok || result.status == OpenVerifyRucioLookupResult::Empty)) {
        m_list_cache->Put(lfn, scheme, result.status, result.candidates);
    }
    ApplySelector(result, client_ip);
    return result;
}

std::size_t OpenVerifyRucio::ListCacheSize() const {
    return (m_list_cache) ? m_list_cache->Size() : 0;
}

bool OpenVerifyRucio::ListCacheEnabled() const {
    return m_list_cache && m_list_cache->Enabled();
}
