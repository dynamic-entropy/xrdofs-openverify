#include "OpenVerifyRucio.hh"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

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

size_t CurlWriteToString(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

size_t CurlHeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    const size_t total = size * nitems;
    auto* token = static_cast<std::string*>(userdata);
    const std::string line(buffer, total);
    static constexpr const char* kHdr = "X-Rucio-Auth-Token:";
    const auto pos = line.find(kHdr);
    if (pos == std::string::npos) {
        // Header names are case-insensitive; accept lowercase too.
        static constexpr const char* kHdrLower = "x-rucio-auth-token:";
        const auto pos2 = line.find(kHdrLower);
        if (pos2 == std::string::npos) return total;
        std::string value = line.substr(pos2 + std::strlen(kHdrLower));
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ')) {
            value.pop_back();
        }
        while (!value.empty() && value.front() == ' ') value.erase(value.begin());
        *token = value;
        return total;
    }
    std::string value = line.substr(pos + std::strlen(kHdr));
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ')) {
        value.pop_back();
    }
    while (!value.empty() && value.front() == ' ') value.erase(value.begin());
    *token = value;
    return total;
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

}  // namespace

std::string OpenVerifyRucioSchemeFromProt(const char* prot) {
    if (prot && (std::strcmp(prot, "http") == 0 || std::strcmp(prot, "https") == 0)) {
        return "davs";
    }
    return "root";
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

std::vector<OpenVerifyRucioCandidate> OpenVerifyRucioParseReplicasJson(const std::string& body,
                                                                      const std::string& want_scheme) {
    std::vector<OpenVerifyRucioCandidate> out;
    if (body.empty()) return out;

    const std::string scheme_prefix = want_scheme + "://";

    auto consume_object = [&](const nlohmann::json& obj) {
        if (!obj.is_object() || !obj.contains("pfns") || !obj["pfns"].is_object()) return;
        for (auto it = obj["pfns"].begin(); it != obj["pfns"].end(); ++it) {
            const std::string pfn = it.key();
            if (pfn.rfind(scheme_prefix, 0) != 0) continue;

            OpenVerifyRucioCandidate c;
            c.pfn = pfn;
            if (!OpenVerifyRucioParsePfn(pfn, c.host, c.port)) continue;

            if (it.value().is_object()) {
                if (it.value().contains("rse") && it.value()["rse"].is_string()) {
                    c.rse = it.value()["rse"].get<std::string>();
                }
                if (it.value().contains("priority") && it.value()["priority"].is_number_integer()) {
                    c.priority = it.value()["priority"].get<int>();
                }
            }
            out.push_back(std::move(c));
        }
    };

    try {
        const auto trimmed_start = body.find_first_not_of(" \t\r\n");
        if (trimmed_start == std::string::npos) return out;
        if (body[trimmed_start] == '[') {
            const auto j = nlohmann::json::parse(body);
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
                consume_object(nlohmann::json::parse(line));
            }
        }
    } catch (const nlohmann::json::exception&) {
        return {};
    }

    std::stable_sort(out.begin(), out.end(),
                     [](const OpenVerifyRucioCandidate& a, const OpenVerifyRucioCandidate& b) {
                         return a.priority < b.priority;
                     });
    return out;
}

OpenVerifyRucio::OpenVerifyRucio(XrdSysError& log) : m_log(log) {
    m_enabled = EnvFlagEnabled("XRD_OPENVERIFY_RUCIO");
    m_rucio_url = EnvOrDefault("XRD_OPENVERIFY_RUCIO_URL", kDefaultRucioUrl);
    while (!m_rucio_url.empty() && m_rucio_url.back() == '/') m_rucio_url.pop_back();
    m_auth_url = EnvOrDefault("XRD_OPENVERIFY_RUCIO_AUTH_URL", kDefaultAuthUrl);
    while (!m_auth_url.empty() && m_auth_url.back() == '/') m_auth_url.pop_back();
    m_account = EnvOrDefault("XRD_OPENVERIFY_RUCIO_ACCOUNT", "");
    m_timeout_s = EnvLongOrDefault("XRD_OPENVERIFY_RUCIO_TIMEOUT", 10);
}

void OpenVerifyRucio::LogConfig() {
    if (!m_enabled) return;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    if (m_account.empty()) {
        m_log.Emsg(" WARN",
                   "openverify rucio enabled but XRD_OPENVERIFY_RUCIO_ACCOUNT unset; lookups will soft-fail to cmsd");
        return;
    }
    const std::string msg = std::string("openverify rucio enabled url=") + m_rucio_url + " auth=" + m_auth_url +
                            " account=" + m_account;
    m_log.Emsg(" INFO", msg.c_str());
}

bool OpenVerifyRucio::EnsureAuthToken(bool force_refresh) {
    std::lock_guard<std::mutex> lock(m_token_mtx);
    const auto now = std::chrono::steady_clock::now();
    if (!force_refresh && !m_token.empty() && now < m_token_expiry) {
        return true;
    }

    if (m_account.empty()) {
        m_log.Emsg(" WARN", "openverify rucio auth skipped: no account");
        return false;
    }
    const char* proxy = std::getenv("X509_USER_PROXY");
    if (!proxy || !*proxy) {
        m_log.Emsg(" WARN", "openverify rucio auth skipped: X509_USER_PROXY unset");
        return false;
    }

    const std::string url = m_auth_url + "/auth/x509_proxy";
    std::string token;
    std::string body;

    CURL* curl = curl_easy_init();
    if (!curl) {
        m_log.Emsg(" WARN", "openverify rucio auth: curl_easy_init failed");
        return false;
    }

    struct curl_slist* headers = nullptr;
    const std::string acct_hdr = std::string("X-Rucio-Account: ") + m_account;
    headers = curl_slist_append(headers, acct_hdr.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, proxy);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, proxy);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlHeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &token);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, m_timeout_s);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, m_timeout_s);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    const CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc == CURLE_OPERATION_TIMEDOUT) {
        m_log.Emsg(" WARN", "openverify rucio auth timed out");
        m_token.clear();
        return false;
    }
    if (rc != CURLE_OK || http_code != 200 || token.empty()) {
        const std::string msg = std::string("openverify rucio auth failed curl=") + curl_easy_strerror(rc) +
                                " http=" + std::to_string(http_code);
        m_log.Emsg(" WARN", msg.c_str());
        m_token.clear();
        return false;
    }

    m_token = std::move(token);
    m_token_expiry = now + kTokenTtl;
    m_log.Emsg(" INFO", "openverify rucio auth token acquired");
    return true;
}

OpenVerifyRucioListResult OpenVerifyRucio::DoListReplicas(const std::string& lfn, const std::string& scheme,
                                                          const std::string& client_ip, const std::string& token) {
    OpenVerifyRucioListResult result;
    result.status = OpenVerifyRucioLookupResult::Error;

    nlohmann::json body = {{"dids", nlohmann::json::array({{{"scope", "cms"}, {"name", lfn}}})},
                           {"schemes", nlohmann::json::array({scheme})},
                           {"sort", "geoip"},
                           {"domain", "wan"}};

    const std::string payload = body.dump();
    const std::string url = m_rucio_url + "/replicas/list";
    std::string response;

    CURL* curl = curl_easy_init();
    if (!curl) {
        m_log.Emsg(" WARN", "openverify rucio list: curl_easy_init failed");
        return result;
    }

    struct curl_slist* headers = nullptr;
    const std::string token_hdr = std::string("X-Rucio-Auth-Token: ") + token;
    headers = curl_slist_append(headers, token_hdr.c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!client_ip.empty()) {
        const std::string xff = std::string("X-Forwarded-For: ") + client_ip;
        headers = curl_slist_append(headers, xff.c_str());
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
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc == CURLE_OPERATION_TIMEDOUT) {
        result.status = OpenVerifyRucioLookupResult::Timeout;
        m_log.Emsg(" WARN", "openverify rucio list_replicas timed out");
        return result;
    }
    if (rc != CURLE_OK) {
        const std::string msg = std::string("openverify rucio list_replicas curl error: ") + curl_easy_strerror(rc);
        m_log.Emsg(" WARN", msg.c_str());
        result.status = OpenVerifyRucioLookupResult::Error;
        return result;
    }
    if (http_code == 401 || http_code == 403) {
        result.status = OpenVerifyRucioLookupResult::AuthError;
        m_log.Emsg(" WARN", "openverify rucio list_replicas auth rejected");
        return result;
    }
    if (http_code == 404) {
        result.status = OpenVerifyRucioLookupResult::Empty;
        return result;
    }
    if (http_code != 200) {
        const std::string msg = std::string("openverify rucio list_replicas http=") + std::to_string(http_code);
        m_log.Emsg(" WARN", msg.c_str());
        result.status = OpenVerifyRucioLookupResult::Error;
        return result;
    }

    result.candidates = OpenVerifyRucioParseReplicasJson(response, scheme);
    result.status = result.candidates.empty() ? OpenVerifyRucioLookupResult::Empty : OpenVerifyRucioLookupResult::Ok;
    return result;
}

OpenVerifyRucioListResult OpenVerifyRucio::ListReplicas(const std::string& lfn, const std::string& scheme,
                                                        const std::string& client_ip) {
    OpenVerifyRucioListResult result;
    if (!m_enabled) {
        result.status = OpenVerifyRucioLookupResult::Disabled;
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
    return result;
}
