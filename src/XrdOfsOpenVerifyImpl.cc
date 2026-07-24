#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

#include "XrdCl/XrdClFile.hh"
#include "XrdCl/XrdClStatus.hh"
#include "XrdCl/XrdClURL.hh"
#include "XrdCl/XrdClXRootDResponses.hh"
#include "XrdOfsOpenVerify.hh"
#include "XrdOuc/XrdOucUtils.hh"

namespace {
std::string MakeXrdClUrlFromKeyAndOpaque(const std::string& key, const char* opaque, const char* ztnFilePath,
                                         const char* gsiCertPath, const char* gsiKeyPath) {
    // `key` format: <host>[:<port>]//<path>
    std::string url = "root://";
    url += key;

    bool haveQuery = false;
    if (opaque && *opaque) {
        url.push_back('?');
        haveQuery = true;
        if (*opaque == '?') {
            url.append(opaque + 1);
        } else {
            url.append(opaque);
        }
    }

    auto appendCgi = [&](const char* name, const char* value) {
        if (!value || !*value) return;
        url.push_back(haveQuery ? '&' : '?');
        haveQuery = true;
        url.append(name);
        url.push_back('=');
        // Raw paths: XrdCl::URL::SetParams does not percent-decode values.
        url.append(value);
    };

    // Per-request token file path for XrdSecztn (see xrd.ztn / findToken in XrdSecProtocolztn).
    appendCgi("xrd.ztn", ztnFilePath);
    // Service X.509 for verify when the client has no bearer token.
    appendCgi("xrd.gsiusrcrt", gsiCertPath);
    appendCgi("xrd.gsiusrkey", gsiKeyPath);

    return url;
}

// Returns true when the originating client connected over the HTTP(S) wire
// protocol (see XrdHttpProtocol, which sets XrdSecEntity::prot to "http"/"https").
bool IsHttpProtocol(const XrdSecEntity* client) {
    if (!client) return false;
    // prot is a fixed-size, NUL-terminated field (XrdSecPROTOIDSIZE).
    return std::strcmp(client->prot, "http") == 0 || std::strcmp(client->prot, "https") == 0;
}

std::string MakeHttpUrlFromKeyAndOpaque(const std::string& key, const char* opaque, const std::string& token) {
    // `key` format: <host>[:<port>]//<path>. HTTP needs a single '/' between the
    // authority and the path, so collapse the "//" separator used by the xroot form.
    std::string url = "https://";
    const size_t sep = key.find("//");
    if (sep == std::string::npos) {
        url += key;
    } else {
        url.append(key, 0, sep);
        url.push_back('/');
        url.append(key, sep + 2, std::string::npos);
    }

    bool haveQuery = false;
    if (opaque && *opaque) {
        url.push_back('?');
        haveQuery = true;
        url.append(*opaque == '?' ? opaque + 1 : opaque);
    }

    // The target XrdHttp server reads the bearer token from the authz CGI param.
    if (!token.empty()) {
        url.push_back(haveQuery ? '&' : '?');
        url.append("authz=");
        url.append(XrdOucUtils::UrlEncode("Bearer " + token));
    }

    return url;
}

// Writes the bearer token to a private temp file; XrdCl ztn reads it via ?xrd.ztn=... on the URL.
class ScopedTokenTempFile {
   public:
    ScopedTokenTempFile(const ScopedTokenTempFile&) = delete;
    ScopedTokenTempFile& operator=(const ScopedTokenTempFile&) = delete;

    explicit ScopedTokenTempFile(const std::string& token) {
        if (token.empty()) return;

        char tmpl[] = "/tmp/xrdovXXXXXX";
        const int fd = mkstemp(tmpl);
        if (fd < 0) return;

        if (fchmod(fd, 0600) != 0) {
            close(fd);
            unlink(tmpl);
            return;
        }

        const char* p = token.data();
        size_t left = token.size();
        while (left > 0) {
            const ssize_t n = write(fd, p, left);
            if (n <= 0) {
                close(fd);
                unlink(tmpl);
                return;
            }
            p += static_cast<size_t>(n);
            left -= static_cast<size_t>(n);
        }
        close(fd);
        m_path = tmpl;
    }

    ~ScopedTokenTempFile() {
        if (!m_path.empty()) {
            unlink(m_path.c_str());
        }
    }

    bool ok() const { return !m_path.empty(); }
    const std::string& path() const { return m_path; }

   private:
    std::string m_path;
};

bool GetTokenFromClientCreds(const XrdSecEntity* client, std::string& outToken) {
    outToken.clear();
    if (!client || !client->creds || client->credslen <= 0) return false;

    outToken.assign(client->creds, static_cast<size_t>(client->credslen));
    if (!outToken.empty() && outToken.back() == '\0') outToken.pop_back();

    if (outToken.find('\0') != std::string::npos) {
        outToken.clear();
        return false;
    }
    return true;
}

bool IsHexDigit(char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

int HexValue(char c) {
    const unsigned char uc = static_cast<unsigned char>(c);
    if (uc >= '0' && uc <= '9') return uc - '0';
    if (uc >= 'a' && uc <= 'f') return 10 + (uc - 'a');
    if (uc >= 'A' && uc <= 'F') return 10 + (uc - 'A');
    return -1;
}

std::string UrlDecode(const std::string& in) {
    std::string out;
    out.reserve(in.size());

    for (size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (c == '%' && i + 2 < in.size() && IsHexDigit(in[i + 1]) && IsHexDigit(in[i + 2])) {
            const int hi = HexValue(in[i + 1]);
            const int lo = HexValue(in[i + 2]);
            out.push_back(static_cast<char>((hi << 4) | lo));
            i += 2;
            continue;
        }
        if (c == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(c);
    }
    return out;
}

std::string ToLowerCopy(const std::string& in) {
    std::string out = in;
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(out[i])));
    }
    return out;
}

std::string TrimAsciiWhitespace(const std::string& in) {
    size_t first = 0;
    while (first < in.size() && std::isspace(static_cast<unsigned char>(in[first])) != 0) {
        ++first;
    }

    size_t last = in.size();
    while (last > first && std::isspace(static_cast<unsigned char>(in[last - 1])) != 0) {
        --last;
    }

    return in.substr(first, last - first);
}

bool TryExtractTokenFromOpaque(const char* opaque, std::string& outToken) {
    outToken.clear();
    if (!opaque || !*opaque) return false;

    std::string q = (*opaque == '?') ? std::string(opaque + 1) : std::string(opaque);
    if (q.empty()) return false;

    size_t start = 0;
    while (start <= q.size()) {
        size_t end = q.find('&', start);
        if (end == std::string::npos) end = q.size();

        const std::string pair = q.substr(start, end - start);
        if (!pair.empty()) {
            size_t eq = pair.find('=');
            const std::string rawKey = (eq == std::string::npos) ? pair : pair.substr(0, eq);
            const std::string rawValue = (eq == std::string::npos) ? std::string() : pair.substr(eq + 1);
            const std::string key = ToLowerCopy(UrlDecode(rawKey));
            std::string value = UrlDecode(rawValue);

            if (key == "authorization" || key == "authz" || key == "bearer" || key == "bearer_token" ||
                key == "token" || key == "access_token" || key == "xrdhttpcreds") {
                value = TrimAsciiWhitespace(value);
                const std::string bearerPrefix = "bearer ";
                const std::string lowerValue = ToLowerCopy(value);
                if (lowerValue.compare(0, bearerPrefix.size(), bearerPrefix) == 0) {
                    value = TrimAsciiWhitespace(value.substr(bearerPrefix.size()));
                }

                if (!value.empty()) {
                    outToken = value;
                    return true;
                }
            }
        }

        if (end == q.size()) break;
        start = end + 1;
    }

    return false;
}

// Maps XrdCl::Status.code (XrdClStatus.hh) -> stable Prometheus `reason` label.
// errOSError is excluded: refined by errno below.
const std::unordered_map<uint16_t, const char*>& XrdClCodeToReason() {
    static const std::unordered_map<uint16_t, const char*> kMap = {
        {XrdCl::errNone, "err_none"},
        {XrdCl::errRetry, "retry"},
        {XrdCl::errUnknown, "unknown"},
        {XrdCl::errInvalidOp, "invalid_op"},
        {XrdCl::errFcntl, "fcntl"},
        {XrdCl::errPoll, "poll"},
        {XrdCl::errConfig, "config"},
        {XrdCl::errInternal, "internal"},
        {XrdCl::errUnknownCommand, "unknown_command"},
        {XrdCl::errInvalidArgs, "invalid_args"},
        {XrdCl::errInProgress, "in_progress"},
        {XrdCl::errUninitialized, "uninitialized"},
        {XrdCl::errNotSupported, "not_supported"},
        {XrdCl::errDataError, "data_error"},
        {XrdCl::errNotImplemented, "not_implemented"},
        {XrdCl::errNoMoreReplicas, "no_more_replicas"},
        {XrdCl::errPipelineFailed, "pipeline_failed"},
        {XrdCl::errInvalidAddr, "invalid_address"},
        {XrdCl::errSocketError, "socket_error"},
        {XrdCl::errSocketTimeout, "socket_timeout"},
        {XrdCl::errSocketDisconnected, "socket_disconnected"},
        {XrdCl::errPollerError, "poller_error"},
        {XrdCl::errSocketOptError, "socket_opt_error"},
        {XrdCl::errStreamDisconnect, "stream_disconnect"},
        {XrdCl::errConnectionError, "connection_error"},
        {XrdCl::errInvalidSession, "invalid_session"},
        {XrdCl::errTlsError, "tls_error"},
        {XrdCl::errInvalidMessage, "invalid_message"},
        {XrdCl::errHandShakeFailed, "handshake_failed"},
        {XrdCl::errLoginFailed, "login_failed"},
        {XrdCl::errAuthFailed, "auth_failed"},
        {XrdCl::errQueryNotSupported, "query_not_supported"},
        {XrdCl::errOperationExpired, "operation_expired"},
        {XrdCl::errOperationInterrupted, "operation_interrupted"},
        {XrdCl::errThresholdExceeded, "threshold_exceeded"},
        {XrdCl::errNoMoreFreeSIDs, "no_more_free_sids"},
        {XrdCl::errInvalidRedirectURL, "invalid_redirect_url"},
        {XrdCl::errInvalidResponse, "invalid_response"},
        {XrdCl::errNotFound, "not_found"},
        {XrdCl::errCheckSumError, "checksum_error"},
        {XrdCl::errRedirectLimit, "redirect_limit"},
        {XrdCl::errCorruptedHeader, "corrupted_header"},
        {XrdCl::errErrorResponse, "error_response"},
        {XrdCl::errRedirect, "redirect"},
        {XrdCl::errLocalError, "local_error"},
        {XrdCl::errResponseNegative, "response_negative"},
    };
    return kMap;
}

// Stable Prometheus `reason` label for XrdCl errors (low cardinality).
std::string ClassifyXrdClStatus(const XrdCl::Status& st) {
    if (st.IsOK()) return "ok";
    if (st.code == XrdCl::errOSError) {
        if (st.errNo == EACCES || st.errNo == EPERM) return "permission_denied";
        if (st.errNo == ENOENT) return "not_found";
        return "os_error";
    }
    // Server-returned protocol errors: errNo holds the kXR_* code.
    if (st.code == XrdCl::errErrorResponse) {
        if (st.errNo == kXR_NotFound)      return "not_found";
        if (st.errNo == kXR_NotAuthorized) return "permission_denied";
    }
    const auto& m = XrdClCodeToReason();
    const auto it = m.find(st.code);
    if (it != m.end()) return it->second;
    return "xrdcl_error";
}

std::string HostPortFromVerifyKey(const std::string& key) {
    const size_t sep = key.find("//");
    if (sep == std::string::npos) return key;
    return key.substr(0, sep);
}

std::string PathFromVerifyKey(const std::string& key) {
    const size_t sep = key.find("//");
    if (sep == std::string::npos) return key;
    return key.substr(sep + 2);
}

// XrdCl DataServer is host:port (optionally user[:password]@host:port).
bool ParseDataServerHostPort(const std::string& dataServer, std::string& host, int& port) {
    if (dataServer.empty()) return false;
    const XrdCl::URL url("root://" + dataServer + "/");
    if (!url.IsValid() || url.GetHostName().empty()) return false;
    host = url.GetHostName();
    port = url.GetPort();
    return port >= 0;
}

bool ExtractFinalDataServer(XrdCl::File& f, std::string& host, int& port) {
    host.clear();
    port = -1;
    std::string dataServer;
    if (!f.GetProperty("DataServer", dataServer) || dataServer.empty()) {
        return false;
    }
    return ParseDataServerHostPort(dataServer, host, port);
}

bool ExtractClientBearerToken(const XrdSecEntity* client, const char* opaque, std::string& outToken,
                              const char** outSource) {
    outToken.clear();
    if (outSource) *outSource = nullptr;

    if (GetTokenFromClientCreds(client, outToken)) {
        if (outSource) *outSource = "client->creds";
        return true;
    }

    if (TryExtractTokenFromOpaque(opaque, outToken)) {
        if (outSource) *outSource = "opaque";
        return true;
    }

    return false;
}

}  // namespace

XrdCl::XRootDStatus OpenVerifyFile::open_verify(const std::string& key, const char* opaque, const XrdSecEntity* client,
                                                time_t timeout_seconds, std::string* final_host, int* final_port) {
    if (final_host) final_host->clear();
    if (final_port) *final_port = -1;

    std::string token;
    const char* tokenSource = nullptr;
    ExtractClientBearerToken(client, opaque, token, &tokenSource);
    const bool haveToken = !token.empty();

    const std::string hostPort = HostPortFromVerifyKey(key);
    const std::string path = PathFromVerifyKey(key);

    if (haveToken) {
        const std::string tokenMsg = std::string("openverify: client bearer token from ") +
                                     (tokenSource ? tokenSource : "unknown") + " len=" +
                                     std::to_string(token.size());
        m_log.Emsg("DEBUG", tokenMsg.c_str());
    } else {
        m_log.Emsg("DEBUG", "openverify: no bearer token in client creds or opaque");
    }

    const std::string verifyMsg = std::string("openverify: verifying ") + path + " on " + hostPort +
                                  (haveToken ? " with token"
                                             : (!m_ov_cert.empty() && !m_ov_key.empty()
                                                    ? " with service cert"
                                                    : " with default XrdCl credentials"));
    m_log.Emsg(" INFO", verifyMsg.c_str());

    // Use XrdCl to open the file and read the first and last byte
    // If the read fails, return false
    // If the read succeeds, return true
    const auto slashPos = key.find('/');
    if (slashPos == std::string::npos || slashPos == 0) {
        m_log.Emsg(" WARN", "openverify invalid key (missing host/path):", key.c_str());
        return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errInvalidAddr, 0, "openverify_invalid_key"};
    }

    // Match the client's wire protocol (http/https vs xroot) for the outbound open.
    const bool useHttp = IsHttpProtocol(client);
    const bool haveServiceCert = !haveToken && !m_ov_cert.empty() && !m_ov_key.empty();

    // xroot carries the bearer token via a per-request ztn token file; http carries
    // it as an authz CGI parameter, so only the xroot path needs the temp file.
    ScopedTokenTempFile tokenFile((!useHttp && haveToken) ? token : std::string());
    const char* ztnPath = nullptr;
    if (!useHttp && haveToken) {
        if (!tokenFile.ok()) {
            m_log.Emsg(" WARN", "openverify could not create temp token file for", key.c_str());
            return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errOSError, static_cast<uint32_t>(errno),
                                       "openverify_token_file_error"};
        }
        ztnPath = tokenFile.path().c_str();
    }

    const char* gsiCert = (!useHttp && haveServiceCert) ? m_ov_cert.c_str() : nullptr;
    const char* gsiKey = (!useHttp && haveServiceCert) ? m_ov_key.c_str() : nullptr;

    const std::string url = useHttp ? MakeHttpUrlFromKeyAndOpaque(key, opaque, haveToken ? token : std::string())
                                    : MakeXrdClUrlFromKeyAndOpaque(key, opaque, ztnPath, gsiCert, gsiKey);

    const char* credLabel =
        haveToken ? "with token" : (haveServiceCert ? "with service cert" : "with default XrdCl credentials");
    if (!haveToken && !haveServiceCert) {
        m_log.Emsg("DEBUG",
                   "openverify: no bearer token and XRD_OPENVERIFY_CERT/KEY unset; outbound open uses default XrdCl "
                   "credentials (X509_USER_PROXY etc.) if any");
    }
    const std::string outboundMsg = std::string("openverify: outbound ") + (useHttp ? "https" : "root") + " open to " +
                                    hostPort + path + " " + credLabel;
    m_log.Emsg("DEBUG", outboundMsg.c_str());

    XrdCl::File f;
    // should we use others - readable open flags instead?
    auto st = f.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::None, timeout_seconds);
    if (!st.IsOK()) {
        const std::string msg = st.ToString();
        m_log.Emsg(" WARN", "openverify XrdCl open failed for", url.c_str(), msg.c_str());
        return XrdCl::XRootDStatus{st, ClassifyXrdClStatus(st)};
    }

    XrdCl::StatInfo* statInfo = nullptr;
    st = f.Stat(false, statInfo);
    if (!st.IsOK() || !statInfo) {
        const std::string msg = st.ToString();
        m_log.Emsg(" WARN", "openverify XrdCl stat failed for", url.c_str(), msg.c_str());
        auto closeSt = f.Close();
        (void)closeSt;
        if (st.IsOK()) {
            return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errInvalidResponse, 0, "openverify_stat_no_info"};
        }
        return XrdCl::XRootDStatus{st, ClassifyXrdClStatus(st)};
    }

    const uint64_t size = statInfo->GetSize();
    delete statInfo;
    statInfo = nullptr;

    if (size == 0) {
        // Empty file: treat as failure
        auto closeSt = f.Close();
        (void)closeSt;
        return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errDataError, 0, "openverify_empty_file"};
    }

    XrdCl::ChunkList chunks;
    const uint32_t totalLen = (size == 1) ? 1u : 2u;
    chunks.reserve(totalLen);

    std::array<char, 2> buf{};
    chunks.emplace_back(0, 1, nullptr);
    if (size > 1) {
        chunks.emplace_back(size - 1, 1, nullptr);
    }

    XrdCl::VectorReadInfo* vri = nullptr;
    st = f.VectorRead(chunks, buf.data(), vri);
    if (vri) {
        delete vri;
        vri = nullptr;
    }

    if (!st.IsOK()) {
        const std::string msg = st.ToString();
        m_log.Emsg(" WARN", "openverify XrdCl vector read failed for", url.c_str(), msg.c_str());
        auto closeSt = f.Close();
        (void)closeSt;
        return XrdCl::XRootDStatus{st, ClassifyXrdClStatus(st)};
    }

    if (final_host || final_port) {
        std::string dsHost;
        int dsPort = -1;
        if (ExtractFinalDataServer(f, dsHost, dsPort)) {
            if (final_host) *final_host = dsHost;
            if (final_port) *final_port = dsPort;
            const std::string dsMsg = "openverify: data server " + dsHost + ":" + std::to_string(dsPort);
            m_log.Emsg("DEBUG", dsMsg.c_str());
        } else {
            m_log.Emsg("DEBUG", "openverify: DataServer property unavailable after verify");
        }
    }

    auto closeSt = f.Close();
    (void)closeSt;
    return XrdCl::XRootDStatus{};
}
