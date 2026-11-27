#include <fcntl.h>
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

#include "OpenVerifyUrl.hh"
#include "XrdCl/XrdClFile.hh"
#include "XrdCl/XrdClStatus.hh"
#include "XrdCl/XrdClURL.hh"
#include "XrdCl/XrdClXRootDResponses.hh"
#include "XrdOfsOpenVerify.hh"
#include "XrdOuc/XrdOucUtils.hh"
#include "XrdSys/XrdSysError.hh"

namespace {
// Build the outbound verify URL. Do not forward the client request opaque: AAA
// clients often send xrd.gsiusrpxy=/var/lib/condor/... (a path on the worker),
// which would override X509_USER_PROXY on this host and cause Auth failed.
std::string MakeXrdClVerifyUrl(const std::string& key, const char* ztnFilePath, const char* gsiCertPath,
                               const char* gsiKeyPath) {
    // `key` format: <host>[:<port>]//<path>
    std::string url = "root://";
    url += key;

    bool haveQuery = false;
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
    // Optional service X.509 when XRD_OPENVERIFY_CERT/KEY are set.
    appendCgi("xrd.gsiusrcrt", gsiCertPath);
    appendCgi("xrd.gsiusrkey", gsiKeyPath);

    return url;
}

// True when the client connected over HTTP. The link dialect is "http" or
// "https". sec.prot stays the auth protocol.
bool IsHttpProtocol(const XrdSecEntity* client) {
    const std::string prot = OpenVerifyClientWireProt(client);
    return prot == "http" || prot == "https";
}

std::string MakeHttpVerifyUrl(const std::string& key, const std::string& token) {
    // `key` is <host>[:<port>]//<path>, or scheme://<host>[:<port>]//<path> when
    // the cmsd redirect named the scheme. HTTP needs one '/' before the path.
    std::string body = key;
    if (body.rfind("davs://", 0) == 0) body.replace(0, 4, "https");
    else if (body.rfind("dav://", 0) == 0) body.replace(0, 3, "http");
    std::string url;
    if (body.find("://") != std::string::npos) {
        url = std::move(body);
        const auto scheme = url.find("://");
        const auto pathsep = url.find("//", scheme + 3);
        if (pathsep != std::string::npos) url.replace(pathsep, 2, "/");
    } else {
        url = "https://";
        const size_t sep = key.find("//");
        if (sep == std::string::npos) {
            url += key;
        } else {
            url.append(key, 0, sep);
            url.push_back('/');
            url.append(key, sep + 2, std::string::npos);
        }
    }

    // Do not forward client opaque (same reason as MakeXrdClVerifyUrl). Only attach
    // a bearer we extracted ourselves.
    if (!token.empty()) {
        url.push_back('?');
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
        if (fd < 0) {
            m_err = errno;
            return;
        }
        // Close-on-exec so a token fd cannot leak across a fork in this process.
        if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || fchmod(fd, 0600) != 0) {
            m_err = errno;
            close(fd);
            unlink(tmpl);
            return;
        }

        const char* p = token.data();
        size_t left = token.size();
        while (left > 0) {
            const ssize_t n = write(fd, p, left);
            if (n < 0) {
                if (errno == EINTR) continue;
                m_err = errno;
                close(fd);
                unlink(tmpl);
                return;
            }
            if (n == 0) {
                m_err = EIO;
                close(fd);
                unlink(tmpl);
                return;
            }
            p += static_cast<size_t>(n);
            left -= static_cast<size_t>(n);
        }
        if (close(fd) != 0) {
            m_err = errno;
            unlink(tmpl);
            return;
        }
        m_path = tmpl;
    }

    ~ScopedTokenTempFile() {
        if (!m_path.empty()) {
            unlink(m_path.c_str());
        }
    }

    bool ok() const { return !m_path.empty(); }
    const std::string& path() const { return m_path; }
    int err() const { return m_err; }

   private:
    std::string m_path;
    int m_err{0};
};

bool GetTokenFromClientCreds(const XrdSecEntity* client, std::string& outToken) {
    outToken.clear();
    if (!client || !client->creds || client->credslen <= 0) return false;
    // Only ztn puts a bearer token in creds. gsi (VOMS certfmt=pem) and sss put proxy/identity
    // material there, which must never be forwarded to a remote site. HTTP bearers arrive via
    // the authz opaque instead.
    if (!client->prot || std::strcmp(client->prot, "ztn") != 0) return false;

    outToken.assign(client->creds, static_cast<size_t>(client->credslen));
    if (!outToken.empty() && outToken.back() == '\0') outToken.pop_back();

    if (outToken.find('\0') != std::string::npos) {
        outToken.clear();
        return false;
    }
    return true;
}

bool IsHexDigit(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }

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
        if (st.errNo == kXR_NotFound) return "not_found";
        if (st.errNo == kXR_NotAuthorized) return "permission_denied";
    }
    const auto& m = XrdClCodeToReason();
    const auto it = m.find(st.code);
    if (it != m.end()) return it->second;
    return "xrdcl_error";
}

// Drop ?query so a bearer (authz=) or ztn path is not written to the daemon log.
std::string ProbeUrlForLog(const std::string& url) { return OpenVerifyUrl::StripUrlQuery(url); }

void LogXrdClProbeFail(XrdSysError& log, const char* stage, const std::string& url, const XrdCl::Status& st) {
    const std::string line = std::string("reason=") + ClassifyXrdClStatus(st) + " stage=" + stage +
                             " url=" + ProbeUrlForLog(url) + " " + st.ToString();
    log.Emsg(" WARN", "openverify_probe", line.c_str());
}

void LogXrdClProbeFail(XrdSysError& log, const char* stage, const std::string& url, const char* reason) {
    const std::string line = std::string("reason=") + reason + " stage=" + stage + " url=" + ProbeUrlForLog(url);
    log.Emsg(" WARN", "openverify_probe", line.c_str());
}

// Sync XrdCl timeouts are uint16_t seconds on XRootD 5 and fit in that range on 6.
uint16_t ProbeTimeout16(time_t seconds) {
    if (seconds <= 0) return 1;
    if (seconds > 65535) return 65535;
    return static_cast<uint16_t>(seconds);
}

// Path separator is the "//" after the authority. A schemed key
// (https://host//path) also contains "//" inside "://".
size_t PathSepInVerifyKey(const std::string& key) {
    const auto scheme = key.find("://");
    const size_t from = (scheme == std::string::npos) ? 0 : scheme + 3;
    return key.find("//", from);
}

std::string HostPortFromVerifyKey(const std::string& key) {
    const size_t sep = PathSepInVerifyKey(key);
    std::string authority = (sep == std::string::npos) ? key : key.substr(0, sep);
    const auto scheme = authority.find("://");
    if (scheme != std::string::npos) authority = authority.substr(scheme + 3);
    return authority;
}

std::string PathFromVerifyKey(const std::string& key) {
    const size_t sep = PathSepInVerifyKey(key);
    if (sep == std::string::npos) return key;
    return key.substr(sep + 2);
}

bool KeyForcesHttp(const std::string& key) {
    const auto scheme = key.find("://");
    if (scheme == std::string::npos) return false;
    const std::string s = key.substr(0, scheme);
    return s == "http" || s == "https" || s == "dav" || s == "davs";
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
                                                time_t timeout_seconds, std::string* final_host, int* final_port,
                                                std::string* fail_stage) {
    if (final_host) final_host->clear();
    if (final_port) *final_port = -1;
    if (fail_stage) fail_stage->clear();

    auto set_stage = [&](const char* stage) {
        if (fail_stage) *fail_stage = stage;
    };

    // A schemed cache key is the redirect URL the client will open. Otherwise
    // match the client's wire protocol (http/https vs xroot).
    const bool useHttp = (key.find("://") != std::string::npos) ? KeyForcesHttp(key) : IsHttpProtocol(client);

    std::string token;
    ExtractClientBearerToken(client, opaque, token, nullptr);
    const bool haveToken = !token.empty();
    const bool haveServiceCert = !haveToken && !m_ov_cert.empty() && !m_ov_key.empty();

    const std::string hostPort = HostPortFromVerifyKey(key);
    const std::string path = PathFromVerifyKey(key);

    const char* credLabel =
        haveToken ? "with token" : (haveServiceCert ? "with service cert" : "with default XrdCl credentials");
    const std::string verifyMsg = std::string("openverify: verifying ") + path + " on " + hostPort + " " + credLabel;
    m_log.Emsg(" INFO", verifyMsg.c_str());

    // Use XrdCl to open the file and read the first and last byte
    // If the read fails, return false
    // If the read succeeds, return true
    const auto slashPos = PathSepInVerifyKey(key);
    if (slashPos == std::string::npos || slashPos == 0) {
        set_stage("key");
        m_log.Emsg(" WARN", "openverify invalid key (missing host/path):", key.c_str());
        return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errInvalidAddr, 0, "openverify_invalid_key"};
    }

    // xroot carries the bearer token via a per-request ztn token file; http carries
    // it as an authz CGI parameter, so only the xroot path needs the temp file.
    ScopedTokenTempFile tokenFile((!useHttp && haveToken) ? token : std::string());
    const char* ztnPath = nullptr;
    if (!useHttp && haveToken) {
        if (!tokenFile.ok()) {
            set_stage("credential_setup");
            m_log.Emsg(" WARN", "openverify could not create temp token file for", key.c_str());
            return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errOSError,
                                       static_cast<uint32_t>(tokenFile.err() != 0 ? tokenFile.err() : errno),
                                       "openverify_token_file_error"};
        }
        ztnPath = tokenFile.path().c_str();
    }

    const char* gsiCert = (!useHttp && haveServiceCert) ? m_ov_cert.c_str() : nullptr;
    const char* gsiKey = (!useHttp && haveServiceCert) ? m_ov_key.c_str() : nullptr;

    // Opaque is only used above for bearer extraction — never forwarded onto the probe URL.
    // A root:// key is stripped back to host//path so MakeXrdClVerifyUrl can prepend the scheme.
    std::string root_key = key;
    if (!useHttp) {
        const auto scheme = key.find("://");
        if (scheme != std::string::npos) root_key = key.substr(scheme + 3);
    }
    const std::string url = useHttp ? MakeHttpVerifyUrl(key, haveToken ? token : std::string())
                                    : MakeXrdClVerifyUrl(root_key, ztnPath, gsiCert, gsiKey);

    const uint16_t probe_timeout = ProbeTimeout16(timeout_seconds);

    XrdCl::File f;
    // should we use others - readable open flags instead?
    auto st = f.Open(url, XrdCl::OpenFlags::Read, XrdCl::Access::None, probe_timeout);
    if (!st.IsOK()) {
        set_stage("open");
        LogXrdClProbeFail(m_log, "open", url, st);
        return XrdCl::XRootDStatus{st, ClassifyXrdClStatus(st)};
    }

    // Stat, VectorRead, and Close must use the same budget as Open. The default
    // timeout (0) follows XrdCl's RequestTimeout, which is often unlimited, so a
    // hung data server would pin this OFS worker past VERIFY_TIMEOUT.
    auto close_probe = [&] {
        const auto close_st = f.Close(probe_timeout);
        (void)close_st;
    };

    XrdCl::StatInfo* statInfo = nullptr;
    st = f.Stat(false, statInfo, probe_timeout);
    if (!st.IsOK() || !statInfo) {
        set_stage("stat");
        if (st.IsOK()) {
            LogXrdClProbeFail(m_log, "stat", url, "openverify_stat_no_info");
        } else {
            LogXrdClProbeFail(m_log, "stat", url, st);
        }
        delete statInfo;
        close_probe();
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
        set_stage("empty_file");
        LogXrdClProbeFail(m_log, "empty_file", url, "openverify_empty_file");
        close_probe();
        return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errDataError, 0, "openverify_empty_file"};
    }

    XrdCl::ChunkList chunks;
    const uint32_t totalLen = (size == 1) ? 1u : 2u;
    chunks.reserve(totalLen);

    std::array<char, 2> buf{};
    // Point each chunk at its own byte. A null chunk buffer plus a shared
    // buffer depends on XrdCl packing, which a short OK reply would hide.
    chunks.emplace_back(0, 1, buf.data());
    if (size > 1) {
        chunks.emplace_back(size - 1, 1, buf.data() + 1);
    }

    XrdCl::VectorReadInfo* vri = nullptr;
    st = f.VectorRead(chunks, nullptr, vri, probe_timeout);
    uint32_t got = 0;
    if (vri) {
        got = vri->GetSize();
        delete vri;
        vri = nullptr;
    }

    if (!st.IsOK() || got < totalLen) {
        set_stage("vector_read");
        if (st.IsOK()) {
            LogXrdClProbeFail(m_log, "vector_read", url, "openverify_short_read");
            close_probe();
            return XrdCl::XRootDStatus{XrdCl::stError, XrdCl::errDataError, 0, "openverify_short_read"};
        }
        LogXrdClProbeFail(m_log, "vector_read", url, st);
        close_probe();
        return XrdCl::XRootDStatus{st, ClassifyXrdClStatus(st)};
    }

    if (final_host || final_port) {
        std::string dsHost;
        int dsPort = -1;
        if (ExtractFinalDataServer(f, dsHost, dsPort)) {
            if (final_host) *final_host = dsHost;
            if (final_port) *final_port = dsPort;
        }
    }

    close_probe();
    return XrdCl::XRootDStatus{};
}
