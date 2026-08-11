#include "OpenVerifyFailureLog.hh"

#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <sstream>

OpenVerifyFailureLog::~OpenVerifyFailureLog() {
    const std::lock_guard<std::mutex> lk(m_mtx);
    if (m_fp) {
        std::fclose(m_fp);
        m_fp = nullptr;
    }
}

bool OpenVerifyFailureLog::Enabled() const {
    const std::lock_guard<std::mutex> lk(m_mtx);
    return m_fp != nullptr;
}

void OpenVerifyFailureLog::Configure(XrdSysError& daemon_log) {
    const std::lock_guard<std::mutex> lk(m_mtx);
    if (m_fp) {
        std::fclose(m_fp);
        m_fp = nullptr;
    }
    m_path.clear();

    const char* path = std::getenv("XRD_OPENVERIFY_FAILURE_LOG");
    if (!path || !*path) {
        return;
    }

    // Private append FILE — do not use XrdSysLogger::Bind. Binding a second
    // logger into the instance log dir can share/disturb the daemon log stream.
    FILE* fp = std::fopen(path, "a");
    if (!fp) {
        const int err = errno;
        const std::string msg = std::string("openverify failure log open failed path=") + path +
                                " errno=" + std::to_string(err);
        daemon_log.Emsg(" WARN", msg.c_str());
        return;
    }

    // Line-buffered so each failure appears promptly without full-block buffering.
    std::setvbuf(fp, nullptr, _IOLBF, 0);

    m_path = path;
    m_fp = fp;
    const std::string msg = std::string("openverify failure log enabled path=") + m_path;
    daemon_log.Emsg(" INFO", msg.c_str());
}

void OpenVerifyFailureLog::Log(const OpenVerifyFailureRecord& rec) {
    const std::string line = FormatRecord(rec);
    const std::string ts = FormatTimestamp();

    const std::lock_guard<std::mutex> lk(m_mtx);
    if (!m_fp) return;
    std::fprintf(m_fp, "%s %s\n", ts.c_str(), line.c_str());
    // fflush is cheap with line buffering; keep for copytruncate safety.
    std::fflush(m_fp);
}

std::string OpenVerifyFailureLog::FormatTimestamp() {
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif
    char buf[32];
    // ISO-ish local time; independent of XrdSysLogger formatting.
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm) == 0) {
        return "unknown-time";
    }
    return buf;
}

std::string OpenVerifyFailureLog::EscapeValue(const std::string& value) {
    bool need_quotes = value.empty();
    for (const unsigned char c : value) {
        if (c <= ' ' || c == '"' || c == '\\' || c == '=' || c == '\n' || c == '\r') {
            need_quotes = true;
            break;
        }
    }
    if (!need_quotes) return value;

    std::string out;
    out.reserve(value.size() + 2);
    out.push_back('"');
    for (const char c : value) {
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n') {
            out.append("\\n");
        } else if (c == '\r') {
            out.append("\\r");
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
    return out;
}

std::string OpenVerifyFailureLog::DavToHttpUrl(const std::string& url) {
    if (url.compare(0, 7, "davs://") == 0) {
        return "https://" + url.substr(7);
    }
    if (url.compare(0, 6, "dav://") == 0) {
        return "http://" + url.substr(6);
    }
    return url;
}

std::string OpenVerifyFailureLog::SynthesizePfn(const std::string& protocol, const std::string& host, int port,
                                                const std::string& path) {
    if (host.empty()) return {};

    std::string p = path;
    while (!p.empty() && p.front() == '/') p.erase(p.begin());
    p.insert(p.begin(), '/');

    std::string authority = host;
    if (port >= 0) {
        authority += ":" + std::to_string(port);
    }

    // HTTP-family schemes put a single '/' between authority and path. "http"
    // maps to https:// because both the outbound probe and the Rucio davs
    // replicas are TLS.
    if (protocol == "http" || protocol == "https") {
        return "https://" + authority + p;
    }
    if (protocol == "davs" || protocol == "dav") {
        return DavToHttpUrl(protocol + "://" + authority + p);
    }
    // CMS root PFNs use '//' between authority and path.
    return "root://" + authority + "/" + p;
}

std::string OpenVerifyFailureLog::StripUrlQuery(const std::string& url) {
    const auto q = url.find('?');
    return (q == std::string::npos) ? url : url.substr(0, q);
}

std::string OpenVerifyFailureLog::PathFromUrl(const std::string& url) {
    const std::string bare = StripUrlQuery(url);
    const auto scheme = bare.find("://");
    if (scheme == std::string::npos) return {};
    const auto path_start = bare.find('/', scheme + 3);
    if (path_start == std::string::npos) return {};
    return bare.substr(path_start);
}

OpenVerifyFailureLog::RedirectTarget OpenVerifyFailureLog::MakeRucioRedirect(bool http_client,
                                                                             const std::string& host,
                                                                             int port,
                                                                             const std::string& pfn,
                                                                             const std::string& path) {
    RedirectTarget out;
    out.code = port;
    out.text = host;
    if (host.empty()) {
        return out;
    }

    // Prefer the catalog PFN (already scheme-matched by Rucio list); fall back to synthesize.
    // Rucio hands back davs:// for the CMS WebDAV replicas, which is a catalog
    // protocol id and not something a Location: header may carry, so translate
    // it to its wire scheme before it leaves the plugin.
    std::string url = DavToHttpUrl(StripUrlQuery(pfn));
    if (url.find("://") == std::string::npos) {
        if (path.empty()) {
            return out;
        }
        url = SynthesizePfn(http_client ? "davs" : "root", host, port, path);
    }
    if (url.empty()) {
        return out;
    }
    out.code = -1;
    out.text = std::move(url);
    return out;
}

std::string OpenVerifyFailureLog::FormatRecord(const OpenVerifyFailureRecord& rec) {
    std::ostringstream o;
    o << "openverify_failure"
      << " source=" << EscapeValue(rec.source.empty() ? "unknown" : rec.source)
      << " attempt=" << rec.attempt
      << " host=" << EscapeValue(rec.host)
      << " port=" << rec.port
      << " path=" << EscapeValue(rec.path)
      << " pfn=" << EscapeValue(rec.pfn)
      << " probe=" << EscapeValue(rec.probe)
      << " probe_path=" << EscapeValue(rec.probe_path)
      << " protocol=" << EscapeValue(rec.protocol.empty() ? "unknown" : rec.protocol)
      << " stage=" << EscapeValue(rec.stage.empty() ? "unknown" : rec.stage)
      << " reason=" << EscapeValue(rec.reason.empty() ? "openverify_failure" : rec.reason)
      << " status_code=" << rec.status_code
      << " err_no=" << rec.err_no
      << " detail=" << EscapeValue(rec.detail);
    return o.str();
}
