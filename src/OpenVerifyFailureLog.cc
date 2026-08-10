#include "OpenVerifyFailureLog.hh"

#include <cstdlib>
#include <sstream>

void OpenVerifyFailureLog::Configure(XrdSysError& daemon_log) {
    m_err.reset();
    m_logger.reset();
    m_path.clear();

    const char* path = std::getenv("XRD_OPENVERIFY_FAILURE_LOG");
    if (!path || !*path) {
        return;
    }

    m_path = path;
    // xrotate=0 and Bind(lfh=0): leave rotation to system logrotate; avoid creating
    // a directory .lock that would disable the daemon's logrotate stanza.
    m_logger = std::make_unique<XrdSysLogger>(STDERR_FILENO, /*xrotate=*/0);
    const int rc = m_logger->Bind(m_path.c_str(), /*lfh=*/0);
    if (rc != 0) {
        m_logger.reset();
        const std::string msg = std::string("openverify failure log bind failed path=") + m_path +
                                " errno=" + std::to_string(-rc);
        daemon_log.Emsg(" WARN", msg.c_str());
        m_path.clear();
        return;
    }

    m_err = std::make_unique<XrdSysError>(m_logger.get(), "openverify_fail");
    const std::string msg = std::string("openverify failure log enabled path=") + m_path;
    daemon_log.Emsg(" INFO", msg.c_str());
}

void OpenVerifyFailureLog::Log(const OpenVerifyFailureRecord& rec) {
    if (!m_err) return;
    const std::string line = FormatRecord(rec);
    m_err->Emsg("", line.c_str());
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

    if (protocol == "http") {
        return "https://" + authority + p;
    }
    // CMS root PFNs use '//' between authority and path.
    return "root://" + authority + "/" + p;
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
      << " protocol=" << EscapeValue(rec.protocol.empty() ? "unknown" : rec.protocol)
      << " stage=" << EscapeValue(rec.stage.empty() ? "unknown" : rec.stage)
      << " reason=" << EscapeValue(rec.reason.empty() ? "openverify_failure" : rec.reason)
      << " status_code=" << rec.status_code
      << " err_no=" << rec.err_no
      << " detail=" << EscapeValue(rec.detail);
    return o.str();
}
