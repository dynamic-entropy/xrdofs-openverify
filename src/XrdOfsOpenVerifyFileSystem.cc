#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "XrdCl/XrdClDefaultEnv.hh"
#include "XrdOfsOpenVerify.hh"

namespace {

bool OpenVerifyObserveModeEnabled() {
    const char* p = std::getenv("XRD_OPENVERIFY_OBSERVE");
    return p && std::strcmp(p, "1") == 0;
}

bool OpenVerifyDirectServerEnabled() {
    const char* p = std::getenv("XRD_OPENVERIFY_DIRECT_SERVER");
    return p && std::strcmp(p, "1") == 0;
}

}  // namespace

OpenVerifyFileSystem* ofs = nullptr;

void OpenVerifyFileSystem::Configure() {
    const char* cert = std::getenv("XRD_OPENVERIFY_CERT");
    const char* key = std::getenv("XRD_OPENVERIFY_KEY");
    const bool haveCert = cert && *cert;
    const bool haveKey = key && *key;

    if (haveCert != haveKey) {
        m_log.Emsg(" WARN",
                   "openverify: XRD_OPENVERIFY_CERT and XRD_OPENVERIFY_KEY must both be set; ignoring incomplete pair");
        return;
    }
    if (!haveCert) {
        m_log.Emsg(" INFO",
                   "openverify: XRD_OPENVERIFY_CERT/KEY not set; no-token verifies use default XrdCl credentials");
        return;
    }

    m_ov_cert = cert;
    m_ov_key = key;

    // HTTPS outbound opens ignore xrd.gsiusr* CGI and use XrdCl DefaultEnv only.
    if (XrdCl::Env* env = XrdCl::DefaultEnv::GetEnv()) {
        env->PutString("HttpClientCertFile", m_ov_cert);
        env->PutString("HttpClientKeyFile", m_ov_key);
    }

    const std::string msg = std::string("openverify: service X.509 cert=") + m_ov_cert + " key=" + m_ov_key;
    m_log.Emsg(" INFO", msg.c_str());
}

OpenVerifyFileSystem::OpenVerifyFileSystem(XrdSfsFileSystem* nativeFS, XrdSysLogger* Logger, const char* configFn,
                                           XrdOucEnv* envP)
    : m_next_sfs(nativeFS),
      m_log(0, "ofs_plugin"),
      m_config(configFn),
      m_env(envP),
      m_rucio(m_log),
      m_observe(OpenVerifyObserveModeEnabled()),
      m_direct_server(OpenVerifyDirectServerEnabled()) {
    m_log.logger(Logger);
    m_log.Emsg(" INFO", "*** XrdOfsOpenVerify Initialised ****");
    if (m_observe) {
        m_log.Emsg(" INFO",
                   "openverify observe mode (XRD_OPENVERIFY_OBSERVE): verify on cache miss, "
                   "no Rucio, no tried=, no retry; cmsd redirect unchanged");
        if (m_rucio.Enabled()) {
            m_log.Emsg(" INFO", "openverify observe mode: XRD_OPENVERIFY_RUCIO ignored; cmsd locate only");
        }
    }
    if (m_direct_server) {
        m_log.Emsg(" INFO",
                   "openverify direct server (XRD_OPENVERIFY_DIRECT_SERVER): rewrite accepted redirects to "
                   "verified data-server host:port (cmsd path only; unsafe for EOS FST)");
    }
    const char* skip_spec = std::getenv("XRD_OPENVERIFY_SKIP_PREFIX");
    m_skip_prefixes = OpenVerifyRucioParseIgnorePrefixes(skip_spec ? skip_spec : "");
    if (!m_skip_prefixes.empty()) {
        std::string joined;
        for (size_t i = 0; i < m_skip_prefixes.size(); ++i) {
            if (i) joined += ",";
            joined += m_skip_prefixes[i];
        }
        const std::string msg =
            std::string("openverify skip_prefix=") + joined + " (no rucio, no verify; cmsd redirect passthrough)";
        m_log.Emsg(" INFO", msg.c_str());
    }
    m_rucio.LogConfig();
    m_rucio.SetMetrics(&m_metrics);
    const std::string health_cfg = m_host_reliability.ConfigSummary();
    m_log.Emsg(" INFO", health_cfg.c_str());
    m_host_reliability.SetEventLog([this](const char* msg) { m_log.Emsg(" WARN", msg); });
    Configure();
    m_metrics.SetSiteSource(&m_host_reliability);
    m_cache.StartExpiryThread();
}

XrdSfsDirectory* OpenVerifyFileSystem::newDir(char* user, int monid) { return m_next_sfs->newDir(user, monid); }

XrdSfsDirectory* OpenVerifyFileSystem::newDir(XrdOucErrInfo& einfo) { return m_next_sfs->newDir(einfo); }

XrdSfsFile* OpenVerifyFileSystem::Wrap(std::unique_ptr<XrdSfsFile> f) {
    if (!f) return nullptr;
    return new OpenVerifyFile(std::move(f), m_log, m_cache, m_metrics, m_single_flight, m_host_reliability, m_rucio,
                              m_observe, m_direct_server, m_ov_cert, m_ov_key, m_skip_prefixes);
}

XrdSfsFile* OpenVerifyFileSystem::newFile(char* user, int monid) {
    std::unique_ptr<XrdSfsFile> f(m_next_sfs->newFile(user, monid));
    if (!f) {
        m_log.Emsg(" WARN", "openverify newFile: underlying newFile returned null");
        return nullptr;
    }
    return Wrap(std::move(f));
}

// XrdSfsFileSystem::newFile(XrdOucErrInfo&) defaults to returning null and the
// header says a wrapper must implement it. Forwarding unwrapped would skip verify
// for every caller that uses the ErrInfo constructor (backward propagation).
XrdSfsFile* OpenVerifyFileSystem::newFile(XrdOucErrInfo& einfo) {
    std::unique_ptr<XrdSfsFile> f(m_next_sfs->newFile(einfo));
    if (!f) {
        m_log.Emsg(" WARN", "openverify newFile(einfo): underlying newFile returned null");
        return nullptr;
    }
    return Wrap(std::move(f));
}

int OpenVerifyFileSystem::chksum(csFunc Func, const char* csName, const char* path, XrdOucErrInfo& eInfo,
                                 const XrdSecEntity* client, const char* opaque) {
    return m_next_sfs->chksum(Func, csName, path, eInfo, client, opaque);
}

int OpenVerifyFileSystem::chmod(const char* path, XrdSfsMode mode, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                                const char* opaque) {
    return m_next_sfs->chmod(path, mode, eInfo, client, opaque);
}

void OpenVerifyFileSystem::Connect(const XrdSecEntity* client) { m_next_sfs->Connect(client); }

void OpenVerifyFileSystem::Disc(const XrdSecEntity* client) { m_next_sfs->Disc(client); }

void OpenVerifyFileSystem::EnvInfo(XrdOucEnv* envP) { m_next_sfs->EnvInfo(envP); }

int OpenVerifyFileSystem::exists(const char* path, XrdSfsFileExistence& eFlag, XrdOucErrInfo& eInfo,
                                 const XrdSecEntity* client, const char* opaque) {
    return m_next_sfs->exists(path, eFlag, eInfo, client, opaque);
}

int OpenVerifyFileSystem::FAttr(XrdSfsFACtl* faReq, XrdOucErrInfo& eInfo, const XrdSecEntity* client) {
    return m_next_sfs->FAttr(faReq, eInfo, client);
}

int OpenVerifyFileSystem::FSctl(const int cmd, XrdSfsFSctl& args, XrdOucErrInfo& eInfo, const XrdSecEntity* client) {
    return m_next_sfs->FSctl(cmd, args, eInfo, client);
}

int OpenVerifyFileSystem::fsctl(const int cmd, const char* args, XrdOucErrInfo& eInfo, const XrdSecEntity* client) {
    return m_next_sfs->fsctl(cmd, args, eInfo, client);
}

int OpenVerifyFileSystem::getChkPSize() { return m_next_sfs->getChkPSize(); }

int OpenVerifyFileSystem::getStats(char* buff, int blen) { return m_next_sfs->getStats(buff, blen); }

const char* OpenVerifyFileSystem::getVersion() { return XrdVERSION; }

int OpenVerifyFileSystem::gpFile(gpfFunc& gpAct, XrdSfsGPFile& gpReq, XrdOucErrInfo& eInfo,
                                 const XrdSecEntity* client) {
    return m_next_sfs->gpFile(gpAct, gpReq, eInfo, client);
}

int OpenVerifyFileSystem::mkdir(const char* path, XrdSfsMode mode, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                                const char* opaque) {
    return m_next_sfs->mkdir(path, mode, eInfo, client, opaque);
}

int OpenVerifyFileSystem::prepare(XrdSfsPrep& pargs, XrdOucErrInfo& eInfo, const XrdSecEntity* client) {
    return m_next_sfs->prepare(pargs, eInfo, client);
}

int OpenVerifyFileSystem::rem(const char* path, XrdOucErrInfo& eInfo, const XrdSecEntity* client, const char* opaque) {
    return m_next_sfs->rem(path, eInfo, client, opaque);
}

int OpenVerifyFileSystem::remdir(const char* path, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                                 const char* opaque) {
    return m_next_sfs->remdir(path, eInfo, client, opaque);
}

int OpenVerifyFileSystem::rename(const char* oPath, const char* nPath, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                                 const char* opaqueO, const char* opaqueN) {
    return m_next_sfs->rename(oPath, nPath, eInfo, client, opaqueO, opaqueN);
}

int OpenVerifyFileSystem::stat(const char* Name, struct stat* buf, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                               const char* opaque) {
    return m_next_sfs->stat(Name, buf, eInfo, client, opaque);
}

int OpenVerifyFileSystem::stat(const char* path, mode_t& mode, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                               const char* opaque) {
    return m_next_sfs->stat(path, mode, eInfo, client, opaque);
}

int OpenVerifyFileSystem::truncate(const char* path, XrdSfsFileOffset fsize, XrdOucErrInfo& eInfo,
                                   const XrdSecEntity* client, const char* opaque) {
    return m_next_sfs->truncate(path, fsize, eInfo, client, opaque);
}

XrdVERSIONINFO(XrdSfsGetFileSystem2, OpenVerifyFileSystem);

extern "C" {
XrdSfsFileSystem* XrdSfsGetFileSystem2(XrdSfsFileSystem* nativeFS, XrdSysLogger* Logger, const char* configFn,
                                       XrdOucEnv* envP) {
    ofs = new OpenVerifyFileSystem(nativeFS, Logger, configFn, envP);
    return ofs;
}
}
