#include "XrdOfsOpenVerify.hh"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "XrdCl/XrdClDefaultEnv.hh"

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
    m_log.Emsg("ERR:: ", "*** XrdOfsOpenVerify Initialised ****");
    if (m_observe) {
        m_log.Emsg("INFO",
                   "openverify observe mode (XRD_OPENVERIFY_OBSERVE): cache metrics + verify on miss only; "
                   "no cache/tried changes; redirect unchanged");
    }
    if (m_direct_server) {
        m_log.Emsg("INFO",
                   "openverify direct server (XRD_OPENVERIFY_DIRECT_SERVER): rewrite accepted redirects to "
                   "verified data-server host:port (cmsd path only; unsafe for EOS FST)");
    }
    m_rucio.LogConfig();
    Configure();
    m_metrics.SetSiteSource(&m_host_reliability);
    m_cache.StartExpiryThread();
}

XrdSfsDirectory* OpenVerifyFileSystem::newDir(char* user, int monid) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::newDir");
    return m_next_sfs->newDir(user, monid);
}

XrdSfsDirectory* OpenVerifyFileSystem::newDir(XrdOucErrInfo& einfo) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::newDir(einfo)");
    return m_next_sfs->newDir(einfo);
}

XrdSfsFile* OpenVerifyFileSystem::newFile(char* user, int monid) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::newFile");
    std::unique_ptr<XrdSfsFile> f(m_next_sfs->newFile(user, monid));
    if (!f) {
        m_log.Emsg(" WARN", "XrdOfsOpenVerify::newFile - underlying newFile returned null");
        return nullptr;
    }
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::newFile - wrapping with FileWrapper");
    return new OpenVerifyFile(std::move(f), m_log, m_cache, m_metrics, m_single_flight, m_host_reliability, m_rucio,
                              m_observe, m_direct_server, m_ov_cert, m_ov_key);
}

XrdSfsFile* OpenVerifyFileSystem::newFile(XrdOucErrInfo& einfo) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::newFile(einfo)");
    return m_next_sfs->newFile(einfo);
}

int OpenVerifyFileSystem::chksum(csFunc Func, const char* csName, const char* path, XrdOucErrInfo& eInfo,
                                 const XrdSecEntity* client, const char* opaque) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::chksum");
    return m_next_sfs->chksum(Func, csName, path, eInfo, client, opaque);
}

int OpenVerifyFileSystem::chmod(const char* path, XrdSfsMode mode, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                                const char* opaque) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::chmod");
    return m_next_sfs->chmod(path, mode, eInfo, client, opaque);
}

void OpenVerifyFileSystem::Connect(const XrdSecEntity* client) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::Connect");
    m_next_sfs->Connect(client);
}

void OpenVerifyFileSystem::Disc(const XrdSecEntity* client) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::Disc");
    m_next_sfs->Disc(client);
}

void OpenVerifyFileSystem::EnvInfo(XrdOucEnv* envP) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::EnvInfo");
    m_next_sfs->EnvInfo(envP);
}

int OpenVerifyFileSystem::exists(const char* path, XrdSfsFileExistence& eFlag, XrdOucErrInfo& eInfo,
                                 const XrdSecEntity* client, const char* opaque) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::exists");
    return m_next_sfs->exists(path, eFlag, eInfo, client, opaque);
}

int OpenVerifyFileSystem::FAttr(XrdSfsFACtl* faReq, XrdOucErrInfo& eInfo, const XrdSecEntity* client) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::FAttr");
    return m_next_sfs->FAttr(faReq, eInfo, client);
}

int OpenVerifyFileSystem::FSctl(const int cmd, XrdSfsFSctl& args, XrdOucErrInfo& eInfo, const XrdSecEntity* client) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::FSctl");
    return m_next_sfs->FSctl(cmd, args, eInfo, client);
}

int OpenVerifyFileSystem::fsctl(const int cmd, const char* args, XrdOucErrInfo& eInfo, const XrdSecEntity* client) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::fsctl");
    return m_next_sfs->fsctl(cmd, args, eInfo, client);
}

int OpenVerifyFileSystem::getChkPSize() {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::getChkPSize");
    return m_next_sfs->getChkPSize();
}

int OpenVerifyFileSystem::getStats(char* buff, int blen) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::getStats");
    return m_next_sfs->getStats(buff, blen);
}

const char* OpenVerifyFileSystem::getVersion() {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::getVersion");
    return XrdVERSION;
}

int OpenVerifyFileSystem::gpFile(gpfFunc& gpAct, XrdSfsGPFile& gpReq, XrdOucErrInfo& eInfo,
                                 const XrdSecEntity* client) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::gpFile");
    return m_next_sfs->gpFile(gpAct, gpReq, eInfo, client);
}

int OpenVerifyFileSystem::mkdir(const char* path, XrdSfsMode mode, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                                const char* opaque) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::mkdir");
    return m_next_sfs->mkdir(path, mode, eInfo, client, opaque);
}

int OpenVerifyFileSystem::prepare(XrdSfsPrep& pargs, XrdOucErrInfo& eInfo, const XrdSecEntity* client) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::prepare");
    return m_next_sfs->prepare(pargs, eInfo, client);
}

int OpenVerifyFileSystem::rem(const char* path, XrdOucErrInfo& eInfo, const XrdSecEntity* client, const char* opaque) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::rem");
    return m_next_sfs->rem(path, eInfo, client, opaque);
}

int OpenVerifyFileSystem::remdir(const char* path, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                                 const char* opaque) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::remdir");
    return m_next_sfs->remdir(path, eInfo, client, opaque);
}

int OpenVerifyFileSystem::rename(const char* oPath, const char* nPath, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                                 const char* opaqueO, const char* opaqueN) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::rename");
    return m_next_sfs->rename(oPath, nPath, eInfo, client, opaqueO, opaqueN);
}

int OpenVerifyFileSystem::stat(const char* Name, struct stat* buf, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                               const char* opaque) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::stat(struct stat)");
    return m_next_sfs->stat(Name, buf, eInfo, client, opaque);
}

int OpenVerifyFileSystem::stat(const char* path, mode_t& mode, XrdOucErrInfo& eInfo, const XrdSecEntity* client,
                               const char* opaque) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::stat(mode_t)");
    return m_next_sfs->stat(path, mode, eInfo, client, opaque);
}

int OpenVerifyFileSystem::truncate(const char* path, XrdSfsFileOffset fsize, XrdOucErrInfo& eInfo,
                                   const XrdSecEntity* client, const char* opaque) {
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::truncate");
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
