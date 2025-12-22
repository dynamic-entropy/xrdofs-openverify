#include "XrdOfsOpenVerify.hh"

OpenVerifyFileSystem* ofs = nullptr;

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
    XrdSfsFile* f = m_next_sfs->newFile(user, monid);
    if (!f) {
        m_log.Emsg(" WARN", "XrdOfsOpenVerify::newFile - underlying newFile returned null");
        return nullptr;
    }
    m_log.Emsg(" INFO", "XrdOfsOpenVerify::newFile - wrapping with FileWrapper");
    XrdSfsFile* fw = new OpenVerifyFile(f, m_log);
    return fw;
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
