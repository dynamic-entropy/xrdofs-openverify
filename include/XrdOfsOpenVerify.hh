#ifndef __XRDOFSOPENVERIFY_H_
#define __XRDOFSOPENVERIFY_H_

#include <string>

#include "XrdSfs/XrdSfsInterface.hh"
#include "XrdVersion.hh"

class OpenVerifyFileSystem : public XrdSfsFileSystem {
   public:
    XrdSfsDirectory* newDir(char* user = 0, int monid = 0) override;

    XrdSfsDirectory* newDir(XrdOucErrInfo& einfo) override;

    XrdSfsFile* newFile(char* user = 0, int monid = 0) override;

    XrdSfsFile* newFile(XrdOucErrInfo& einfo) override;

    int chksum(csFunc Func, const char* csName, const char* path, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0,
               const char* opaque = 0) override;

    int chmod(const char* path, XrdSfsMode mode, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0,
              const char* opaque = 0) override;

    void Connect(const XrdSecEntity* client = 0) override;

    void Disc(const XrdSecEntity* client = 0) override;

    void EnvInfo(XrdOucEnv* envP) override;

    int exists(const char* path, XrdSfsFileExistence& eFlag, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0,
               const char* opaque = 0) override;

    int FAttr(XrdSfsFACtl* faReq, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0) override;

    int FSctl(const int cmd, XrdSfsFSctl& args, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0) override;

    int fsctl(const int cmd, const char* args, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0) override;

    int getChkPSize() override;

    int getStats(char* buff, int blen) override;

    const char* getVersion() override;

    int gpFile(gpfFunc& gpAct, XrdSfsGPFile& gpReq, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0) override;

    int mkdir(const char* path, XrdSfsMode mode, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0,
              const char* opaque = 0) override;

    int prepare(XrdSfsPrep& pargs, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0) override;

    int rem(const char* path, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0, const char* opaque = 0) override;

    int remdir(const char* path, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0, const char* opaque = 0) override;

    int rename(const char* oPath, const char* nPath, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0,
               const char* opaqueO = 0, const char* opaqueN = 0) override;

    int stat(const char* Name, struct stat* buf, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0,
             const char* opaque = 0) override;

    int stat(const char* path, mode_t& mode, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0,
             const char* opaque = 0) override;

    int truncate(const char* path, XrdSfsFileOffset fsize, XrdOucErrInfo& eInfo, const XrdSecEntity* client = 0,
                 const char* opaque = 0) override;

    OpenVerifyFileSystem(XrdSfsFileSystem* nativeFS, XrdSysLogger* Logger, const char* configFn, XrdOucEnv* envP)
        : m_next_sfs(nativeFS), m_log(0, "ofs_plugin"), m_config(configFn), m_env(envP) {
        m_log.logger(Logger);
        m_log.Emsg("ERR:: ", "*** XrdOfsOpenVerify Initialised ****");
    }

    XrdSfsFileSystem* m_next_sfs;
    XrdSysError m_log;
    const char* m_config;
    XrdOucEnv* m_env;
};

class OpenVerifyFile : public XrdSfsFile {
   public:
    int open(const char* fileName, XrdSfsFileOpenMode openMode, mode_t createMode, const XrdSecEntity* client,
             const char* opaque = 0) override;

    int close() override;

    int checkpoint(cpAct act, struct iov* range = 0, int n = 0) override;

    int fctl(const int cmd, const char* args, XrdOucErrInfo& out_error) override;

    const char* FName() override;

    int getMmap(void** Addr, off_t& Size) override;

    XrdSfsXferSize pgRead(XrdSfsFileOffset offset, char* buffer, XrdSfsXferSize rdlen, uint32_t* csvec,
                          uint64_t opts = 0) override;

    XrdSfsXferSize pgRead(XrdSfsAio* aioparm, uint64_t opts = 0) override;

    XrdSfsXferSize pgWrite(XrdSfsFileOffset offset, char* buffer, XrdSfsXferSize rdlen, uint32_t* csvec,
                           uint64_t opts = 0) override;

    XrdSfsXferSize pgWrite(XrdSfsAio* aioparm, uint64_t opts = 0) override;

    int read(XrdSfsFileOffset fileOffset, XrdSfsXferSize amount) override;

    XrdSfsXferSize read(XrdSfsFileOffset fileOffset, char* buffer, XrdSfsXferSize buffer_size) override;

    int read(XrdSfsAio* aioparm) override;

    XrdSfsXferSize write(XrdSfsFileOffset fileOffset, const char* buffer, XrdSfsXferSize buffer_size) override;

    int write(XrdSfsAio* aioparm) override;

    int sync() override;

    int sync(XrdSfsAio* aiop) override;

    int stat(struct stat* buf) override;

    int truncate(XrdSfsFileOffset fileOffset) override;

    int getCXinfo(char cxtype[4], int& cxrsz) override;

    int SendData(XrdSfsDio* sfDio, XrdSfsFileOffset offset, XrdSfsXferSize size) override;

    OpenVerifyFile(XrdSfsFile* wrapF, XrdSysError& log) : XrdSfsFile(wrapF->error), m_wrapped(wrapF), m_log(log) {}
    ~OpenVerifyFile();

    XrdSfsFile* m_wrapped;
    XrdSysError& m_log;

   private:
    bool open_verify();
};

#endif