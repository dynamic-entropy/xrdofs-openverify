#ifndef __XRDOFSOPENVERIFY_H_
#define __XRDOFSOPENVERIFY_H_

#include <ctime>
#include <memory>
#include <string>

#include "OpenVerifyCache.hh"
#include "OpenVerifyFailureLog.hh"
#include "OpenVerifyHostReliability.hh"
#include "OpenVerifyMetrics.hh"
#include "OpenVerifyRucio.hh"
#include "OpenVerifySingleFlight.hh"
#include "XrdCl/XrdClXRootDResponses.hh"
#include "XrdOuc/XrdOucErrInfo.hh"
#include "XrdSec/XrdSecEntity.hh"
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

    OpenVerifyFileSystem(XrdSfsFileSystem* nativeFS, XrdSysLogger* Logger, const char* configFn, XrdOucEnv* envP);

    XrdSfsFileSystem* m_next_sfs;
    XrdSysError m_log;
    const char* m_config;
    XrdOucEnv* m_env;
    OpenVerifyMetrics m_metrics;
    OpenVerifyCache m_cache;
    OpenVerifySingleFlight m_single_flight{m_metrics};
    OpenVerifyHostReliability m_host_reliability;
    OpenVerifyFailureLog m_failure_log;
    OpenVerifyRucio m_rucio;
    const bool m_observe;
    // When true, rewrite accepted SFS_REDIRECT host/port to the verified data server
    // (XRD_OPENVERIFY_DIRECT_SERVER=1). cmsd path only — do not use for EOS FSTs.
    const bool m_direct_server;

    std::string m_ov_cert;
    std::string m_ov_key;

   private:
    void Configure();
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

    OpenVerifyFile(std::unique_ptr<XrdSfsFile> wrapF, XrdSysError& log, OpenVerifyCache& cache,
                   OpenVerifyMetrics& metrics, OpenVerifySingleFlight& single_flight,
                   OpenVerifyHostReliability& host_reliability, OpenVerifyFailureLog& failure_log,
                   OpenVerifyRucio& rucio, bool observe, bool direct_server, std::string ov_cert,
                   std::string ov_key);
    ~OpenVerifyFile();

    std::unique_ptr<XrdSfsFile> m_wrapped;
    XrdSysError& m_log;
    OpenVerifyCache& m_cache;
    OpenVerifyMetrics& m_metrics;
    OpenVerifySingleFlight& m_single_flight;
    OpenVerifyHostReliability& m_host_reliability;
    OpenVerifyFailureLog& m_failure_log;
    OpenVerifyRucio& m_rucio;
    const bool m_observe;
    const bool m_direct_server;
    const std::string m_ov_cert;
    const std::string m_ov_key;

   private:
    // On success, optionally fills final_host/final_port with the data server XrdCl reached.
    // On failure, optionally fills fail_stage / protocol / probe_url (credential-free) for the
    // dedicated failure log.
    XrdCl::XRootDStatus open_verify(const std::string& key, const char* opaque, const XrdSecEntity* client,
                                    time_t timeout_seconds, std::string* final_host = nullptr,
                                    int* final_port = nullptr, std::string* fail_stage = nullptr,
                                    std::string* protocol = nullptr, std::string* probe_url = nullptr);

    void LogLiveVerifyFailure(const char* source, int attempt, const std::string& host, int port,
                              const std::string& path, const std::string& pfn, const XrdCl::XRootDStatus& st,
                              const std::string& fail_stage, const std::string& protocol,
                              const std::string& probe_url);
};

#endif