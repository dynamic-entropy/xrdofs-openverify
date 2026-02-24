#include <chrono>
#include <string>

#include "OpenVerifyCacheKey.hh"
#include "XrdOfsOpenVerify.hh"

namespace {
bool ShouldBypassOpenVerify(const XrdSfsFileOpenMode openMode) {
    constexpr int kAccessModeMask = 0x3;
    const int accessMode = (openMode & kAccessModeMask);
    const bool writeAccess = (accessMode == SFS_O_WRONLY || accessMode == SFS_O_RDWR);
    const bool createOrTruncate = (openMode & SFS_O_CREAT) || (openMode & SFS_O_CREATAT) || (openMode & SFS_O_TRUNC);
    return writeAccess || createOrTruncate;
}
}  // namespace

OpenVerifyFile::~OpenVerifyFile() { m_log.Emsg(" INFO", "FileWrapper::~FileWrapper"); }

int OpenVerifyFile::open(const char* fileName, XrdSfsFileOpenMode openMode, mode_t createMode,
                         const XrdSecEntity* client, const char* opaque) {
    m_log.Emsg(" INFO", "FileWrapper::open");

    // PUT/CREATE-style requests should not go through open-verify.
    if (ShouldBypassOpenVerify(openMode)) {
        m_log.Emsg(" INFO", "Skipping open-verify for write/create open mode");
        return m_wrapped->open(fileName, openMode, createMode, client, opaque);
    }

    int rc = 0;
    std::string tried_hosts;
    int retry_count{0}, max_retries{3};
    bool retry = true;

    while (retry && retry_count < max_retries) {
        // if max_retries exhausts and open_verify fail on all of them
        // currently we return the last redirect, thus only performing a best effort verify
        // another approach is we change this and return SFS_ERROR instead

        std::string opaque_str = opaque ? opaque : "";
        if (!tried_hosts.empty()) {
            if (opaque_str.empty()) {
                opaque_str = "tried=" + tried_hosts;
            } else {
                size_t tried_pos = opaque_str.find("tried=");
                if (tried_pos != std::string::npos) {
                    size_t end_pos = opaque_str.find('&', tried_pos);
                    if (end_pos == std::string::npos) {
                        opaque_str += "," + tried_hosts;
                    } else {
                        opaque_str.insert(end_pos, "," + tried_hosts);
                    }
                } else {
                    opaque_str += "&tried=" + tried_hosts;
                }
            }
        }

        m_log.Emsg("INFO", "Retrying with opaque = ", opaque_str.c_str());

        rc = m_wrapped->open(fileName, openMode, createMode, client, opaque_str.c_str());
        m_log.Emsg("INFO", "returned from open with rc =", std::to_string(rc).c_str(), "\n");

        if (rc > 0){
            // sleep for rc seconds and try again
            sleep(rc);
            m_log.Emsg("INFO", "slept for rc seconds; retrying \n");
            continue;
        }
        retry_count++;

        if (rc != SFS_REDIRECT) break;

        int port;
        const char* host = m_wrapped->error.getErrText(port);
        const std::string hostStr = host ? host : "";
        const int portVal = (port >= 0) ? port : -1;

        const std::string hostPort = (port < 0) ? hostStr : (hostStr + ":" + std::to_string(port));
        m_log.Emsg(" INFO", "redirecting to", hostPort.c_str());

        const std::string pathStr = fileName ? fileName : "";
        const auto key = MakeOpenVerifyCacheKey(pathStr, hostStr, portVal);
        const auto cached = m_cache.Get(key);

        switch (cached) {
            case OpenVerifyCache::Status::Miss: {
                m_log.Emsg(" INFO", "openverify cache miss for", key.c_str());
                // call open verify and cache the result for a postive or negative entry
                // if fails populate the cache as a negative entry for path -> server and with a short ttl - 15
                // seconds if works populate the cache as a positve entry for path -> server with a relatively
                // larger ttl - 120
                if (open_verify(key, opaque_str.c_str(), client)) {
                    m_cache.PutPositive(key, std::chrono::seconds(120));
                    retry = false;
                    m_log.Emsg(" INFO", "openverify succeeded for", key.c_str());
                } else {
                    m_cache.PutNegative(key, std::chrono::seconds(15));
                    tried_hosts = tried_hosts.empty() ? hostPort : tried_hosts + "," + hostPort;
                    m_log.Emsg(" WARN", "openverify failed for", key.c_str());
                }
                break;
            }
            case OpenVerifyCache::Status::Positive:
                m_log.Emsg(" INFO", "openverify succeeded (cached) for", key.c_str());
                retry = false;
                break;
            case OpenVerifyCache::Status::Negative:
                tried_hosts = tried_hosts.empty() ? hostPort : tried_hosts + "," + hostPort;
                m_log.Emsg(" WARN", "openverify failed (cached) for", key.c_str());
                break;
        }
    }

    return rc;
}

// Need to think how to handle these other return states
// #define SFS_STALL         1 // Return value -> Seconds to stall client
// #define SFS_OK            0 // ErrInfo code -> All is well
// #define SFS_ERROR        -1 // ErrInfo code -> Error occurred
// #define SFS_REDIRECT   -256 // ErrInfo code -> Port number to redirect to
// #define SFS_STARTED    -512 // ErrInfo code -> Estimated seconds to completion
// #define SFS_DATA      -1024 // ErrInfo code -> Length of data
// #define SFS_DATAVEC   -2048 // ErrInfo code -> Num iovec elements in msgbuff


int OpenVerifyFile::close() {
    m_log.Emsg(" INFO", "FileWrapper::close");
    return m_wrapped->close();
}

int OpenVerifyFile::checkpoint(cpAct act, struct iov* range, int n) {
    m_log.Emsg(" INFO", "FileWrapper::checkpoint");
    return m_wrapped->checkpoint(act, range, n);
}

int OpenVerifyFile::fctl(const int cmd, const char* args, XrdOucErrInfo& out_error) {
    m_log.Emsg(" INFO", "FileWrapper::fctl");
    return m_wrapped->fctl(cmd, args, out_error);
}

const char* OpenVerifyFile::FName() {
    m_log.Emsg(" INFO", "FileWrapper::FName");
    return m_wrapped->FName();
}

int OpenVerifyFile::getMmap(void** Addr, off_t& Size) {
    m_log.Emsg(" INFO", "FileWrapper::getMmap");
    return m_wrapped->getMmap(Addr, Size);
}

XrdSfsXferSize OpenVerifyFile::pgRead(XrdSfsFileOffset offset, char* buffer, XrdSfsXferSize rdlen, uint32_t* csvec,
                                      uint64_t opts) {
    m_log.Emsg(" INFO", "FileWrapper::pgRead(offset, buffer)");
    return m_wrapped->pgRead(offset, buffer, rdlen, csvec, opts);
}

XrdSfsXferSize OpenVerifyFile::pgRead(XrdSfsAio* aioparm, uint64_t opts) {
    m_log.Emsg(" INFO", "FileWrapper::pgRead(aioparm)");
    return m_wrapped->pgRead(aioparm, opts);
}

XrdSfsXferSize OpenVerifyFile::pgWrite(XrdSfsFileOffset offset, char* buffer, XrdSfsXferSize rdlen, uint32_t* csvec,
                                       uint64_t opts) {
    m_log.Emsg(" INFO", "FileWrapper::pgWrite(offset, buffer)");
    return m_wrapped->pgWrite(offset, buffer, rdlen, csvec, opts);
}

XrdSfsXferSize OpenVerifyFile::pgWrite(XrdSfsAio* aioparm, uint64_t opts) {
    m_log.Emsg(" INFO", "FileWrapper::pgWrite(aioparm)");
    return m_wrapped->pgWrite(aioparm, opts);
}

int OpenVerifyFile::read(XrdSfsFileOffset fileOffset, XrdSfsXferSize amount) {
    m_log.Emsg(" INFO", "FileWrapper::read(offset, amount)");
    return m_wrapped->read(fileOffset, amount);
}

XrdSfsXferSize OpenVerifyFile::read(XrdSfsFileOffset fileOffset, char* buffer, XrdSfsXferSize buffer_size) {
    m_log.Emsg(" INFO", "FileWrapper::read(offset, buffer)");
    return m_wrapped->read(fileOffset, buffer, buffer_size);
}

int OpenVerifyFile::read(XrdSfsAio* aioparm) {
    m_log.Emsg(" INFO", "FileWrapper::read(aioparm)");
    return m_wrapped->read(aioparm);
}

XrdSfsXferSize OpenVerifyFile::write(XrdSfsFileOffset fileOffset, const char* buffer, XrdSfsXferSize buffer_size) {
    m_log.Emsg(" INFO", "FileWrapper::write(offset, buffer)");
    return m_wrapped->write(fileOffset, buffer, buffer_size);
}

int OpenVerifyFile::write(XrdSfsAio* aioparm) {
    m_log.Emsg(" INFO", "FileWrapper::write(aioparm)");
    return m_wrapped->write(aioparm);
}

int OpenVerifyFile::sync() {
    m_log.Emsg(" INFO", "FileWrapper::sync");
    return m_wrapped->sync();
}

int OpenVerifyFile::sync(XrdSfsAio* aiop) {
    m_log.Emsg(" INFO", "FileWrapper::sync(aiop)");
    return m_wrapped->sync(aiop);
}

int OpenVerifyFile::stat(struct stat* buf) {
    m_log.Emsg(" INFO", "FileWrapper::stat");
    return m_wrapped->stat(buf);
}

int OpenVerifyFile::truncate(XrdSfsFileOffset fileOffset) {
    m_log.Emsg(" INFO", "FileWrapper::truncate");
    return m_wrapped->truncate(fileOffset);
}

int OpenVerifyFile::getCXinfo(char cxtype[4], int& cxrsz) {
    m_log.Emsg(" INFO", "FileWrapper::getCXinfo");
    return m_wrapped->getCXinfo(cxtype, cxrsz);
}

int OpenVerifyFile::SendData(XrdSfsDio* sfDio, XrdSfsFileOffset offset, XrdSfsXferSize size) {
    m_log.Emsg(" INFO", "FileWrapper::SendData");
    return m_wrapped->SendData(sfDio, offset, size);
}
