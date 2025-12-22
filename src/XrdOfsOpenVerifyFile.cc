#include <string>

#include "XrdOfsOpenVerify.hh"

OpenVerifyFile::~OpenVerifyFile() { m_log.Emsg(" INFO", "FileWrapper::~FileWrapper"); }

int OpenVerifyFile::open(const char* fileName, XrdSfsFileOpenMode openMode, mode_t createMode,
                         const XrdSecEntity* client, const char* opaque) {
    m_log.Emsg(" INFO", "FileWrapper::open");

    int rc = m_wrapped->open(fileName, openMode, createMode, client, opaque);
    open_verify();

    return rc;
}

bool OpenVerifyFile::open_verify() {
    // use xrdcl client to read?
    return true;  // on success
}

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
