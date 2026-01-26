#include <array>
#include <cstdint>
#include <string>

#include "XrdCl/XrdClFile.hh"
#include "XrdCl/XrdClXRootDResponses.hh"
#include "XrdOfsOpenVerify.hh"

namespace {
std::string MakeXrdClUrlFromKeyAndOpaque(const std::string& key, const char* opaque) {
    // `key` format: <host>[:<port>]/<path>
    std::string url = "root://";
    url += key;

    if (opaque && *opaque) {
        url.push_back('?');
        if (*opaque == '?') {
            url.append(opaque + 1);
        } else {
            url.append(opaque);
        }
    }

    return url;
}
}  // namespace

bool OpenVerifyFile::open_verify(const std::string& key, const char* opaque) {
    // Use XrdCl to open the file and read the first and last byte
    // If the read fails, return false
    // If the read succeeds, return true

    const auto slashPos = key.find('/');
    if (slashPos == std::string::npos || slashPos == 0) {
        m_log.Emsg(" WARN", "openverify invalid key (missing host/path):", key.c_str());
        return false;
    }

    const std::string url = MakeXrdClUrlFromKeyAndOpaque(key, opaque);

    XrdCl::File f;
    auto st = f.Open(url, XrdCl::OpenFlags::Read);
    if (!st.IsOK()) {
        const std::string msg = st.ToString();
        m_log.Emsg(" WARN", "openverify XrdCl open failed for", url.c_str(), msg.c_str());
        return false;
    }

    XrdCl::StatInfo* statInfo = nullptr;
    st = f.Stat(false, statInfo);
    if (!st.IsOK() || !statInfo) {
        const std::string msg = st.ToString();
        m_log.Emsg(" WARN", "openverify XrdCl stat failed for", url.c_str(), msg.c_str());
        auto closeSt = f.Close();
        (void)closeSt;
        return false;
    }

    const uint64_t size = statInfo->GetSize();
    delete statInfo;
    statInfo = nullptr;

    if (size == 0) {
        // Empty file: treat as failure
        auto closeSt = f.Close();
        (void)closeSt;
        return false;
    }

    XrdCl::ChunkList chunks;
    const uint32_t totalLen = (size == 1) ? 1u : 2u;
    chunks.reserve(totalLen);

    std::array<char, 2> buf{};
    chunks.emplace_back(0, 1, nullptr);
    if (size > 1) {
        chunks.emplace_back(size - 1, 1, nullptr);
    }

    XrdCl::VectorReadInfo* vri = nullptr;
    st = f.VectorRead(chunks, buf.data(), vri);
    if (vri) {
        delete vri;
        vri = nullptr;
    }

    if (!st.IsOK()) {
        const std::string msg = st.ToString();
        m_log.Emsg(" WARN", "openverify XrdCl vector read failed for", url.c_str(), msg.c_str());
        auto closeSt = f.Close();
        (void)closeSt;
        return false;
    }

    auto closeSt = f.Close();
    (void)closeSt;
    return true;
}
