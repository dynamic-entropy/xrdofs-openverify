#include "OpenVerifyRucioCurlPool.hh"

#include <cstdlib>
#include <mutex>

namespace {

constexpr std::size_t kMaxPoolSize = 256;
// Same default as OpenVerifySingleFlight (XRD_OPENVERIFY_MAX_INFLIGHT).
constexpr int kDefaultMaxInflight = 32;

void EnsureCurlGlobalInit() {
    static std::once_flag once;
    std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

std::size_t ClampPoolSize(long v) {
    if (v < 1) return 1;
    if (v > static_cast<long>(kMaxPoolSize)) return kMaxPoolSize;
    return static_cast<std::size_t>(v);
}

int PositiveEnvOrDefault(const char* name, int dflt) {
    const char* p = std::getenv(name);
    if (!p || !*p) return dflt;
    const int v = std::atoi(p);
    return v > 0 ? v : dflt;
}

}  // namespace

std::size_t OpenVerifyRucioPoolSizeFromEnv() {
    const char* p = std::getenv("XRD_OPENVERIFY_RUCIO_POOL_SIZE");
    if (p && *p) {
        return ClampPoolSize(std::strtol(p, nullptr, 10));
    }
    // Locate runs before the verify FIFO; keep Rucio HTTPS as parallel as
    // admitted probes so pool wait does not starve MAX_INFLIGHT slots.
    return ClampPoolSize(PositiveEnvOrDefault("XRD_OPENVERIFY_MAX_INFLIGHT", kDefaultMaxInflight));
}

OpenVerifyRucioCurlPool::Handle::Handle(OpenVerifyRucioCurlPool* pool, CURL* easy) : m_pool(pool), m_easy(easy) {}

OpenVerifyRucioCurlPool::Handle::~Handle() {
    if (m_pool && m_easy) m_pool->Release(m_easy);
}

OpenVerifyRucioCurlPool::Handle::Handle(Handle&& other) noexcept : m_pool(other.m_pool), m_easy(other.m_easy) {
    other.m_pool = nullptr;
    other.m_easy = nullptr;
}

OpenVerifyRucioCurlPool::Handle& OpenVerifyRucioCurlPool::Handle::operator=(Handle&& other) noexcept {
    if (this != &other) {
        if (m_pool && m_easy) m_pool->Release(m_easy);
        m_pool = other.m_pool;
        m_easy = other.m_easy;
        other.m_pool = nullptr;
        other.m_easy = nullptr;
    }
    return *this;
}

OpenVerifyRucioCurlPool::OpenVerifyRucioCurlPool(std::size_t size) {
    EnsureCurlGlobalInit();

    m_share = curl_share_init();
    if (m_share) {
        curl_share_setopt(m_share, CURLSHOPT_LOCKFUNC, ShareLock);
        curl_share_setopt(m_share, CURLSHOPT_UNLOCKFUNC, ShareUnlock);
        curl_share_setopt(m_share, CURLSHOPT_USERDATA, static_cast<void*>(m_share_locks));
        curl_share_setopt(m_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
        curl_share_setopt(m_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
        curl_share_setopt(m_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
    }

    const std::size_t want = size < 1 ? 1 : size;
    m_size = want;
    m_idle.reserve(want);
    for (std::size_t i = 0; i < want; ++i) {
        CURL* easy = curl_easy_init();
        if (!easy) continue;
        ApplyPooledOptions(easy);
        m_idle.push_back(easy);
    }
    m_size = m_idle.size();
}

OpenVerifyRucioCurlPool::~OpenVerifyRucioCurlPool() {
    {
        std::unique_lock<std::mutex> lock(m_mu);
        m_stopping = true;
        m_cv.notify_all();
        m_cv.wait(lock, [this] { return m_checked_out == 0; });
    }
    for (CURL* easy : m_idle) {
        if (m_share) curl_easy_setopt(easy, CURLOPT_SHARE, nullptr);
        curl_easy_cleanup(easy);
    }
    m_idle.clear();
    if (m_share) {
        curl_share_cleanup(m_share);
        m_share = nullptr;
    }
}

void OpenVerifyRucioCurlPool::ApplyPooledOptions(CURL* easy) {
    if (m_share) curl_easy_setopt(easy, CURLOPT_SHARE, m_share);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPIDLE, 30L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPINTVL, 15L);
    // Auth host + REST host, plus one spare per pooled handle.
    curl_easy_setopt(easy, CURLOPT_MAXCONNECTS, static_cast<long>(m_size + 2));
}

OpenVerifyRucioCurlPool::Handle OpenVerifyRucioCurlPool::Acquire() {
    CURL* easy = nullptr;
    {
        std::unique_lock<std::mutex> lock(m_mu);
        if (m_size == 0) return {};
        m_cv.wait(lock, [this] { return m_stopping || !m_idle.empty(); });
        if (m_stopping || m_idle.empty()) return {};
        easy = m_idle.back();
        m_idle.pop_back();
        ++m_checked_out;
    }
    curl_easy_reset(easy);
    ApplyPooledOptions(easy);
    return Handle(this, easy);
}

void OpenVerifyRucioCurlPool::Release(CURL* easy) {
    if (!easy) return;
    std::lock_guard<std::mutex> lock(m_mu);
    m_idle.push_back(easy);
    if (m_checked_out > 0) --m_checked_out;
    m_cv.notify_one();
}

std::size_t OpenVerifyRucioCurlPool::IdleCount() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_idle.size();
}

void OpenVerifyRucioCurlPool::ShareLock(CURL* /*handle*/, curl_lock_data data, curl_lock_access /*access*/,
                                       void* userptr) {
    if (data <= CURL_LOCK_DATA_NONE || data >= CURL_LOCK_DATA_LAST) return;
    static_cast<std::mutex*>(userptr)[data].lock();
}

void OpenVerifyRucioCurlPool::ShareUnlock(CURL* /*handle*/, curl_lock_data data, void* userptr) {
    if (data <= CURL_LOCK_DATA_NONE || data >= CURL_LOCK_DATA_LAST) return;
    static_cast<std::mutex*>(userptr)[data].unlock();
}
