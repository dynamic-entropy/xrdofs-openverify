#include "OpenVerifyRucioCurlPool.hh"

#include <cstdlib>
#include <mutex>
#include <utility>

namespace {

constexpr std::size_t kDefaultMin = 50;
constexpr std::size_t kDefaultMax = 500;
constexpr std::size_t kHardMax = 500;
// Drop idle keep-alives before typical front-end/NAT idle timeouts so reuse
// does not stall on a half-closed socket until CURLOPT_TIMEOUT (10s).
constexpr long kMaxIdleConnSeconds = 15;

void EnsureCurlGlobalInit() {
    static std::once_flag once;
    std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

std::size_t ClampRange(long v, std::size_t lo, std::size_t hi) {
    if (v < static_cast<long>(lo)) return lo;
    if (v > static_cast<long>(hi)) return hi;
    return static_cast<std::size_t>(v);
}

bool EnvSet(const char* name) {
    const char* p = std::getenv(name);
    return p && *p;
}

long EnvLong(const char* name, long dflt) {
    const char* p = std::getenv(name);
    if (!p || !*p) return dflt;
    return std::strtol(p, nullptr, 10);
}

}  // namespace

OpenVerifyRucioCurlPoolConfig OpenVerifyRucioCurlPoolConfig::FromEnv() {
    OpenVerifyRucioCurlPoolConfig cfg;
    long min_v = kDefaultMin;
    if (EnvSet("XRD_OPENVERIFY_RUCIO_POOL_MIN")) {
        min_v = EnvLong("XRD_OPENVERIFY_RUCIO_POOL_MIN", static_cast<long>(kDefaultMin));
    } else if (EnvSet("XRD_OPENVERIFY_RUCIO_POOL_SIZE")) {
        min_v = EnvLong("XRD_OPENVERIFY_RUCIO_POOL_SIZE", static_cast<long>(kDefaultMin));
    }
    cfg.min_handles = ClampRange(min_v, 1, kHardMax);

    long max_v = kDefaultMax;
    if (EnvSet("XRD_OPENVERIFY_RUCIO_POOL_MAX")) {
        max_v = EnvLong("XRD_OPENVERIFY_RUCIO_POOL_MAX", static_cast<long>(kDefaultMax));
    }
    cfg.max_handles = ClampRange(max_v, 1, kHardMax);
    if (cfg.max_handles < cfg.min_handles) cfg.max_handles = cfg.min_handles;
    return cfg;
}

OpenVerifyRucioCurlPool::Handle::Handle(OpenVerifyRucioCurlPool* pool, CURL* easy, bool reused)
    : m_pool(pool), m_easy(easy), m_reused(reused) {}

OpenVerifyRucioCurlPool::Handle::~Handle() {
    if (m_pool && m_easy) m_pool->Release(m_easy);
}

OpenVerifyRucioCurlPool::Handle::Handle(Handle&& other) noexcept
    : m_pool(other.m_pool), m_easy(other.m_easy), m_reused(other.m_reused) {
    other.m_pool = nullptr;
    other.m_easy = nullptr;
    other.m_reused = false;
}

OpenVerifyRucioCurlPool::Handle& OpenVerifyRucioCurlPool::Handle::operator=(Handle&& other) noexcept {
    if (this != &other) {
        if (m_pool && m_easy) m_pool->Release(m_easy);
        m_pool = other.m_pool;
        m_easy = other.m_easy;
        m_reused = other.m_reused;
        other.m_pool = nullptr;
        other.m_easy = nullptr;
        other.m_reused = false;
    }
    return *this;
}

OpenVerifyRucioCurlPool::OpenVerifyRucioCurlPool(OpenVerifyRucioCurlPoolConfig cfg)
    : m_min(cfg.min_handles < 1 ? 1 : cfg.min_handles),
      m_max(cfg.max_handles < m_min ? m_min : cfg.max_handles),
      m_shrink_idle(cfg.shrink_idle) {
    InitShareAndWarm();
}

OpenVerifyRucioCurlPool::OpenVerifyRucioCurlPool(std::size_t min_handles, std::size_t max_handles,
                                                std::chrono::milliseconds shrink_idle)
    : OpenVerifyRucioCurlPool(OpenVerifyRucioCurlPoolConfig{min_handles < 1 ? 1 : min_handles,
                                                           max_handles < 1 ? 1 : max_handles, shrink_idle}) {}

void OpenVerifyRucioCurlPool::InitShareAndWarm() {
    EnsureCurlGlobalInit();

    m_share = curl_share_init();
    if (m_share) {
        curl_share_setopt(m_share, CURLSHOPT_LOCKFUNC, ShareLock);
        curl_share_setopt(m_share, CURLSHOPT_UNLOCKFUNC, ShareUnlock);
        curl_share_setopt(m_share, CURLSHOPT_USERDATA, static_cast<void*>(m_share_locks));
        curl_share_setopt(m_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
        curl_share_setopt(m_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
        // Do not share CURL_LOCK_DATA_CONNECT: concurrent easy handles to the
        // same host serialize on that lock, and HTTP/1.1 cannot multiplex.
        // Each pooled handle keeps its own connection cache across reset.
    }

    const auto now = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < m_min; ++i) {
        CURL* easy = curl_easy_init();
        if (!easy) break;
        ApplyPooledOptions(easy);
        m_idle.push_back(IdleSlot{easy, now});
        ++m_created;
    }
    if (m_created < m_min) m_min = m_created;
    if (m_max < m_min) m_max = m_min;
}

OpenVerifyRucioCurlPool::~OpenVerifyRucioCurlPool() {
    {
        std::unique_lock<std::mutex> lock(m_mu);
        m_stopping = true;
        m_cv.notify_all();
        m_cv.wait(lock, [this] { return m_checked_out == 0; });
    }
    for (auto& slot : m_idle) DestroyEasy(slot.easy);
    m_idle.clear();
    m_created = 0;
    if (m_share) {
        curl_share_cleanup(m_share);
        m_share = nullptr;
    }
}

void OpenVerifyRucioCurlPool::DestroyEasy(CURL* easy) {
    if (!easy) return;
    if (m_share) curl_easy_setopt(easy, CURLOPT_SHARE, nullptr);
    curl_easy_cleanup(easy);
}

void OpenVerifyRucioCurlPool::ApplyPooledOptions(CURL* easy) {
    if (m_share) curl_easy_setopt(easy, CURLOPT_SHARE, m_share);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPIDLE, 10L);
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPINTVL, 10L);
    curl_easy_setopt(easy, CURLOPT_MAXCONNECTS, 4L);
#if LIBCURL_VERSION_NUM >= 0x074100
    curl_easy_setopt(easy, CURLOPT_MAXAGE_CONN, kMaxIdleConnSeconds);
#endif
}

void OpenVerifyRucioCurlPool::ShrinkIdleLocked(std::chrono::steady_clock::time_point now) {
    while (m_created > m_min && !m_idle.empty()) {
        const auto& oldest = m_idle.front();
        if (m_shrink_idle.count() > 0 && (now - oldest.idle_since) < m_shrink_idle) break;
        CURL* easy = oldest.easy;
        m_idle.pop_front();
        --m_created;
        ++m_shrinks;
        DestroyEasy(easy);
    }
}

OpenVerifyRucioCurlPool::Handle OpenVerifyRucioCurlPool::Acquire() {
    CURL* easy = nullptr;
    bool grew = false;
    {
        std::unique_lock<std::mutex> lock(m_mu);
        const auto now = std::chrono::steady_clock::now();
        ShrinkIdleLocked(now);
        while (!m_stopping && m_idle.empty() && m_created >= m_max) {
            m_cv.wait(lock);
        }
        if (m_stopping) return {};
        if (!m_idle.empty()) {
            easy = m_idle.back().easy;
            m_idle.pop_back();
            ++m_checked_out;
        } else if (m_created < m_max) {
            ++m_created;
            ++m_checked_out;
            ++m_grows;
            grew = true;
        } else {
            return {};
        }
    }

    if (grew) {
        easy = curl_easy_init();
        if (!easy) {
            std::lock_guard<std::mutex> lock(m_mu);
            if (m_created > 0) --m_created;
            if (m_checked_out > 0) --m_checked_out;
            if (m_grows > 0) --m_grows;
            m_cv.notify_all();
            return {};
        }
        ApplyPooledOptions(easy);
        return Handle(this, easy, /*reused=*/false);
    }

    curl_easy_reset(easy);
    ApplyPooledOptions(easy);
    return Handle(this, easy, /*reused=*/true);
}

void OpenVerifyRucioCurlPool::Release(CURL* easy) {
    if (!easy) return;
    std::unique_lock<std::mutex> lock(m_mu);
    if (m_checked_out > 0) --m_checked_out;
    const auto now = std::chrono::steady_clock::now();
    if (m_created > m_min && m_shrink_idle.count() == 0) {
        --m_created;
        ++m_shrinks;
        lock.unlock();
        DestroyEasy(easy);
        m_cv.notify_all();
        return;
    }
    m_idle.push_back(IdleSlot{easy, now});
    ShrinkIdleLocked(now);
    m_cv.notify_all();
}

std::size_t OpenVerifyRucioCurlPool::Size() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_created;
}

std::size_t OpenVerifyRucioCurlPool::IdleCount() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_idle.size();
}

std::size_t OpenVerifyRucioCurlPool::InflightCount() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_checked_out;
}

OpenVerifyRucioCurlPool::Stats OpenVerifyRucioCurlPool::GetStats() const {
    std::lock_guard<std::mutex> lock(m_mu);
    Stats s;
    s.handles = m_created;
    s.idle = m_idle.size();
    s.inflight = m_checked_out;
    s.grows = m_grows;
    s.shrinks = m_shrinks;
    return s;
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
