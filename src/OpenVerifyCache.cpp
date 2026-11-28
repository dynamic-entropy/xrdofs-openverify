#include "OpenVerifyCache.hh"

#include <cstdlib>

OpenVerifyCache::OpenVerifyCache(std::size_t max_entries) : m_max_entries(max_entries) {
    if (max_entries == 0) {
        m_max_entries = MaxFromEnv();
    }
}

std::size_t OpenVerifyCache::MaxFromEnv() {
    constexpr std::size_t kDefault = 65536;
    const char* p = std::getenv("XRD_OPENVERIFY_CACHE_MAX");
    if (!p || !*p) return kDefault;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(p, &end, 10);
    if (end == p || (end && *end != '\0')) return kDefault;
    return static_cast<std::size_t>(v);
}

OpenVerifyCache::~OpenVerifyCache() { StopExpiryThread(); }

void OpenVerifyCache::StartExpiryThread() {
    std::unique_lock lk(m_shutdown_lock);
    if (m_thread_started) {
        return;
    }
    m_thread_started = true;
    m_shutdown_requested = false;
    m_shutdown_complete = false;
    m_expiry_thread = std::thread(&OpenVerifyCache::ExpireThread, this);
}

void OpenVerifyCache::StopExpiryThread() {
    std::unique_lock lk(m_shutdown_lock);
    if (!m_thread_started) {
        return;
    }
    m_shutdown_requested = true;
    m_shutdown_requested_cv.notify_one();

    // Wait for thread to acknowledge shutdown.
    m_shutdown_complete_cv.wait(lk, [&] { return m_shutdown_complete; });

    lk.unlock();
    if (m_expiry_thread.joinable()) {
        m_expiry_thread.join();
    }

    lk.lock();
    m_thread_started = false;
}

std::string OpenVerifyCache::NormalizeKey(const std::string& key) {
    std::string out;
    out.reserve(key.size());
    size_t i = 0;
    while (i < key.size()) {
        while (i < key.size() && key[i] == '/') ++i;
        if (i >= key.size()) break;
        const size_t end = key.find('/', i);
        const size_t n = (end == std::string::npos) ? key.size() - i : end - i;
        if (!out.empty()) out.push_back('/');
        out.append(key, i, n);
        i = (end == std::string::npos) ? key.size() : end;
    }
    return out;
}

void OpenVerifyCache::EvictOverflowLocked() {
    if (m_max_entries == 0) return;
    while (m_map.size() > m_max_entries && !m_lru.empty()) {
        const std::string& victim = m_lru.back();
        m_map.erase(victim);
        m_lru.pop_back();
    }
}

OpenVerifyCache::Lookup OpenVerifyCache::Get(const std::string& key, std::chrono::steady_clock::time_point now) const {
    const std::string norm = NormalizeKey(key);
    const std::shared_lock lk(m_mutex);

    const auto it = m_map.find(norm);
    if (it == m_map.end() || now >= it->second.expiry) {
        return Lookup{};
    }

    Lookup out;
    out.status = it->second.status;
    if (out.status == Status::Positive) {
        out.final_host = it->second.final_host;
        out.final_port = it->second.final_port;
    }
    return out;
}

void OpenVerifyCache::PutPositive(const std::string& key, std::chrono::seconds ttl,
                                  std::chrono::steady_clock::time_point now) {
    PutPositive(key, ttl, std::string{}, -1, now);
}

void OpenVerifyCache::PutPositive(const std::string& key, std::chrono::seconds ttl, std::string final_host,
                                  int final_port, std::chrono::steady_clock::time_point now) {
    const std::string norm = NormalizeKey(key);
    if (norm.empty()) return;
    const std::unique_lock lk(m_mutex);
    auto it = m_map.find(norm);
    if (it != m_map.end()) {
        it->second.status = Status::Positive;
        it->second.expiry = now + ttl;
        it->second.final_host = std::move(final_host);
        it->second.final_port = final_port;
        m_lru.splice(m_lru.begin(), m_lru, it->second.lru_it);
        return;
    }
    m_lru.push_front(norm);
    Entry e;
    e.status = Status::Positive;
    e.expiry = now + ttl;
    e.final_host = std::move(final_host);
    e.final_port = final_port;
    e.lru_it = m_lru.begin();
    m_map.emplace(norm, std::move(e));
    EvictOverflowLocked();
}

void OpenVerifyCache::PutNegative(const std::string& key, std::chrono::seconds ttl,
                                  std::chrono::steady_clock::time_point now) {
    const std::string norm = NormalizeKey(key);
    if (norm.empty()) return;
    const std::unique_lock lk(m_mutex);
    auto it = m_map.find(norm);
    if (it != m_map.end()) {
        it->second.status = Status::Negative;
        it->second.expiry = now + ttl;
        it->second.final_host.clear();
        it->second.final_port = -1;
        m_lru.splice(m_lru.begin(), m_lru, it->second.lru_it);
        return;
    }
    m_lru.push_front(norm);
    Entry e;
    e.status = Status::Negative;
    e.expiry = now + ttl;
    e.final_port = -1;
    e.lru_it = m_lru.begin();
    m_map.emplace(norm, std::move(e));
    EvictOverflowLocked();
}

void OpenVerifyCache::Expire(std::chrono::steady_clock::time_point now) {
    const std::unique_lock lk(m_mutex);
    for (auto it = m_map.begin(); it != m_map.end();) {
        if (it->second.expiry <= now) {
            m_lru.erase(it->second.lru_it);
            it = m_map.erase(it);
        } else {
            ++it;
        }
    }
}

void OpenVerifyCache::Reset() {
    const std::unique_lock lk(m_mutex);
    m_map.clear();
    m_lru.clear();
}

void OpenVerifyCache::ExpireThread() {
    while (true) {
        {
            std::unique_lock lk(m_shutdown_lock);
            m_shutdown_requested_cv.wait_for(lk, std::chrono::seconds(5), [&] { return m_shutdown_requested; });
            if (m_shutdown_requested) {
                break;
            }
        }

        Expire(std::chrono::steady_clock::now());
    }

    std::unique_lock lk(m_shutdown_lock);
    m_shutdown_complete = true;
    m_shutdown_complete_cv.notify_one();
}
