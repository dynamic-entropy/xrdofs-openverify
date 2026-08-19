#include "OpenVerifyRucioListCache.hh"

#include <cctype>
#include <cstdlib>
#include <cstring>

namespace {

long EnvLongAllowZero(const char* name, long def) {
    const char* p = std::getenv(name);
    if (!p || !*p) return def;
    char* end = nullptr;
    const long v = std::strtol(p, &end, 10);
    if (end == p) return def;
    return v >= 0 ? v : def;
}

std::string TrimCopy(const std::string& s) {
    size_t a = 0;
    size_t b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

// Collapse leading slashes to one; drop a trailing slash except for "/".
std::string NormalizeLfn(const std::string& raw) {
    const std::string t = TrimCopy(raw);
    if (t.empty()) return {};
    size_t start = 0;
    while (start < t.size() && t[start] == '/') ++start;
    std::string out = "/" + t.substr(start);
    while (out.size() > 1 && out.back() == '/') out.pop_back();
    return out;
}

}  // namespace

OpenVerifyRucioListCacheConfig OpenVerifyRucioListCacheConfig::FromEnv() {
    OpenVerifyRucioListCacheConfig cfg;
    cfg.ttl = std::chrono::seconds(EnvLongAllowZero("XRD_OPENVERIFY_RUCIO_CACHE_TTL", 60));
    const long n = EnvLongAllowZero("XRD_OPENVERIFY_RUCIO_CACHE_SIZE", 8192);
    cfg.max_entries = static_cast<std::size_t>(n);
    return cfg;
}

OpenVerifyRucioListCache::OpenVerifyRucioListCache(OpenVerifyRucioListCacheConfig cfg)
    : m_ttl(cfg.ttl), m_max_entries(cfg.max_entries) {}

OpenVerifyRucioListCache::Key OpenVerifyRucioListCache::MakeKey(const std::string& lfn, const std::string& scheme) {
    Key k;
    k.scheme = OpenVerifyRucioNormalizeScheme(scheme);
    k.lfn = NormalizeLfn(lfn);
    return k;
}

OpenVerifyRucioListCache::Lookup OpenVerifyRucioListCache::Get(const std::string& lfn, const std::string& scheme,
                                                              std::chrono::steady_clock::time_point now) {
    Lookup out;
    if (!Enabled()) return out;

    const Key key = MakeKey(lfn, scheme);
    if (key.lfn.empty() || key.scheme.empty()) return out;

    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_map.find(key);
    if (it == m_map.end()) return out;
    if (now >= it->second.first.expiry) {
        m_lru.erase(it->second.second);
        m_map.erase(it);
        return out;
    }

    m_lru.splice(m_lru.begin(), m_lru, it->second.second);
    it->second.second = m_lru.begin();

    out.hit = true;
    out.status = it->second.first.status;
    out.candidates = it->second.first.candidates;
    return out;
}

void OpenVerifyRucioListCache::Put(const std::string& lfn, const std::string& scheme,
                                   OpenVerifyRucioLookupResult status,
                                   const std::vector<OpenVerifyRucioCandidate>& candidates,
                                   std::chrono::steady_clock::time_point now) {
    if (!Enabled()) return;
    if (status != OpenVerifyRucioLookupResult::Ok && status != OpenVerifyRucioLookupResult::Empty) {
        return;
    }

    const Key key = MakeKey(lfn, scheme);
    if (key.lfn.empty() || key.scheme.empty()) return;

    Entry e;
    e.status = status;
    e.candidates = candidates;
    e.expiry = now + m_ttl;

    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_map.find(key);
    if (it != m_map.end()) {
        it->second.first = std::move(e);
        m_lru.splice(m_lru.begin(), m_lru, it->second.second);
        it->second.second = m_lru.begin();
        return;
    }

    m_lru.push_front(key);
    m_map.emplace(key, std::make_pair(std::move(e), m_lru.begin()));

    while (m_map.size() > m_max_entries && !m_lru.empty()) {
        const Key& victim = m_lru.back();
        m_map.erase(victim);
        m_lru.pop_back();
    }
}

std::size_t OpenVerifyRucioListCache::Size() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_map.size();
}

void OpenVerifyRucioListCache::Reset() {
    std::lock_guard<std::mutex> lock(m_mu);
    m_map.clear();
    m_lru.clear();
}
