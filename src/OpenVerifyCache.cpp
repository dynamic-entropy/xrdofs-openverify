#include "OpenVerifyCache.hh"

#include <functional>

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

std::vector<std::string> OpenVerifyCache::SplitPath(const std::string& path) {
    std::vector<std::string> segments;
    segments.reserve(8);

    size_t start = 0;
    while (start < path.size()) {
        // Skip repeated separators.
        while (start < path.size() && path[start] == '/') {
            ++start;
        }
        if (start >= path.size()) {
            break;
        }
        size_t end = path.find('/', start);
        if (end == std::string::npos) {
            end = path.size();
        }
        if (end > start) {
            segments.emplace_back(path.substr(start, end - start));
        }
        start = end;
    }

    return segments;
}

OpenVerifyCache::Node* OpenVerifyCache::TraverseCreate(const std::vector<std::string>& segments) {
    Node* node = &m_root;
    for (const auto& seg : segments) {
        auto& child = node->children[seg];
        if (!child) {
            child = std::make_unique<Node>();
        }
        node = child.get();
    }
    return node;
}

const OpenVerifyCache::Node* OpenVerifyCache::Traverse(const std::vector<std::string>& segments) const {
    const Node* node = &m_root;
    for (const auto& seg : segments) {
        auto it = node->children.find(seg);
        if (it == node->children.end()) {
            return nullptr;
        }
        node = it->second.get();
    }
    return node;
}

OpenVerifyCache::Status OpenVerifyCache::Get(const std::string& key, std::chrono::steady_clock::time_point now) const {
    const std::shared_lock lk(m_mutex);

    const auto* node = Traverse(SplitPath(key));
    if (!node) {
        return Status::Miss;
    }

    if (!node->entry) {
        return Status::Miss;
    }
    if (now >= node->entry->expiry) {
        return Status::Miss;
    }
    return node->entry->status;
}

void OpenVerifyCache::PutPositive(const std::string& key, std::chrono::seconds ttl,
                                  std::chrono::steady_clock::time_point now) {
    const std::unique_lock lk(m_mutex);
    Node* node = TraverseCreate(SplitPath(key));
    node->entry = std::make_unique<Entry>(Entry{Status::Positive, now + ttl});
}

void OpenVerifyCache::PutNegative(const std::string& key, std::chrono::seconds ttl,
                                  std::chrono::steady_clock::time_point now) {
    const std::unique_lock lk(m_mutex);
    Node* node = TraverseCreate(SplitPath(key));
    node->entry = std::make_unique<Entry>(Entry{Status::Negative, now + ttl});
}

void OpenVerifyCache::Expire(std::chrono::steady_clock::time_point now) {
    const std::unique_lock lk(m_mutex);

    std::function<bool(Node&)> expire_node = [&](Node& node) -> bool {
        if (node.entry && node.entry->expiry <= now) {
            node.entry.reset();
        }

        for (auto it = node.children.begin(); it != node.children.end();) {
            if (expire_node(*it->second)) {
                it = node.children.erase(it);
            } else {
                ++it;
            }
        }

        return !node.entry && node.children.empty();
    };

    // Don't delete the root node; just purge its children/entries.
    expire_node(m_root);
}

void OpenVerifyCache::Reset() {
    const std::unique_lock lk(m_mutex);
    m_root.children.clear();
    m_root.entry.reset();
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
