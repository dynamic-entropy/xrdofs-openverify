#pragma once

#include <string>

// Construct a cache key for a (path, host, port) combination.
//
// The cache itself is generic (key -> positive/negative with TTL); this helper
// provides a consistent external key format.
//
// Format:
//   <host>[:<port>]//<path>
//
// - If port < 0, we omit ":<port>".
// - We ensure there's exactly two '/' between hostpart and the path.
inline std::string MakeOpenVerifyCacheKey(const std::string& path, const std::string& host, int port) {
    std::string hostpart = host;
    if (port >= 0) {
        hostpart += ":" + std::to_string(port);
    }

    std::string p = path;
    while (!p.empty() && p.front() == '/') {
        p.erase(p.begin());
    }

    return hostpart + "//" + p;
}
