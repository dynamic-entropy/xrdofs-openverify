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
// - An IPv6 host is bracketed before the port so the port is not another hextet
//   (root://2001:db8::1:1094/ is not a valid URL; root://[2001:db8::1]:1094/ is).
inline std::string BracketIpv6Host(const std::string& host) {
    if (host.empty() || host.front() == '[') return host;
    if (host.find(':') == std::string::npos) return host;
    return "[" + host + "]";
}

inline bool OpenVerifyHttpFamilyScheme(const std::string& scheme) {
    return scheme == "http" || scheme == "https" || scheme == "dav" || scheme == "davs";
}

inline bool OpenVerifyKeyHasScheme(const std::string& key, const char* scheme) {
    const std::string prefix = std::string(scheme) + "://";
    return key.compare(0, prefix.size(), prefix) == 0;
}

// True for a cleartext HTTP or WebDAV URL. A bearer must not be appended.
inline bool OpenVerifyKeyIsCleartextHttp(const std::string& key) {
    return OpenVerifyKeyHasScheme(key, "http") || OpenVerifyKeyHasScheme(key, "dav");
}

// scheme, when set, is part of the key so root:// and https:// to the same
// host and path do not share a verify result.
//
// ROOT keys stay <scheme>://<host>[:<port>]//<path> with leading slashes
// stripped: XRootD treats repeated '/' as one separator.
// HTTP-family keys are the URL the client opens, so /store/a and //store/a
// stay distinct.
inline std::string MakeOpenVerifyCacheKey(const std::string& path, const std::string& host, int port,
                                          const std::string& scheme = {}) {
    std::string hostpart = BracketIpv6Host(host);
    if (port >= 0) {
        hostpart += ":" + std::to_string(port);
    }

    if (OpenVerifyHttpFamilyScheme(scheme)) {
        std::string p = path;
        if (p.empty() || p.front() != '/') p.insert(p.begin(), '/');
        return scheme + "://" + hostpart + p;
    }

    if (!scheme.empty()) {
        hostpart = scheme + "://" + hostpart;
    }

    std::string p = path;
    while (!p.empty() && p.front() == '/') {
        p.erase(p.begin());
    }

    return hostpart + "//" + p;
}
