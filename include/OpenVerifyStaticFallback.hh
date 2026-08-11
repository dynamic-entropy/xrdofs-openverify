#pragma once

#include <string>

// CMS global redirectors use a static xrootd.redirect ENOENT fallback for /store:
//   xrootd.redirect cms-xrd-transit.cern.ch:1094 ? /store
// That hop is neither a cmsd federation peer nor a Rucio replica — OpenVerify
// must pass it through without probing.

inline constexpr const char* kOpenVerifyTransitFallbackHost = "cms-xrd-transit.cern.ch";

// True if `host` is the AAA transit static fallback (bare hostname or root/https URL).
inline bool IsStaticXrootdFallbackHost(const std::string& host) {
    if (host.empty()) return false;
    if (host == kOpenVerifyTransitFallbackHost) return true;

    // Full-URL form from some redirect encodings: root://cms-xrd-transit.cern.ch:1094/...
    const std::string marker = std::string("://") + kOpenVerifyTransitFallbackHost;
    const auto pos = host.find(marker);
    if (pos == std::string::npos) return false;
    const size_t after = pos + marker.size();
    return after >= host.size() || host[after] == ':' || host[after] == '/' || host[after] == '?';
}

// Stable Prometheus fallback= label for the known AAA transit rule.
inline const char* StaticXrootdFallbackLabel(const std::string& host) {
    return IsStaticXrootdFallbackHost(host) ? "transit" : "unknown";
}
