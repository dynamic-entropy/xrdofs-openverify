#pragma once

#include <cctype>
#include <string>
#include <unordered_set>

#include "OpenVerifyCacheKey.hh"

// Client/plugin `tried=` CGI: comma-separated host or host:port entries.
// Used to skip already-tried Rucio/cmsd hops and to inject failed hosts into
// the next cmsd locate (still the `tried=` key — never a separate CGI param).
// Retry logs may print client_tried= vs ov_tried=; they never print the full
// opaque (which may contain authz=/bearer tokens).
//
// cmsd (XrdCmsNode::do_SelAvoid) parses each comma-separated token as:
//   '+' <cluster id>     → XrdCmsClustID::Mask (not a hostname)
//   anything else        → XrdNetAddr::Set, then the node with that address
// A legacy client token "+NN<hostname>" (two digits, NN == hostname length)
// therefore does not avoid that host. MergeTriedOpaque rewrites those to the
// bare hostname XrdNetAddr can resolve. host:port is also reduced to the
// hostname: Set() drops the whole token when the port suffix is not numeric,
// and XrdNetAddrInfo::Same (used by isNode) ignores the port anyway.

inline std::string TrimTriedToken(std::string entry) {
    while (!entry.empty() && (entry.front() == ' ' || entry.front() == '\t')) entry.erase(entry.begin());
    while (!entry.empty() && (entry.back() == ' ' || entry.back() == '\t')) entry.pop_back();
    return entry;
}

inline bool TriedAllDigits(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (std::isdigit(c) == 0) return false;
    }
    return true;
}

// Token cmsd's avoid list will actually match. Empty if the entry is unusable.
// '+' cluster ids that are not the legacy length-prefix form are preserved.
inline std::string NormalizeCmsdTriedEntry(std::string e) {
    e = TrimTriedToken(std::move(e));
    if (e.empty()) return {};

    if (e.size() >= 4 && e[0] == '+' && std::isdigit(static_cast<unsigned char>(e[1])) != 0 &&
        std::isdigit(static_cast<unsigned char>(e[2])) != 0) {
        const int n = (e[1] - '0') * 10 + (e[2] - '0');
        if (n > 0 && e.size() == 3u + static_cast<size_t>(n)) {
            e = e.substr(3);
        } else {
            return e;
        }
    } else if (!e.empty() && e[0] == '+') {
        return e;
    }

    const auto scheme = e.find("://");
    if (scheme != std::string::npos) {
        std::string rest = e.substr(scheme + 3);
        const auto slash = rest.find('/');
        const auto at = rest.find('@');
        if (at != std::string::npos && (slash == std::string::npos || at < slash)) {
            rest = rest.substr(at + 1);
        }
        const auto auth_end = rest.find('/');
        e = (auth_end == std::string::npos) ? rest : rest.substr(0, auth_end);
        const auto q = e.find('?');
        if (q != std::string::npos) e.resize(q);
    }

    if (!e.empty() && e.front() == '[') {
        const auto end = e.find(']');
        if (end == std::string::npos || end == 1) return {};
        const std::string inner = e.substr(1, end - 1);
        if (inner.find(':') != std::string::npos) return "[" + inner + "]";
        e = inner;
    }

    // More than one colon: an unbracketed IPv6 address. The last hextet is
    // often all digits (2001:db8::10); that is not a port. A real port is
    // only stripped above, from the bracket form [addr]:port.
    const auto first_colon = e.find(':');
    const auto last_colon = e.rfind(':');
    if (first_colon != std::string::npos && first_colon != last_colon) {
        return "[" + e + "]";
    }

    if (first_colon != std::string::npos && TriedAllDigits(e.substr(first_colon + 1))) {
        e.resize(first_colon);
    }
    return e;
}

inline std::string NormalizeTriedList(const std::string& list) {
    std::string out;
    std::unordered_set<std::string> seen;
    size_t i = 0;
    while (i < list.size()) {
        size_t j = list.find(',', i);
        if (j == std::string::npos) j = list.size();
        const std::string n = NormalizeCmsdTriedEntry(list.substr(i, j - i));
        if (!n.empty() && seen.insert(n).second) {
            if (!out.empty()) out.push_back(',');
            out += n;
        }
        i = j + 1;
    }
    return out;
}

// Index of a CGI key at a '&' / start boundary. `tried=` inside another
// parameter's value (for example a proxy path) must not match.
inline size_t FindCgiKey(const std::string& body, const char* key) {
    const std::string k = std::string(key) + "=";
    size_t pos = 0;
    while (pos <= body.size()) {
        const bool boundary = (pos == 0) || body[pos - 1] == '&';
        if (boundary && body.compare(pos, k.size(), k) == 0) return pos;
        const auto amp = body.find('&', pos);
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return std::string::npos;
}

inline std::string TriedCgiValue(const char* opaque) {
    if (!opaque || !*opaque) return {};
    std::string s = opaque;
    if (!s.empty() && s.front() == '?') s.erase(s.begin());
    const size_t pos = FindCgiKey(s, "tried");
    if (pos == std::string::npos) return {};
    const size_t start = pos + 6;
    size_t end = s.find('&', start);
    if (end == std::string::npos) end = s.size();
    return s.substr(start, end - start);
}

inline std::unordered_set<std::string> ParseTriedHosts(const char* opaque) {
    std::unordered_set<std::string> out;
    const std::string list = TriedCgiValue(opaque);
    size_t i = 0;
    while (i < list.size()) {
        size_t j = list.find(',', i);
        if (j == std::string::npos) j = list.size();
        const std::string raw = TrimTriedToken(list.substr(i, j - i));
        if (!raw.empty()) {
            out.insert(raw);
            // "+NN<host>" is a legacy client token. Index the hostname too so
            // a later hop on that host is skipped. host:port stays port-specific.
            if (raw[0] == '+') {
                const std::string normalized = NormalizeCmsdTriedEntry(raw);
                if (!normalized.empty()) out.insert(normalized);
            }
        }
        i = j + 1;
    }
    return out;
}

inline bool IsInTriedList(const std::unordered_set<std::string>& tried, const std::string& host, int port) {
    if (tried.empty() || host.empty()) return false;
    if (tried.count(host)) return true;
    const std::string canon = BracketIpv6Host(host);
    if (canon != host && tried.count(canon)) return true;
    if (canon.size() >= 2 && canon.front() == '[' && canon.back() == ']') {
        const std::string bare = canon.substr(1, canon.size() - 2);
        if (tried.count(bare)) return true;
    }
    const std::string normalized = NormalizeCmsdTriedEntry(host);
    if (!normalized.empty() && tried.count(normalized)) return true;
    if (port >= 0) {
        const std::string hostPort = host + ":" + std::to_string(port);
        if (tried.count(hostPort)) return true;
        const std::string normalizedPort = NormalizeCmsdTriedEntry(hostPort);
        if (!normalizedPort.empty() && normalizedPort != hostPort && tried.count(normalizedPort)) return true;
    }
    return false;
}

inline void AppendTriedHost(std::string& tried_hosts, const std::string& hostPort) {
    if (hostPort.empty()) return;
    size_t i = 0;
    while (i < tried_hosts.size()) {
        size_t j = tried_hosts.find(',', i);
        if (j == std::string::npos) j = tried_hosts.size();
        if (tried_hosts.compare(i, j - i, hostPort) == 0) return;
        i = j + 1;
    }
    if (!tried_hosts.empty()) tried_hosts.push_back(',');
    tried_hosts += hostPort;
}

// Inject plugin-collected hosts into cgi `tried=` without dropping other keys
// (authz=, xrd.gsiusrpxy, …). Observe mode never mutates opaque.
// The value written is the cmsd avoid form (bare host, legacy +NN rewritten,
// duplicates removed) so do_SelAvoid can resolve it.
inline std::string MergeTriedOpaque(const char* opaque, const std::string& tried_hosts, bool observe) {
    std::string opaque_str = opaque ? opaque : "";
    if (observe || tried_hosts.empty()) return opaque_str;

    const std::string added = NormalizeTriedList(tried_hosts);
    if (added.empty()) return opaque_str;

    bool leading_q = false;
    std::string body = opaque_str;
    if (!body.empty() && body.front() == '?') {
        leading_q = true;
        body.erase(body.begin());
    }

    const std::string existing = TriedCgiValue(body.c_str());
    const std::string merged = NormalizeTriedList(existing.empty() ? added : existing + "," + added);
    if (merged.empty()) return opaque_str;

    const size_t pos = FindCgiKey(body, "tried");
    if (pos == std::string::npos) {
        if (!body.empty()) body.push_back('&');
        body += "tried=" + merged;
    } else {
        const size_t val = pos + 6;
        size_t end = body.find('&', val);
        if (end == std::string::npos) end = body.size();
        body.replace(val, end - val, merged);
    }
    if (leading_q) body.insert(body.begin(), '?');
    return body;
}
