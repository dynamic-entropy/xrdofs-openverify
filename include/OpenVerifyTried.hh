#pragma once

#include <string>
#include <unordered_set>

// Client/plugin `tried=` CGI: comma-separated host or host:port entries.
// Used to skip already-tried Rucio/cmsd hops and to inject failed hosts into
// the next cmsd locate. Retry logs print this list — never the full opaque
// (which may contain authz=/bearer tokens).

inline std::unordered_set<std::string> ParseTriedHosts(const char* opaque) {
    std::unordered_set<std::string> out;
    if (!opaque || !*opaque) return out;

    std::string s = opaque;
    if (!s.empty() && s.front() == '?') s.erase(s.begin());

    const size_t pos = s.find("tried=");
    if (pos == std::string::npos) return out;
    size_t start = pos + 6;
    size_t end = s.find('&', start);
    if (end == std::string::npos) end = s.size();
    const std::string list = s.substr(start, end - start);

    size_t i = 0;
    while (i < list.size()) {
        size_t j = list.find(',', i);
        if (j == std::string::npos) j = list.size();
        std::string entry = list.substr(i, j - i);
        while (!entry.empty() && (entry.front() == ' ' || entry.front() == '\t')) entry.erase(entry.begin());
        while (!entry.empty() && (entry.back() == ' ' || entry.back() == '\t')) entry.pop_back();
        if (!entry.empty()) out.insert(std::move(entry));
        i = j + 1;
    }
    return out;
}

inline bool IsInTriedList(const std::unordered_set<std::string>& tried, const std::string& host, int port) {
    if (tried.empty() || host.empty()) return false;
    if (tried.count(host)) return true;
    if (port >= 0) {
        const std::string hostPort = host + ":" + std::to_string(port);
        if (tried.count(hostPort)) return true;
    }
    return false;
}

inline void AppendTriedHost(std::string& tried_hosts, const std::string& hostPort) {
    tried_hosts = tried_hosts.empty() ? hostPort : tried_hosts + "," + hostPort;
}

// Inject plugin-collected hosts into cgi `tried=` without dropping other keys
// (authz=, xrd.gsiusrpxy, …). Observe mode never mutates opaque.
inline std::string MergeTriedOpaque(const char* opaque, const std::string& tried_hosts, bool observe) {
    std::string opaque_str = opaque ? opaque : "";
    if (observe || tried_hosts.empty()) return opaque_str;

    if (opaque_str.empty()) {
        return "tried=" + tried_hosts;
    }
    size_t tried_pos = opaque_str.find("tried=");
    if (tried_pos != std::string::npos) {
        size_t end_pos = opaque_str.find('&', tried_pos);
        if (end_pos == std::string::npos) {
            opaque_str += "," + tried_hosts;
        } else {
            opaque_str.insert(end_pos, "," + tried_hosts);
        }
    } else {
        opaque_str += "&tried=" + tried_hosts;
    }
    return opaque_str;
}
