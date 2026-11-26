#include "OpenVerifyUrl.hh"

#include <cstdlib>

#include "OpenVerifyCacheKey.hh"

std::string OpenVerifyUrl::DavToHttpUrl(const std::string& url) {
    if (url.compare(0, 7, "davs://") == 0) {
        return "https://" + url.substr(7);
    }
    if (url.compare(0, 6, "dav://") == 0) {
        return "http://" + url.substr(6);
    }
    return url;
}

std::string OpenVerifyUrl::SynthesizePfn(const std::string& protocol, const std::string& host, int port,
                                         const std::string& path) {
    if (host.empty()) return {};

    std::string p = path;
    while (!p.empty() && p.front() == '/') p.erase(p.begin());
    p.insert(p.begin(), '/');

    std::string authority = BracketIpv6Host(host);
    if (port >= 0) {
        authority += ":" + std::to_string(port);
    }

    // HTTP-family schemes put a single '/' between authority and path. "http"
    // maps to https:// because both the outbound probe and the Rucio davs
    // replicas are TLS.
    if (protocol == "http" || protocol == "https") {
        return "https://" + authority + p;
    }
    if (protocol == "davs" || protocol == "dav") {
        return DavToHttpUrl(protocol + "://" + authority + p);
    }
    // CMS root PFNs use '//' between authority and path.
    return "root://" + authority + "/" + p;
}

std::string OpenVerifyUrl::StripUrlQuery(const std::string& url) {
    const auto q = url.find('?');
    return (q == std::string::npos) ? url : url.substr(0, q);
}

std::string OpenVerifyUrl::PathFromUrl(const std::string& url) {
    const std::string bare = StripUrlQuery(url);
    const auto scheme = bare.find("://");
    if (scheme == std::string::npos) return {};
    const auto path_start = bare.find('/', scheme + 3);
    if (path_start == std::string::npos) return {};
    return bare.substr(path_start);
}

std::string OpenVerifyUrl::CmsLfnFromPath(const std::string& path) {
    if (path.empty()) return path;
    const auto pos = path.find("/store/");
    if (pos == std::string::npos) return path;
    return path.substr(pos);
}

OpenVerifyUrl::RedirectTarget OpenVerifyUrl::MakeRucioRedirect(bool http_client, const std::string& host, int port,
                                                               const std::string& pfn, const std::string& path) {
    RedirectTarget out;
    out.code = port;
    out.text = host;
    if (host.empty()) {
        return out;
    }

    // Prefer the catalog PFN path (may include a site prefix). Do not strip to LFN
    // here — inbound sanitization is separate (CmsLfnFromPath at open).
    std::string redirect_path = PathFromUrl(StripUrlQuery(pfn));
    if (redirect_path.empty()) {
        redirect_path = path;
    }
    if (redirect_path.empty()) {
        return out;
    }

    std::string url = SynthesizePfn(http_client ? "davs" : "root", host, port, redirect_path);
    if (url.empty()) {
        return out;
    }
    out.code = -1;
    out.text = std::move(url);
    return out;
}

OpenVerifyUrl::RedirectParts OpenVerifyUrl::DescribeRedirect(const std::string& text, int port_hint) {
    RedirectParts out;
    if (text.empty()) return out;

    const auto scheme = text.find("://");
    if (scheme == std::string::npos) {
        out.host = text;
        out.port = port_hint;
        return out;
    }

    std::string rest = text.substr(scheme + 3);
    const auto slash = rest.find('/');
    const auto at = rest.find('@');
    if (at != std::string::npos && (slash == std::string::npos || at < slash)) {
        rest = rest.substr(at + 1);
    }
    const auto auth_end = rest.find('/');
    std::string auth = (auth_end == std::string::npos) ? rest : rest.substr(0, auth_end);
    const auto q = auth.find('?');
    if (q != std::string::npos) auth.resize(q);
    out.path = PathFromUrl(text);

    if (auth.empty()) return {};

    if (auth.front() == '[') {
        const auto end = auth.find(']');
        if (end == std::string::npos || end <= 1) return {};
        // Keep the brackets. XrdCl splits the host on the first colon, so
        // root://2001:db8::1:1095/ is not an IPv6 URL. [::1] is rewritten to
        // 127.0.0.1 later (XrdCl keeps brackets in the hostname and then
        // fails getaddrinfo).
        out.host = auth.substr(0, end + 1);
        if (end + 1 < auth.size() && auth[end + 1] == ':') {
            char* endptr = nullptr;
            const long p = std::strtol(auth.c_str() + end + 2, &endptr, 10);
            if (endptr == auth.c_str() + end + 2 || (endptr && *endptr) || p <= 0 || p > 65535) return {};
            out.port = static_cast<int>(p);
        } else if (end + 1 != auth.size()) {
            return {};
        }
        return out;
    }

    const auto first = auth.find(':');
    const auto last = auth.rfind(':');
    if (first != std::string::npos && first == last) {
        out.host = auth.substr(0, first);
        char* endptr = nullptr;
        const long p = std::strtol(auth.c_str() + first + 1, &endptr, 10);
        if (!out.host.empty() && endptr && *endptr == '\0' && p > 0 && p <= 65535) {
            out.port = static_cast<int>(p);
            return out;
        }
        // Not host:port. Keep the whole authority (unbracketed IPv6 has many colons;
        // a single colon that is not a port falls through below).
    }
    if (first != std::string::npos && first != last) {
        // Unbracketed IPv6. Do not peel a trailing hextet off as a port.
        out.host = "[" + auth + "]";
        out.port = -1;
        return out;
    }
    out.host = auth;
    out.port = -1;
    return out;
}
