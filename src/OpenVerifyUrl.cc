#include "OpenVerifyUrl.hh"

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

    std::string authority = host;
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

OpenVerifyUrl::RedirectTarget OpenVerifyUrl::MakeRucioRedirect(bool http_client, const std::string& host, int port,
                                                               const std::string& pfn, const std::string& path) {
    RedirectTarget out;
    out.code = port;
    out.text = host;
    if (host.empty()) {
        return out;
    }

    // Prefer the catalog PFN (already scheme-matched by Rucio list); fall back to synthesize.
    // Rucio hands back davs:// for the CMS WebDAV replicas, which is a catalog
    // protocol id and not something a Location: header may carry, so translate
    // it to its wire scheme before it leaves the plugin.
    std::string url = DavToHttpUrl(StripUrlQuery(pfn));
    if (url.find("://") == std::string::npos) {
        if (path.empty()) {
            return out;
        }
        url = SynthesizePfn(http_client ? "davs" : "root", host, port, path);
    }
    if (url.empty()) {
        return out;
    }
    out.code = -1;
    out.text = std::move(url);
    return out;
}
