#pragma once

#include <string>

// URL / redirect helpers for Rucio PFNs and outbound probes.
class OpenVerifyUrl {
   public:
    // Translate a WebDAV URL alias to the wire scheme it stands for: davs:// →
    // https://, dav:// → http://. Rucio reports CMS WebDAV replicas under the
    // "davs" protocol id, but dav/davs are client-side input aliases (compare
    // DavToHttp() in XrdClHttp and PrepareURL() in XrdHttpTpc) that no HTTP
    // client will follow in a Location: header, so every URL leaving this
    // plugin for an HTTP client goes through here first.
    static std::string DavToHttpUrl(const std::string& url);
    // Credential-free PFN: root://host:port//path for root, or scheme://host:port/path
    // for the HTTP family (http/https/davs → https, dav → http).
    static std::string SynthesizePfn(const std::string& protocol, const std::string& host, int port,
                                     const std::string& path);
    // Drop ?query (opaque/token/cert CGI) from an XrdCl open URL.
    static std::string StripUrlQuery(const std::string& url);
    // Path after authority (keeps leading '/' or '//'); empty if URL has no path.
    static std::string PathFromUrl(const std::string& url);

    // CMS logical name: substring from the first "/store/" (site PFN prefixes
    // like /eos/cms/, /dcache/uscmsdisk/, /grid/cms/ are stripped). Unchanged if
    // "/store/" is absent (e.g. /tmp/...). Applied once to the inbound open path
    // so Rucio/cmsd see an LFN even when a client retries a PFN after load-balancer
    // fallback (https://github.com/xrootd/xrootd/issues/2394). Outbound redirects
    // still use the catalog/cmsd PFN path.
    static std::string CmsLfnFromPath(const std::string& path);

    // ErrInfo payload for a Rucio gateway redirect. Both dialects get a full URL
    // with code -1. Prefer the catalog `pfn` path (site prefix intact); fall back
    // to synthesizing from `path` (usually the sanitized LFN) when pfn is empty.
    // HTTP clients get davs→https. Degrades to host + port when no URL can be built.
    struct RedirectTarget {
        int code{-1};     // setErrInfo port / -1 for full URL
        std::string text; // hostname or full URL
    };
    static RedirectTarget MakeRucioRedirect(bool http_client, const std::string& host, int port,
                                            const std::string& pfn, const std::string& path);
};
