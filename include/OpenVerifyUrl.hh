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

    // ErrInfo payload for a Rucio gateway redirect. Both dialects get the full
    // catalog PFN URL + code -1 so the client opens the PFN path (which may carry a
    // site prefix a disk door requires) rather than the original LFN; http_client
    // only selects the scheme for the synthesized fallback. The URL is always a
    // wire scheme, never a dav/davs alias. Degrades to host + port when no URL
    // can be built.
    struct RedirectTarget {
        int code{-1};     // setErrInfo port / -1 for full URL
        std::string text; // hostname or full URL
    };
    static RedirectTarget MakeRucioRedirect(bool http_client, const std::string& host, int port,
                                            const std::string& pfn, const std::string& path);
};
