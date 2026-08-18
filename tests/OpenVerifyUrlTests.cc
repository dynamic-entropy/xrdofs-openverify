#include <iostream>
#include <string>

#include "OpenVerifyCacheKey.hh"
#include "OpenVerifyUrl.hh"

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

void Test_DavToHttpUrl() {
    Expect(OpenVerifyUrl::DavToHttpUrl("davs://h.example.edu:2880/store/a.root") ==
               "https://h.example.edu:2880/store/a.root",
           "DavToHttpUrl: davs -> https");
    Expect(OpenVerifyUrl::DavToHttpUrl("dav://h.example.edu/store/a.root") ==
               "http://h.example.edu/store/a.root",
           "DavToHttpUrl: dav -> http");
    // Only the scheme changes; authority, port and path are untouched.
    Expect(OpenVerifyUrl::DavToHttpUrl("davs://h.example.edu//dcache/store/a.root") ==
               "https://h.example.edu//dcache/store/a.root",
           "DavToHttpUrl: keeps double slash in path");
    // Wire schemes and non-HTTP schemes pass through untouched.
    Expect(OpenVerifyUrl::DavToHttpUrl("https://h.example.edu/store/a.root") ==
               "https://h.example.edu/store/a.root",
           "DavToHttpUrl: https unchanged");
    Expect(OpenVerifyUrl::DavToHttpUrl("root://h.example.edu:1094//store/a.root") ==
               "root://h.example.edu:1094//store/a.root",
           "DavToHttpUrl: root unchanged");
    Expect(OpenVerifyUrl::DavToHttpUrl("") == "", "DavToHttpUrl: empty unchanged");
    // "davfoo" must not be mistaken for the dav alias.
    Expect(OpenVerifyUrl::DavToHttpUrl("davfoo://h/x") == "davfoo://h/x",
           "DavToHttpUrl: unrelated scheme with dav prefix unchanged");
}

void Test_SynthesizePfn() {
    Expect(OpenVerifyUrl::SynthesizePfn("root", "h.example.edu", 1094, "/store/a.root") ==
               "root://h.example.edu:1094//store/a.root",
           "SynthesizePfn: root double-slash path");
    Expect(OpenVerifyUrl::SynthesizePfn("http", "h.example.edu", 1094, "/store/a.root") ==
               "https://h.example.edu:1094/store/a.root",
           "SynthesizePfn: https");
    Expect(OpenVerifyUrl::SynthesizePfn("root", "h.example.edu", -1, "store/a.root") ==
               "root://h.example.edu//store/a.root",
           "SynthesizePfn: no port + normalize path");
    // dav/davs are catalog aliases, so they resolve to a wire scheme with a
    // single slash before the path.
    Expect(OpenVerifyUrl::SynthesizePfn("davs", "h.example.edu", 1094, "/store/a.root") ==
               "https://h.example.edu:1094/store/a.root",
           "SynthesizePfn: davs resolves to https");
    Expect(OpenVerifyUrl::SynthesizePfn("dav", "h.example.edu", 1094, "/store/a.root") ==
               "http://h.example.edu:1094/store/a.root",
           "SynthesizePfn: dav resolves to http");
    Expect(OpenVerifyUrl::SynthesizePfn("https", "h.example.edu", 1094, "/store/a.root") ==
               "https://h.example.edu:1094/store/a.root",
           "SynthesizePfn: https alias");
}

void Test_ProbeUrlHelpers() {
    Expect(OpenVerifyUrl::StripUrlQuery("root://h:1094//store/a?authz=secret") == "root://h:1094//store/a",
           "StripUrlQuery: drops query");
    Expect(OpenVerifyUrl::PathFromUrl("root://h:1094//dcache/store/a.root") == "//dcache/store/a.root",
           "PathFromUrl: keeps double-slash PFN path");
    Expect(OpenVerifyUrl::PathFromUrl("https://h:1094/store/a.root?x=1") == "/store/a.root",
           "PathFromUrl: https single-slash path");
}

void Test_MakeRucioRedirect() {
    const char* pfn = "root://cmsdcadisk.fnal.gov:1094//dcache/uscmsdisk/store/mc/file.root?x=1";
    const auto root = OpenVerifyUrl::MakeRucioRedirect(false, "cmsdcadisk.fnal.gov", 1094, pfn,
                                                      "/store/mc/file.root");
    Expect(root.code == -1, "MakeRucioRedirect: root uses full-URL code -1");
    Expect(root.text == "root://cmsdcadisk.fnal.gov:1094//dcache/uscmsdisk/store/mc/file.root",
           "MakeRucioRedirect: root strips query and keeps PFN path");

    // HTTP clients get the catalog PFN as a full URL too, so the disk-door site
    // prefix survives instead of XrdHttp re-appending the client LFN. Rucio's
    // davs:// becomes https:// so the Location: header is followable.
    const char* davs_pfn = "davs://cmsdcadisk.fnal.gov:1094/dcache/uscmsdisk/store/mc/file.root?x=1";
    const auto http = OpenVerifyUrl::MakeRucioRedirect(true, "cmsdcadisk.fnal.gov", 1094, davs_pfn,
                                                      "/store/mc/file.root");
    Expect(http.code == -1, "MakeRucioRedirect: http uses full-URL code -1");
    Expect(http.text == "https://cmsdcadisk.fnal.gov:1094/dcache/uscmsdisk/store/mc/file.root",
           "MakeRucioRedirect: http strips query and resolves davs PFN to https");

    const auto synth = OpenVerifyUrl::MakeRucioRedirect(false, "h.example.edu", 1094, "",
                                                       "//dcache/store/a.root");
    Expect(synth.code == -1, "MakeRucioRedirect: synthesize full URL when pfn empty");
    Expect(synth.text == "root://h.example.edu:1094//dcache/store/a.root",
           "MakeRucioRedirect: synthesize from path");

    // Synthesized fallback must follow the client dialect, not hardcode root://.
    const auto synth_http = OpenVerifyUrl::MakeRucioRedirect(true, "h.example.edu", 1094, "",
                                                           "/dcache/store/a.root");
    Expect(synth_http.code == -1, "MakeRucioRedirect: http synthesize uses code -1");
    Expect(synth_http.text == "https://h.example.edu:1094/dcache/store/a.root",
           "MakeRucioRedirect: http synthesize uses https wire scheme");

    // No host and no path: degrade to host + port rather than emit a bogus URL.
    const auto bare = OpenVerifyUrl::MakeRucioRedirect(true, "h.example.edu", 1094, "", "");
    Expect(bare.code == 1094, "MakeRucioRedirect: falls back to port when nothing to build");
    Expect(bare.text == "h.example.edu", "MakeRucioRedirect: falls back to host");
}

void Test_RucioPfnVerifyCacheKey() {
    // Disk-door PFN with site prefix: verify key must carry that path, not the LFN.
    const char* pfn =
        "root://cmsdcadisk.fnal.gov:1094//dcache/uscmsdisk/store/mc/file.root";
    const auto pfn_path = OpenVerifyUrl::PathFromUrl(pfn);
    const auto key = MakeOpenVerifyCacheKey(pfn_path, "cmsdcadisk.fnal.gov", 1094);
    Expect(key == "cmsdcadisk.fnal.gov:1094//dcache/uscmsdisk/store/mc/file.root",
           "RucioPfnVerifyCacheKey: key uses PFN path");
    Expect(key.find("//store/mc/file.root") == std::string::npos ||
               key.find("dcache/uscmsdisk/store/mc/file.root") != std::string::npos,
           "RucioPfnVerifyCacheKey: site prefix retained");
    // LFN-only key must not collide with the PFN-path key.
    const auto lfn_key = MakeOpenVerifyCacheKey("/store/mc/file.root", "cmsdcadisk.fnal.gov", 1094);
    Expect(lfn_key == "cmsdcadisk.fnal.gov:1094//store/mc/file.root", "RucioPfnVerifyCacheKey: lfn key");
    Expect(lfn_key != key, "RucioPfnVerifyCacheKey: pfn key distinct from lfn key");
}

}  // namespace

int main() {
    Test_DavToHttpUrl();
    Test_SynthesizePfn();
    Test_ProbeUrlHelpers();
    Test_MakeRucioRedirect();
    Test_RucioPfnVerifyCacheKey();

    if (g_failures != 0) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "OK\n";
    return 0;
}
