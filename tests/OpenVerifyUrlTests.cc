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
    Expect(OpenVerifyUrl::SynthesizePfn("root", "2001:db8::1", 1094, "/store/a.root") ==
               "root://[2001:db8::1]:1094//store/a.root",
           "SynthesizePfn: brackets ipv6 before the port");
    Expect(MakeOpenVerifyCacheKey("/store/a.root", "2001:db8::1", 1094) == "[2001:db8::1]:1094//store/a.root",
           "cache key brackets ipv6 before the port");
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

void Test_CmsLfnFromPath() {
    Expect(OpenVerifyUrl::CmsLfnFromPath("/eos/cms/store/data/a.root") == "/store/data/a.root",
           "CmsLfnFromPath: strips /eos/cms");
    Expect(OpenVerifyUrl::CmsLfnFromPath("//eos/cms//store/data/a.root") == "/store/data/a.root",
           "CmsLfnFromPath: strips double-slash EOS prefix");
    Expect(OpenVerifyUrl::CmsLfnFromPath("/dcache/uscmsdisk/store/mc/file.root") == "/store/mc/file.root",
           "CmsLfnFromPath: strips dcache prefix");
    Expect(OpenVerifyUrl::CmsLfnFromPath("/store/user/x.root") == "/store/user/x.root",
           "CmsLfnFromPath: LFN unchanged");
    Expect(OpenVerifyUrl::CmsLfnFromPath("/tmp/xrootd-testfile.global") == "/tmp/xrootd-testfile.global",
           "CmsLfnFromPath: non-store path unchanged");
    Expect(OpenVerifyUrl::CmsLfnFromPath("/store/test/xrootd/T2_US_Wisconsin/store/mc/SAM/file.root") ==
               "/store/test/xrootd/T2_US_Wisconsin/store/mc/SAM/file.root",
           "CmsLfnFromPath: SAM AAA pin keeps the wrapper (first /store/)");
    Expect(OpenVerifyUrl::CmsLfnFromPath("") == "", "CmsLfnFromPath: empty");
}

void Test_MakeRucioRedirect() {
    // Redirect carries the catalog PFN path; inbound LFN sanitization is separate.
    const char* pfn = "root://cmsdcadisk.fnal.gov:1094//dcache/uscmsdisk/store/mc/file.root?x=1";
    const auto root = OpenVerifyUrl::MakeRucioRedirect(false, "cmsdcadisk.fnal.gov", 1094, pfn,
                                                      "/store/mc/file.root");
    Expect(root.code == -1, "MakeRucioRedirect: root uses full-URL code -1");
    Expect(root.text == "root://cmsdcadisk.fnal.gov:1094//dcache/uscmsdisk/store/mc/file.root",
           "MakeRucioRedirect: root strips query and keeps PFN path");

    const char* davs_pfn = "davs://cmsdcadisk.fnal.gov:1094/dcache/uscmsdisk/store/mc/file.root?x=1";
    const auto http = OpenVerifyUrl::MakeRucioRedirect(true, "cmsdcadisk.fnal.gov", 1094, davs_pfn,
                                                      "/store/mc/file.root");
    Expect(http.code == -1, "MakeRucioRedirect: http uses full-URL code -1");
    Expect(http.text == "https://cmsdcadisk.fnal.gov:1094/dcache/uscmsdisk/store/mc/file.root",
           "MakeRucioRedirect: http strips query and resolves davs PFN to https");

    const auto synth = OpenVerifyUrl::MakeRucioRedirect(false, "h.example.edu", 1094, "",
                                                       "/store/a.root");
    Expect(synth.code == -1, "MakeRucioRedirect: synthesize full URL when pfn empty");
    Expect(synth.text == "root://h.example.edu:1094//store/a.root",
           "MakeRucioRedirect: synthesize from path fallback");

    const auto synth_http = OpenVerifyUrl::MakeRucioRedirect(true, "h.example.edu", 1094, "",
                                                           "/store/a.root");
    Expect(synth_http.code == -1, "MakeRucioRedirect: http synthesize uses code -1");
    Expect(synth_http.text == "https://h.example.edu:1094/store/a.root",
           "MakeRucioRedirect: http synthesize uses https wire scheme");

    const auto bare = OpenVerifyUrl::MakeRucioRedirect(true, "h.example.edu", 1094, "", "");
    Expect(bare.code == 1094, "MakeRucioRedirect: falls back to port when nothing to build");
    Expect(bare.text == "h.example.edu", "MakeRucioRedirect: falls back to host");
}

void Test_RucioPfnVerifyCacheKey() {
    // Disk-door PFN with site prefix: verify key carries that path, not the LFN.
    const char* pfn =
        "root://cmsdcadisk.fnal.gov:1094//dcache/uscmsdisk/store/mc/file.root";
    const auto pfn_path = OpenVerifyUrl::PathFromUrl(pfn);
    const auto key = MakeOpenVerifyCacheKey(pfn_path, "cmsdcadisk.fnal.gov", 1094);
    Expect(key == "cmsdcadisk.fnal.gov:1094//dcache/uscmsdisk/store/mc/file.root",
           "RucioPfnVerifyCacheKey: key uses PFN path");
    const auto lfn_key = MakeOpenVerifyCacheKey("/store/mc/file.root", "cmsdcadisk.fnal.gov", 1094);
    Expect(lfn_key == "cmsdcadisk.fnal.gov:1094//store/mc/file.root", "RucioPfnVerifyCacheKey: lfn key");
    Expect(lfn_key != key, "RucioPfnVerifyCacheKey: pfn key distinct from lfn key");
}

void Test_DescribeRedirect() {
    const auto hostport = OpenVerifyUrl::DescribeRedirect("cms.example.edu", 1094);
    Expect(hostport.host == "cms.example.edu" && hostport.port == 1094 && hostport.path.empty(),
           "DescribeRedirect: bare host keeps the port hint");

    const auto root = OpenVerifyUrl::DescribeRedirect("root://cms.example.edu:1094//store/a.root", -1);
    Expect(root.scheme == "root", "DescribeRedirect: root scheme");
    Expect(root.host == "cms.example.edu", "DescribeRedirect: root host");
    Expect(root.port == 1094, "DescribeRedirect: root port");
    Expect(root.path == "//store/a.root", "DescribeRedirect: root path keeps the double slash");

    const auto https = OpenVerifyUrl::DescribeRedirect("https://cms.example.edu/store/a.root?authz=secret", -1);
    Expect(https.host == "cms.example.edu" && https.port == -1, "DescribeRedirect: https without port");
    Expect(https.path == "/store/a.root", "DescribeRedirect: path drops the query");
    Expect(https.scheme == "https", "DescribeRedirect: https scheme");
    Expect(MakeOpenVerifyCacheKey("/store/a.root", "cms.example.edu", -1, "https") ==
               "https://cms.example.edu//store/a.root",
           "cache key includes the redirect scheme");
    Expect(MakeOpenVerifyCacheKey("//store/a.root", "cms.example.edu", -1, "https") ==
               MakeOpenVerifyCacheKey("/store/a.root", "cms.example.edu", -1, "https"),
           "https keys collapse repeated slashes the same way root keys do");
    Expect(MakeOpenVerifyCacheKey("/store/a.root", "cms.example.edu", 1094, "roots") ==
               "roots://cms.example.edu:1094//store/a.root",
           "roots stays a distinct cache key");
    // NOSONAR: literal used to reject bearer tokens over plain http
    Expect(OpenVerifyKeyIsCleartextHttp("http://h/store/a"), "http key is cleartext");
    Expect(OpenVerifyKeyIsCleartextHttp("dav://h/store/a"), "dav key is cleartext");
    Expect(!OpenVerifyKeyIsCleartextHttp("https://h/store/a"), "https key is not cleartext");
    Expect(!OpenVerifyKeyIsCleartextHttp("h:1094//store/a"), "unschemed key is not cleartext http");

    const auto bare = OpenVerifyUrl::DescribeRedirect("https://h.example", -1);
    Expect(bare.host == "h.example" && bare.path.empty() && bare.scheme == "https",
           "DescribeRedirect: https URL with no path");
    Expect(OpenVerifyUrl::VerifyPathForRedirect("/store/a", bare, true) == "/",
           "full URL with no path is probed as /");
    Expect(OpenVerifyUrl::VerifyPathForRedirect("/store/a", hostport, false) == "/store/a",
           "host:port redirect keeps the inbound path");

    const auto roots = OpenVerifyUrl::DescribeRedirect("roots://site.example:1094//store/a", -1);
    Expect(roots.scheme == "roots" && roots.host == "site.example" && roots.port == 1094,
           "DescribeRedirect: roots scheme is preserved");

    const auto v6 = OpenVerifyUrl::DescribeRedirect("root://[2001:db8::1]:1095//store/a", -1);
    Expect(v6.host == "[2001:db8::1]" && v6.port == 1095, "DescribeRedirect: keeps ipv6 brackets");
    Expect(v6.path == "//store/a", "DescribeRedirect: ipv6 path");

    const auto v6bare = OpenVerifyUrl::DescribeRedirect("root://2001:db8::10//store/a", -1);
    Expect(v6bare.host == "[2001:db8::10]" && v6bare.port == -1,
           "DescribeRedirect: unbracketed ipv6 keeps the last hextet");

    const auto bad = OpenVerifyUrl::DescribeRedirect("root://", -1);
    Expect(bad.host.empty(), "DescribeRedirect: empty authority is unusable");
}

}  // namespace

int main() {
    Test_DavToHttpUrl();
    Test_SynthesizePfn();
    Test_ProbeUrlHelpers();
    Test_CmsLfnFromPath();
    Test_MakeRucioRedirect();
    Test_RucioPfnVerifyCacheKey();
    Test_DescribeRedirect();

    if (g_failures != 0) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "OK\n";
    return 0;
}
