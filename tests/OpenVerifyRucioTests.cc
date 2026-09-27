#include <cstdlib>
#include <iostream>
#include <string>

#include "OpenVerifyRucio.hh"
#include "OpenVerifyRucioSelector.hh"

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

void Test_SchemeFromProt() {
    Expect(OpenVerifyRucioSchemeFromProt("http") == "davs", "http -> davs");
    Expect(OpenVerifyRucioSchemeFromProt("https") == "davs", "https -> davs");
    Expect(OpenVerifyRucioSchemeFromProt("xroot") == "root", "xroot -> root");
    Expect(OpenVerifyRucioSchemeFromProt("") == "root", "empty -> root");
    Expect(OpenVerifyRucioSchemeFromProt(nullptr) == "root", "null -> root");
}

void Test_NormalizeScheme() {
    Expect(OpenVerifyRucioNormalizeScheme("http") == "davs", "normalize http");
    Expect(OpenVerifyRucioNormalizeScheme("https") == "davs", "normalize https");
    Expect(OpenVerifyRucioNormalizeScheme("davs") == "davs", "normalize davs");
    Expect(OpenVerifyRucioNormalizeScheme("xroot") == "root", "normalize xroot");
    Expect(OpenVerifyRucioNormalizeScheme("root") == "root", "normalize root");
}

void Test_ParsePfnRoot() {
    std::string host;
    int port = -1;
    Expect(OpenVerifyRucioParsePfn("root://cms-xrd.example.edu:1094//store/data/file.root", host, port),
           "root pfn parse ok");
    Expect(host == "cms-xrd.example.edu", "root host");
    Expect(port == 1094, "root port");
}

void Test_ParsePfnRootDefaultPort() {
    std::string host;
    int port = -1;
    Expect(OpenVerifyRucioParsePfn("root://gateway.site.edu//store/foo", host, port), "root default port parse");
    Expect(host == "gateway.site.edu", "root default host");
    Expect(port == 1094, "root default port 1094");
}

void Test_ParsePfnDavs() {
    std::string host;
    int port = -1;
    Expect(OpenVerifyRucioParsePfn("davs://dav.site.edu:2880/store/data/file.root", host, port), "davs pfn parse");
    Expect(host == "dav.site.edu", "davs host");
    Expect(port == 2880, "davs port");
}

void Test_ParsePfnDavsDefaultPort() {
    std::string host;
    int port = -1;
    Expect(OpenVerifyRucioParsePfn("davs://dav.site.edu/store/foo", host, port), "davs default port parse");
    Expect(host == "dav.site.edu", "davs default host");
    Expect(port == 443, "davs default port 443");
}

void Test_ParsePfnIpv6() {
    std::string host;
    int port = -1;
    Expect(OpenVerifyRucioParsePfn("root://[2001:db8::1]:1094//store/x", host, port), "ipv6 pfn parse");
    Expect(host == "2001:db8::1", "ipv6 host");
    Expect(port == 1094, "ipv6 port");
}

void Test_ParseReplicasJsonArray() {
    const std::string body = R"([
      {
        "scope": "cms",
        "name": "/store/data/file.root",
        "pfns": {
          "root://b.example:1094//store/data/file.root": {"rse": "T2_B", "priority": 2},
          "root://a.example:1095//store/data/file.root": {"rse": "T2_A", "priority": 1},
          "davs://ignored.example/store/data/file.root": {"rse": "T2_C", "priority": 1}
        }
      }
    ])";
    const auto cands = OpenVerifyRucioParseReplicasJson(body, "root");
    Expect(cands.size() == 2, "array: two root candidates");
    if (cands.size() >= 2) {
        bool saw_a = false, saw_b = false;
        for (const auto& c : cands) {
            if (c.host == "a.example" && c.port == 1095 && c.rse == "T2_A" && c.priority == 1) saw_a = true;
            if (c.host == "b.example" && c.port == 1094 && c.rse == "T2_B" && c.priority == 2) saw_b = true;
        }
        Expect(saw_a && saw_b, "array: both root PFNs with rse/priority");
        // Rucio's sort=geoip order is the pfns key order; parse must not re-sort keys.
        Expect(cands[0].host == "b.example" && cands[1].host == "a.example", "array: keeps Rucio pfns order");
    }
}

void Test_ServerOrderSelector() {
    std::vector<OpenVerifyRucioCandidate> cands = {
        {.host = "c.example", .port = 1094, .priority = 3},
        {.host = "a.example", .port = 1094, .priority = 1},
        {.host = "b.example", .port = 1094, .priority = 2},
    };
    OpenVerifyRucioServerOrderSelector sel;
    OpenVerifyRucioSelectContext ctx;
    sel.Order(cands, ctx);
    Expect(cands[0].host == "c.example" && cands[1].host == "a.example" && cands[2].host == "b.example",
           "rucio: order unchanged");
}

void Test_PrioritySelector() {
    std::vector<OpenVerifyRucioCandidate> cands = {
        {.host = "b.example", .port = 1094, .priority = 2},
        {.host = "a.example", .port = 1095, .priority = 1},
        {.host = "c.example", .port = 1094, .priority = 1},
    };
    OpenVerifyRucioPrioritySelector sel;
    OpenVerifyRucioSelectContext ctx;
    sel.Order(cands, ctx);
    Expect(cands.size() == 3, "priority: size");
    Expect(cands[0].priority == 1 && cands[1].priority == 1 && cands[2].priority == 2, "priority: sorted");
    Expect(cands[0].host == "a.example", "priority: stable first among ties");
    Expect(cands[1].host == "c.example", "priority: stable second among ties");
}

void Test_RandomSelectorDeterministic() {
    std::vector<OpenVerifyRucioCandidate> cands = {
        {.host = "a", .port = 1},
        {.host = "b", .port = 2},
        {.host = "c", .port = 3},
        {.host = "d", .port = 4},
    };
    OpenVerifyRucioRandomSelector sel(42);
    OpenVerifyRucioSelectContext ctx;
    sel.Order(cands, ctx);
    std::vector<OpenVerifyRucioCandidate> again = {
        {.host = "a", .port = 1},
        {.host = "b", .port = 2},
        {.host = "c", .port = 3},
        {.host = "d", .port = 4},
    };
    OpenVerifyRucioRandomSelector sel2(42);
    sel2.Order(again, ctx);
    Expect(cands.size() == again.size(), "random: size");
    bool same = true;
    for (size_t i = 0; i < cands.size(); ++i) {
        if (cands[i].host != again[i].host) same = false;
    }
    Expect(same, "random: same seed → same order");
    // With seed 42, order should differ from input for this size (probabilistic but fixed).
    Expect(!(cands[0].host == "a" && cands[1].host == "b" && cands[2].host == "c" && cands[3].host == "d"),
           "random: seed 42 reshuffles");
}

void Test_MakeSelector() {
    Expect(std::string(OpenVerifyRucioMakeSelector("random")->Name()) == "random", "make random");
    Expect(std::string(OpenVerifyRucioMakeSelector("priority")->Name()) == "priority", "make priority");
    Expect(std::string(OpenVerifyRucioMakeSelector("geoip")->Name()) == "geoip", "make geoip");
    Expect(std::string(OpenVerifyRucioMakeSelector("rucio")->Name()) == "rucio", "make rucio");
    Expect(std::string(OpenVerifyRucioMakeSelector("unknown")->Name()) == "rucio", "unknown → rucio");
    unsetenv("XRD_OPENVERIFY_RUCIO_SELECT");
    Expect(OpenVerifyRucioSelectorNameFromEnv() == "rucio", "default selector is rucio");
}

void Test_ParseReplicasNdjson() {
    const std::string body =
        R"({"scope":"cms","name":"/store/x","pfns":{"davs://h.example:2880/store/x":{"rse":"T2_X","priority":1}}})"
        "\n";
    const auto cands = OpenVerifyRucioParseReplicasJson(body, "davs");
    Expect(cands.size() == 1, "ndjson: one davs candidate");
    if (!cands.empty()) {
        Expect(cands[0].host == "h.example" && cands[0].port == 2880, "ndjson host/port");
    }
}

void Test_ParseReplicasHttpAliasFindsDavs() {
    // Rucio never uses scheme "http"; wire http/https must still match davs:// PFNs.
    const std::string body = R"([
      {
        "scope": "cms",
        "name": "/store/x",
        "pfns": {
          "davs://dav.example:2880/store/x": {"rse": "T2_A", "type": "DISK", "priority": 1},
          "https://alt.example:443/store/x": {"rse": "T2_B", "type": "DISK", "priority": 2},
          "root://root.example:1094//store/x": {"rse": "T2_C", "type": "DISK", "priority": 3}
        }
      }
    ])";
    const auto via_http = OpenVerifyRucioParseReplicasJson(body, "http");
    Expect(via_http.size() == 2, "http alias: davs+https PFNs");
    const auto via_davs = OpenVerifyRucioParseReplicasJson(body, "davs");
    Expect(via_davs.size() == 2, "davs: davs+https PFNs");
    const auto via_root = OpenVerifyRucioParseReplicasJson(body, "root");
    Expect(via_root.size() == 1 && via_root[0].host == "root.example", "root ignores davs/https");
}

void Test_ParseReplicasEmpty() {
    Expect(OpenVerifyRucioParseReplicasJson("[]", "root").empty(), "empty array");
    Expect(OpenVerifyRucioParseReplicasJson("not-json", "root").empty(), "bad json");
}

void Test_IsTapeCandidate() {
    OpenVerifyRucioCandidate disk{.rse = "T1_FR_CCIN2P3_Disk", .type = "DISK"};
    OpenVerifyRucioCandidate tape_type{.rse = "SOME_RSE", .type = "TAPE"};
    OpenVerifyRucioCandidate tape_type_ci{.rse = "SOME_RSE", .type = "tape"};
    OpenVerifyRucioCandidate tape_rse{.rse = "T1_FR_CCIN2P3_Tape"};
    OpenVerifyRucioCandidate disk_no_type{.rse = "T1_US_FNAL_Disk"};
    Expect(!OpenVerifyRucioIsTapeCandidate(disk), "disk type+rse");
    Expect(OpenVerifyRucioIsTapeCandidate(tape_type), "type TAPE");
    Expect(OpenVerifyRucioIsTapeCandidate(tape_type_ci), "type tape ci");
    Expect(OpenVerifyRucioIsTapeCandidate(tape_rse), "rse _Tape suffix");
    Expect(!OpenVerifyRucioIsTapeCandidate(disk_no_type), "disk rse no type");
}

void Test_ParseReplicasSkipsTape() {
    // Same gateway host for Disk and Tape (CCIN2P3-style): only Disk must remain.
    const std::string body = R"([
      {
        "scope": "cms",
        "name": "/store/mc/file.root",
        "pfns": {
          "root://ccxrdcms.in2p3.fr:1094//pnfs/in2p3.fr/data/cms/data/store/mc/file.root": {
            "rse": "T1_FR_CCIN2P3_Tape", "type": "TAPE", "priority": 1
          },
          "root://ccxrdcms.in2p3.fr:1094//store/mc/file.root": {
            "rse": "T1_FR_CCIN2P3_Disk", "type": "DISK", "priority": 2
          },
          "root://cmsdcadisk.fnal.gov:1094//dcache/uscmsdisk/store/mc/file.root": {
            "rse": "T1_US_FNAL_Disk", "type": "DISK", "priority": 3
          },
          "root://tape-only.example:1094//store/mc/file.root": {
            "rse": "T1_XX_Tape", "priority": 4
          }
        }
      }
    ])";
    const auto cands = OpenVerifyRucioParseReplicasJson(body, "root");
    Expect(cands.size() == 2, "skip tape: two disk candidates");
    bool saw_ccin2p3_disk = false, saw_fnal = false, saw_tape = false;
    for (const auto& c : cands) {
        if (c.rse == "T1_FR_CCIN2P3_Disk" && c.host == "ccxrdcms.in2p3.fr" &&
            c.pfn.find("//store/mc/") != std::string::npos) {
            saw_ccin2p3_disk = true;
        }
        if (c.rse == "T1_US_FNAL_Disk") saw_fnal = true;
        if (c.rse.find("_Tape") != std::string::npos || c.type == "TAPE") saw_tape = true;
        if (c.pfn.find("/pnfs/") != std::string::npos) saw_tape = true;
    }
    Expect(saw_ccin2p3_disk && saw_fnal, "skip tape: both disk RSEs kept");
    Expect(!saw_tape, "skip tape: no tape pfn/rse left");
}

void Test_ParseIgnorePrefixes() {
    Expect(OpenVerifyRucioParseIgnorePrefixes("").empty(), "empty spec");
    Expect(OpenVerifyRucioParseIgnorePrefixes("   ").empty(), "whitespace spec");
    const auto one = OpenVerifyRucioParseIgnorePrefixes("/store/user");
    Expect(one.size() == 1 && one[0] == "/store/user", "single prefix");
    const auto slashy = OpenVerifyRucioParseIgnorePrefixes("//store/user/");
    Expect(slashy.size() == 1 && slashy[0] == "/store/user", "collapse slashes");
    const auto many = OpenVerifyRucioParseIgnorePrefixes(" /store/user , /store/temp/ ");
    Expect(many.size() == 2, "two prefixes");
    if (many.size() == 2) {
        Expect(many[0] == "/store/user" && many[1] == "/store/temp", "trimmed prefixes");
    }
}

void Test_ShouldIgnoreLfn() {
    const auto prefixes = OpenVerifyRucioParseIgnorePrefixes("/store/user");
    Expect(OpenVerifyRucioShouldIgnoreLfn("/store/user/rchauhan/a.root", prefixes), "user file");
    Expect(OpenVerifyRucioMatchedIgnorePrefix("/store/user/rchauhan/a.root", prefixes) == "/store/user",
           "matched prefix user");
    Expect(OpenVerifyRucioShouldIgnoreLfn("/store/user", prefixes), "exact prefix");
    Expect(OpenVerifyRucioShouldIgnoreLfn("//store/user/foo", prefixes), "double leading slash");
    Expect(!OpenVerifyRucioShouldIgnoreLfn("/store/userdata/a.root", prefixes), "not userdata");
    Expect(OpenVerifyRucioMatchedIgnorePrefix("/store/userdata/a.root", prefixes).empty(), "userdata no match");
    Expect(!OpenVerifyRucioShouldIgnoreLfn("/store/mc/file.root", prefixes), "not mc");
    Expect(!OpenVerifyRucioShouldIgnoreLfn("/store/user", {}), "no prefixes configured");
    Expect(!OpenVerifyRucioShouldIgnoreLfn("", prefixes), "empty lfn");
    const auto multi = OpenVerifyRucioParseIgnorePrefixes("/store/user,/store/temp,/tmp");
    Expect(OpenVerifyRucioShouldIgnoreLfn("/store/temp/x.root", multi), "second prefix");
    Expect(OpenVerifyRucioMatchedIgnorePrefix("/store/temp/x.root", multi) == "/store/temp", "matched temp");
    Expect(OpenVerifyRucioShouldIgnoreLfn("/tmp/xrootd-testfile.global", multi), "tmp testfile");
    Expect(OpenVerifyRucioMatchedIgnorePrefix("/tmp/xrootd-testfile.global", multi) == "/tmp", "matched tmp");
    Expect(OpenVerifyRucioShouldIgnoreLfn("/tmp", multi), "exact tmp");
    Expect(!OpenVerifyRucioShouldIgnoreLfn("/tmpdir/x", multi), "not tmpdir");
    // Same matcher is used for XRD_OPENVERIFY_SKIP_PREFIX (SAM AAA cmsd/TFC pin).
    const auto sam = OpenVerifyRucioParseIgnorePrefixes("/store/test/xrootd");
    Expect(OpenVerifyRucioMatchedIgnorePrefix("/store/test/xrootd/T2_US_Wisconsin/store/mc/SAM/file.root", sam) ==
               "/store/test/xrootd",
           "SAM AAA pin matches skip prefix");
    Expect(OpenVerifyRucioMatchedIgnorePrefix("/store/mc/SAM/file.root", sam).empty(),
           "bare SAM LFN is not the pin");
    Expect(OpenVerifyRucioMatchedIgnorePrefix("/store/test/xrootdfoo/T2_US_Wisconsin/store/mc/SAM/a.root", sam)
               .empty(),
           "path-component match does not prefix-steal");
    Expect(OpenVerifyRucioShouldIgnoreLfn("/store/test/xrootd", sam), "exact SAM pin prefix");
}

}  // namespace

int main() {
    Test_SchemeFromProt();
    Test_NormalizeScheme();
    Test_ParsePfnRoot();
    Test_ParsePfnRootDefaultPort();
    Test_ParsePfnDavs();
    Test_ParsePfnDavsDefaultPort();
    Test_ParsePfnIpv6();
    Test_ParseReplicasJsonArray();
    Test_ParseReplicasNdjson();
    Test_ParseReplicasHttpAliasFindsDavs();
    Test_ParseReplicasEmpty();
    Test_IsTapeCandidate();
    Test_ParseReplicasSkipsTape();
    Test_ParseIgnorePrefixes();
    Test_ShouldIgnoreLfn();
    Test_PrioritySelector();
    Test_ServerOrderSelector();
    Test_RandomSelectorDeterministic();
    Test_MakeSelector();

    if (g_failures) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "All OpenVerifyRucio tests passed\n";
    return 0;
}
