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
        // Parse preserves JSON object iteration order; try-order is a separate selector.
        bool saw_a = false, saw_b = false;
        for (const auto& c : cands) {
            if (c.host == "a.example" && c.port == 1095 && c.rse == "T2_A" && c.priority == 1) saw_a = true;
            if (c.host == "b.example" && c.port == 1094 && c.rse == "T2_B" && c.priority == 2) saw_b = true;
        }
        Expect(saw_a && saw_b, "array: both root PFNs with rse/priority");
    }
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
    Expect(std::string(OpenVerifyRucioMakeSelector("unknown")->Name()) == "random", "unknown → random");
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

void Test_ParseReplicasEmpty() {
    Expect(OpenVerifyRucioParseReplicasJson("[]", "root").empty(), "empty array");
    Expect(OpenVerifyRucioParseReplicasJson("not-json", "root").empty(), "bad json");
}

}  // namespace

int main() {
    Test_SchemeFromProt();
    Test_ParsePfnRoot();
    Test_ParsePfnRootDefaultPort();
    Test_ParsePfnDavs();
    Test_ParsePfnDavsDefaultPort();
    Test_ParsePfnIpv6();
    Test_ParseReplicasJsonArray();
    Test_ParseReplicasNdjson();
    Test_ParseReplicasEmpty();
    Test_PrioritySelector();
    Test_RandomSelectorDeterministic();
    Test_MakeSelector();

    if (g_failures) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "All OpenVerifyRucio tests passed\n";
    return 0;
}
