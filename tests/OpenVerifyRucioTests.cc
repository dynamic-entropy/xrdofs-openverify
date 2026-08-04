#include <iostream>
#include <string>

#include "OpenVerifyRucio.hh"

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
        Expect(cands[0].host == "a.example" && cands[0].port == 1095, "array: priority 1 first");
        Expect(cands[0].rse == "T2_A", "array: rse A");
        Expect(cands[1].host == "b.example" && cands[1].port == 1094, "array: priority 2 second");
    }
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

    if (g_failures) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "All OpenVerifyRucio tests passed\n";
    return 0;
}
