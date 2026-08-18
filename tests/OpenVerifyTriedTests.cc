#include <iostream>
#include <string>

#include "OpenVerifyTried.hh"

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

void Test_ParseTriedHosts() {
    Expect(ParseTriedHosts(nullptr).empty(), "null opaque");
    Expect(ParseTriedHosts("").empty(), "empty opaque");
    Expect(ParseTriedHosts("authz=Bearer%20secret").empty(), "no tried= key");

    const auto one = ParseTriedHosts("tried=disk.example.edu:1094");
    Expect(one.count("disk.example.edu:1094") == 1 && one.size() == 1, "bare tried=");

    const auto q = ParseTriedHosts("?tried=h1,h2:1094");
    Expect(q.count("h1") && q.count("h2:1094") && q.size() == 2, "leading ? and comma list");

    const auto mixed = ParseTriedHosts("authz=Bearer%20secret&tried=h1, h2:1094 ,h3&foo=1");
    Expect(mixed.count("h1") && mixed.count("h2:1094") && mixed.count("h3") && mixed.size() == 3,
           "tried= among other cgi; whitespace trimmed");
    Expect(!mixed.count("Bearer%20secret") && !mixed.count("authz"), "authz value is not a tried host");
}

void Test_IsInTriedList() {
    const auto tried = ParseTriedHosts("tried=disk.example.edu,cmsdcadisk.fnal.gov:1094");
    Expect(IsInTriedList(tried, "disk.example.edu", 1094), "bare host matches any port");
    Expect(IsInTriedList(tried, "cmsdcadisk.fnal.gov", 1094), "host:port matches");
    Expect(!IsInTriedList(tried, "cmsdcadisk.fnal.gov", 1095), "host:port does not match other port");
    Expect(!IsInTriedList(tried, "other.edu", 1094), "unknown host");
    Expect(!IsInTriedList({}, "disk.example.edu", 1094), "empty list");
}

void Test_AppendTriedHost() {
    std::string tried;
    AppendTriedHost(tried, "a:1094");
    Expect(tried == "a:1094", "first host");
    AppendTriedHost(tried, "b:1094");
    Expect(tried == "a:1094,b:1094", "comma-append");
}

void Test_MergeTriedOpaque() {
    Expect(MergeTriedOpaque("authz=secret", "h:1094", /*observe=*/true) == "authz=secret",
           "observe leaves opaque unchanged");
    Expect(MergeTriedOpaque("authz=secret", "", /*observe=*/false) == "authz=secret",
           "empty tried_hosts leaves opaque unchanged");
    Expect(MergeTriedOpaque(nullptr, "h:1094", false) == "tried=h:1094", "null opaque becomes tried=");

    const std::string with_token = MergeTriedOpaque("authz=Bearer%20secret&foo=1", "h:1094", false);
    Expect(with_token.find("authz=Bearer%20secret") != std::string::npos, "merge keeps authz=");
    Expect(with_token.find("tried=h:1094") != std::string::npos, "merge appends tried=");
    Expect(with_token.find("foo=1") != std::string::npos, "merge keeps other keys");

    const std::string extend = MergeTriedOpaque("tried=h1:1094&x=1", "h2:1094", false);
    Expect(extend.find("tried=h1:1094,h2:1094") != std::string::npos, "extend existing tried= before next &");
    Expect(extend.find("&x=1") != std::string::npos, "keys after tried= preserved");

    Expect(MergeTriedOpaque("tried=h1", "h2", false) == "tried=h1,h2", "extend tried= at end");
}

}  // namespace

int main() {
    Test_ParseTriedHosts();
    Test_IsInTriedList();
    Test_AppendTriedHost();
    Test_MergeTriedOpaque();
    if (g_failures) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "ok\n";
    return 0;
}
