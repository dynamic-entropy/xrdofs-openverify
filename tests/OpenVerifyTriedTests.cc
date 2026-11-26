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

    Expect(TriedCgiValue("authz=x&tried=h1,h2&foo=1") == "h1,h2", "raw cgi value for logs");
    Expect(TriedCgiValue(nullptr).empty(), "null cgi value");

    // `tried=` inside another parameter's value must not hide the real key.
    const char* buried = "xrd.gsiusrpxy=/var/lib/condor/tried=not-a-host&tried=real.edu&foo=1";
    Expect(TriedCgiValue(buried) == "real.edu", "tried= key is not a substring of another value");
    const auto buried_hosts = ParseTriedHosts(buried);
    Expect(buried_hosts.count("real.edu") == 1 && buried_hosts.count("not-a-host") == 0,
           "parser ignores tried= embedded in a proxy path");

    // Legacy "+NN<hostname>" (NN is the hostname length). cmsd treats '+' as a cluster id.
    const char* legacy = "tried=+16disk.example.edu,+15other.example";
    const auto leg = ParseTriedHosts(legacy);
    Expect(leg.count("+16disk.example.edu") == 1, "legacy token kept raw");
    Expect(leg.count("disk.example.edu") == 1, "legacy +NN indexes the hostname");
    Expect(IsInTriedList(leg, "disk.example.edu", 1094), "legacy +NN matches the host at any port");
    Expect(!IsInTriedList(leg, "other.example", 1094), "wrong length is not decoded as a hostname");

    Expect(NormalizeCmsdTriedEntry("2001:db8::10") == "[2001:db8::10]",
           "unbracketed ipv6 does not drop a trailing hextet");
    Expect(NormalizeCmsdTriedEntry("[2001:db8::1]:1094") == "[2001:db8::1]",
           "bracketed ipv6 drops the :port after ]");
    Expect(NormalizeCmsdTriedEntry("disk.example.edu:1094") == "disk.example.edu",
           "single-colon host:port still drops the port");
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
    Expect(MergeTriedOpaque(nullptr, "h:1094", false) == "tried=h", "null opaque becomes bare tried=");

    const std::string with_token = MergeTriedOpaque("authz=Bearer%20secret&foo=1", "h:1094", false);
    Expect(with_token.find("authz=Bearer%20secret") != std::string::npos, "merge keeps authz=");
    Expect(with_token.find("tried=h") != std::string::npos, "merge appends bare host cmsd can resolve");
    Expect(with_token.find("foo=1") != std::string::npos, "merge keeps other keys");
    Expect(with_token.find("h:1094") == std::string::npos, "merge drops :port (Same() ignores it; a bad port drops the token)");

    const std::string extend = MergeTriedOpaque("tried=h1:1094&x=1", "h2:1094", false);
    Expect(extend.find("tried=h1,h2") != std::string::npos, "extend existing tried= as bare hosts before next &");
    Expect(extend.find("&x=1") != std::string::npos, "keys after tried= preserved");

    Expect(MergeTriedOpaque("tried=h1", "h2", false) == "tried=h1,h2", "extend tried= at end");

    // "+NN<host>" in the client list is rewritten so do_SelAvoid does not treat it as a cluster id.
    const std::string legacy = MergeTriedOpaque("tried=+16disk.example.edu&authz=secret", "disk.example.edu:1094", false);
    Expect(legacy.find("tried=disk.example.edu") != std::string::npos, "legacy +NN rewritten to hostname");
    Expect(legacy.find("+16") == std::string::npos, "length prefix is not forwarded");
    Expect(legacy.find("authz=secret") != std::string::npos, "rewrite keeps authz");
    Expect(legacy.find("disk.example.edu,disk.example.edu") == std::string::npos, "rewritten host is not duplicated");

    // A tried= embedded in another value must not be the insertion point.
    const std::string buried = MergeTriedOpaque("xrd.gsiusrpxy=/tmp/tried=nope&foo=1", "real.edu", false);
    Expect(buried.find("xrd.gsiusrpxy=/tmp/tried=nope") != std::string::npos, "proxy path left intact");
    Expect(buried.find("&tried=real.edu") != std::string::npos || buried.find("tried=real.edu") != std::string::npos,
           "real tried= key appended");
    Expect(buried.find("tried=nope,real.edu") == std::string::npos, "does not extend the embedded tried=");
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
