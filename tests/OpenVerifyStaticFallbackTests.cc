#include <iostream>
#include <string>

#include "OpenVerifyStaticFallback.hh"

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

void Test_BareHost() {
    Expect(IsStaticXrootdFallbackHost("cms-xrd-transit.cern.ch"), "bare transit host");
    Expect(!IsStaticXrootdFallbackHost("cms-xrd-global.cern.ch"), "global is not transit");
    Expect(!IsStaticXrootdFallbackHost(""), "empty host");
    Expect(!IsStaticXrootdFallbackHost("cms-xrd-transit.cern.ch.evil.example"), "suffix spoof");
}

void Test_UrlHost() {
    Expect(IsStaticXrootdFallbackHost("root://cms-xrd-transit.cern.ch:1094//store/foo"), "root URL");
    Expect(IsStaticXrootdFallbackHost("https://cms-xrd-transit.cern.ch:1094/store/foo"), "https URL");
    Expect(IsStaticXrootdFallbackHost("root://cms-xrd-transit.cern.ch//store/foo"), "root URL no port");
    Expect(!IsStaticXrootdFallbackHost("root://cms-xrd-transit.cern.ch.evil.example:1094//x"), "URL spoof");
    Expect(!IsStaticXrootdFallbackHost("root://other.cern.ch:1094//store/foo"), "other host URL");
}

void Test_FallbackLabel() {
    Expect(std::string(StaticXrootdFallbackLabel("cms-xrd-transit.cern.ch")) == "transit", "label transit");
    Expect(std::string(StaticXrootdFallbackLabel("disk.example.edu")) == "unknown", "label unknown");
}

}  // namespace

int main() {
    Test_BareHost();
    Test_UrlHost();
    Test_FallbackLabel();
    if (g_failures) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "ok\n";
    return 0;
}
