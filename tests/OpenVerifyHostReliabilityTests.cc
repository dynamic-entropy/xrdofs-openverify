#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "OpenVerifyHostReliability.hh"

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

void ExpectNear(double got, double want, double eps, const std::string& msg) {
    if (!(std::fabs(got - want) <= eps)) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << " got=" << got << " want=" << want << "\n";
    }
}

struct EnvGuard {
    std::string name;
    std::string old;
    bool had{false};

    EnvGuard(const char* n, const char* v) : name(n) {
        const char* p = std::getenv(n);
        had = p != nullptr;
        if (had) old = p;
        setenv(n, v, 1);
    }

    ~EnvGuard() {
        if (had) {
            setenv(name.c_str(), old.c_str(), 1);
        } else {
            unsetenv(name.c_str());
        }
    }

    EnvGuard(const EnvGuard&) = delete;
    EnvGuard& operator=(const EnvGuard&) = delete;
};

void ClearReliabilityEnv() {
    unsetenv("XRD_OPENVERIFY_EWMA_ALPHA_FAIL");
    unsetenv("XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS");
    unsetenv("XRD_OPENVERIFY_MIN_ATTEMPTS");
    unsetenv("XRD_OPENVERIFY_QUARANTINE_THRESHOLD");
    unsetenv("XRD_OPENVERIFY_RECOVER_THRESHOLD");
    unsetenv("XRD_OPENVERIFY_PROBE_COOLDOWN");
}

OpenVerifyHostReliability::SiteSnapshot FindSite(const OpenVerifyHostReliability& hr, const std::string& host) {
    for (const auto& s : hr.Snapshot()) {
        if (s.host == host) return s;
    }
    return {};
}

void Test_DefaultConfig() {
    ClearReliabilityEnv();
    OpenVerifyHostReliability hr;
    const auto cfg = hr.GetConfig();
    ExpectNear(cfg.ewma_alpha_fail, 0.05, 1e-12, "DefaultConfig: alpha_fail");
    ExpectNear(cfg.ewma_alpha_success, 0.10, 1e-12, "DefaultConfig: alpha_success");
    Expect(cfg.min_attempts == 20, "DefaultConfig: min_attempts");
    ExpectNear(cfg.quarantine_threshold, 0.6, 1e-12, "DefaultConfig: quarantine");
    ExpectNear(cfg.recover_threshold, 0.4, 1e-12, "DefaultConfig: recover");
    Expect(cfg.probe_cooldown.count() == 60, "DefaultConfig: probe_cooldown");
}

void Test_InvalidEnvFallsBack() {
    ClearReliabilityEnv();
    EnvGuard a("XRD_OPENVERIFY_EWMA_ALPHA_FAIL", "0");
    EnvGuard b("XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS", "1.5");
    EnvGuard c("XRD_OPENVERIFY_MIN_ATTEMPTS", "0");
    EnvGuard d("XRD_OPENVERIFY_QUARANTINE_THRESHOLD", "nope");
    EnvGuard e("XRD_OPENVERIFY_PROBE_COOLDOWN", "-5");
    OpenVerifyHostReliability hr;
    const auto cfg = hr.GetConfig();
    ExpectNear(cfg.ewma_alpha_fail, 0.05, 1e-12, "InvalidEnv: alpha_fail");
    ExpectNear(cfg.ewma_alpha_success, 0.10, 1e-12, "InvalidEnv: alpha_success");
    Expect(cfg.min_attempts == 20, "InvalidEnv: min_attempts");
    ExpectNear(cfg.quarantine_threshold, 0.6, 1e-12, "InvalidEnv: quarantine");
    Expect(cfg.probe_cooldown.count() == 60, "InvalidEnv: probe_cooldown");
}

void Test_EnvOverridesAndRecoverClamp() {
    ClearReliabilityEnv();
    EnvGuard a("XRD_OPENVERIFY_EWMA_ALPHA_FAIL", "0.02");
    EnvGuard b("XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS", "0.25");
    EnvGuard c("XRD_OPENVERIFY_MIN_ATTEMPTS", "3");
    EnvGuard d("XRD_OPENVERIFY_QUARANTINE_THRESHOLD", "0.7");
    EnvGuard e("XRD_OPENVERIFY_RECOVER_THRESHOLD", "0.9");  // above quarantine → clamped
    EnvGuard f("XRD_OPENVERIFY_PROBE_COOLDOWN", "30");
    OpenVerifyHostReliability hr;
    const auto cfg = hr.GetConfig();
    ExpectNear(cfg.ewma_alpha_fail, 0.02, 1e-12, "EnvOverrides: alpha_fail");
    ExpectNear(cfg.ewma_alpha_success, 0.25, 1e-12, "EnvOverrides: alpha_success");
    Expect(cfg.min_attempts == 3, "EnvOverrides: min_attempts");
    ExpectNear(cfg.quarantine_threshold, 0.7, 1e-12, "EnvOverrides: quarantine");
    ExpectNear(cfg.recover_threshold, 0.7, 1e-12, "EnvOverrides: recover clamped to quarantine");
    Expect(cfg.probe_cooldown.count() == 30, "EnvOverrides: probe_cooldown");
}

void Test_QuarantineAndRecover() {
    ClearReliabilityEnv();
    EnvGuard a("XRD_OPENVERIFY_EWMA_ALPHA_FAIL", "1.0");
    EnvGuard b("XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS", "1.0");
    EnvGuard c("XRD_OPENVERIFY_MIN_ATTEMPTS", "1");
    EnvGuard d("XRD_OPENVERIFY_QUARANTINE_THRESHOLD", "0.6");
    EnvGuard e("XRD_OPENVERIFY_RECOVER_THRESHOLD", "0.4");
    EnvGuard f("XRD_OPENVERIFY_PROBE_COOLDOWN", "3600");
    OpenVerifyHostReliability hr;

    hr.RecordVerifyFailure("ex.example", 1094, 100);  // connectivity penalty 1.0 → ewma=1.0
    auto snap = FindSite(hr, "ex.example");
    ExpectNear(snap.ewma_health, 1.0, 1e-12, "Quarantine: ewma after one fail");
    Expect(!snap.healthy, "Quarantine: site should be unhealthy");
    Expect(hr.AvoidSite("ex.example", 1094), "Quarantine: should avoid during cooldown");

    hr.RecordVerifySuccess("ex.example", 1094);  // alpha_success=1 → ewma=0
    snap = FindSite(hr, "ex.example");
    ExpectNear(snap.ewma_health, 0.0, 1e-12, "Recover: ewma after one success");
    Expect(snap.healthy, "Recover: site should be healthy");
    Expect(!hr.AvoidSite("ex.example", 1094), "Recover: should not avoid healthy site");
}

void Test_MinAttemptsHoldsQuarantine() {
    ClearReliabilityEnv();
    EnvGuard a("XRD_OPENVERIFY_EWMA_ALPHA_FAIL", "1.0");
    EnvGuard b("XRD_OPENVERIFY_MIN_ATTEMPTS", "3");
    EnvGuard c("XRD_OPENVERIFY_QUARANTINE_THRESHOLD", "0.5");
    OpenVerifyHostReliability hr;

    hr.RecordVerifyFailure("slow.example", 1094, 100);
    hr.RecordVerifyFailure("slow.example", 1094, 100);
    auto snap = FindSite(hr, "slow.example");
    Expect(snap.healthy, "MinAttempts: still healthy before 3 attempts");
    ExpectNear(snap.ewma_health, 1.0, 1e-12, "MinAttempts: ewma already high");

    hr.RecordVerifyFailure("slow.example", 1094, 100);
    snap = FindSite(hr, "slow.example");
    Expect(!snap.healthy, "MinAttempts: quarantined once min_attempts is met");
}

}  // namespace

int main() {
    Test_DefaultConfig();
    Test_InvalidEnvFallsBack();
    Test_EnvOverridesAndRecoverClamp();
    Test_QuarantineAndRecover();
    Test_MinAttemptsHoldsQuarantine();

    if (g_failures) {
        std::cerr << g_failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "All tests passed.\n";
    return 0;
}
