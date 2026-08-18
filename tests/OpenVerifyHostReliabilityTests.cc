#include <chrono>
#include <cmath>
#include <cstdint>
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
    unsetenv("XRD_OPENVERIFY_FAILSAFE_MAX_SITES");
    unsetenv("XRD_OPENVERIFY_FAILSAFE_WINDOW");
}

OpenVerifyHostReliability::Config FastFailCfg(uint64_t failsafe_max_sites, std::chrono::seconds failsafe_window) {
    OpenVerifyHostReliability::Config cfg;
    cfg.ewma_alpha_fail = 1.0;
    cfg.ewma_alpha_success = 1.0;
    cfg.min_attempts = 1;
    cfg.quarantine_threshold = 0.6;
    cfg.recover_threshold = 0.4;
    cfg.probe_cooldown = std::chrono::seconds(3600);
    cfg.failsafe_max_sites = failsafe_max_sites;
    cfg.failsafe_window = failsafe_window;
    return cfg;
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
    Expect(cfg.failsafe_max_sites == 8, "DefaultConfig: failsafe_max_sites");
    Expect(cfg.failsafe_window.count() == 300, "DefaultConfig: failsafe_window");
}

void Test_InvalidEnvFallsBack() {
    ClearReliabilityEnv();
    EnvGuard a("XRD_OPENVERIFY_EWMA_ALPHA_FAIL", "0");
    EnvGuard b("XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS", "1.5");
    EnvGuard c("XRD_OPENVERIFY_MIN_ATTEMPTS", "0");
    EnvGuard d("XRD_OPENVERIFY_QUARANTINE_THRESHOLD", "nope");
    EnvGuard e("XRD_OPENVERIFY_PROBE_COOLDOWN", "-5");
    EnvGuard g("XRD_OPENVERIFY_FAILSAFE_MAX_SITES", "-1");
    EnvGuard h("XRD_OPENVERIFY_FAILSAFE_WINDOW", "0");
    OpenVerifyHostReliability hr;
    const auto cfg = hr.GetConfig();
    ExpectNear(cfg.ewma_alpha_fail, 0.05, 1e-12, "InvalidEnv: alpha_fail");
    ExpectNear(cfg.ewma_alpha_success, 0.10, 1e-12, "InvalidEnv: alpha_success");
    Expect(cfg.min_attempts == 20, "InvalidEnv: min_attempts");
    ExpectNear(cfg.quarantine_threshold, 0.6, 1e-12, "InvalidEnv: quarantine");
    Expect(cfg.probe_cooldown.count() == 60, "InvalidEnv: probe_cooldown");
    Expect(cfg.failsafe_max_sites == 8, "InvalidEnv: failsafe_max_sites");
    Expect(cfg.failsafe_window.count() == 300, "InvalidEnv: failsafe_window");
}

void Test_EnvOverridesAndRecoverClamp() {
    ClearReliabilityEnv();
    EnvGuard a("XRD_OPENVERIFY_EWMA_ALPHA_FAIL", "0.02");
    EnvGuard b("XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS", "0.25");
    EnvGuard c("XRD_OPENVERIFY_MIN_ATTEMPTS", "3");
    EnvGuard d("XRD_OPENVERIFY_QUARANTINE_THRESHOLD", "0.7");
    EnvGuard e("XRD_OPENVERIFY_RECOVER_THRESHOLD", "0.9");  // above quarantine → clamped
    EnvGuard f("XRD_OPENVERIFY_PROBE_COOLDOWN", "30");
    EnvGuard g("XRD_OPENVERIFY_FAILSAFE_MAX_SITES", "3");
    EnvGuard h("XRD_OPENVERIFY_FAILSAFE_WINDOW", "120");
    OpenVerifyHostReliability hr;
    const auto cfg = hr.GetConfig();
    ExpectNear(cfg.ewma_alpha_fail, 0.02, 1e-12, "EnvOverrides: alpha_fail");
    ExpectNear(cfg.ewma_alpha_success, 0.25, 1e-12, "EnvOverrides: alpha_success");
    Expect(cfg.min_attempts == 3, "EnvOverrides: min_attempts");
    ExpectNear(cfg.quarantine_threshold, 0.7, 1e-12, "EnvOverrides: quarantine");
    ExpectNear(cfg.recover_threshold, 0.7, 1e-12, "EnvOverrides: recover clamped to quarantine");
    Expect(cfg.probe_cooldown.count() == 30, "EnvOverrides: probe_cooldown");
    Expect(cfg.failsafe_max_sites == 3, "EnvOverrides: failsafe_max_sites");
    Expect(cfg.failsafe_window.count() == 120, "EnvOverrides: failsafe_window");
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

void Test_FailSafeTripsAndReleases() {
    auto now = std::chrono::steady_clock::now();
    OpenVerifyHostReliability hr(FastFailCfg(2, std::chrono::seconds(60)), [&now] { return now; });

    hr.RecordVerifyFailure("a.example", 1094, 100);
    Expect(!FindSite(hr, "a.example").healthy, "FailSafe: first site quarantined");
    Expect(hr.AvoidSite("a.example", 1094), "FailSafe: first site avoided");
    Expect(!hr.GetFailSafeSnapshot().active, "FailSafe: not tripped after 1 site");

    hr.RecordVerifyFailure("b.example", 1094, 100);
    const auto fs = hr.GetFailSafeSnapshot();
    Expect(fs.active, "FailSafe: tripped after 2 sites in window");
    Expect(fs.trips == 1, "FailSafe: one trip");
    Expect(FindSite(hr, "a.example").healthy, "FailSafe: released site a");
    Expect(FindSite(hr, "b.example").healthy, "FailSafe: released site b");
    Expect(!hr.AvoidSite("a.example", 1094), "FailSafe: no longer avoids a");
    Expect(!hr.AvoidSite("b.example", 1094), "FailSafe: no longer avoids b");

    hr.RecordVerifyFailure("c.example", 1094, 100);
    Expect(FindSite(hr, "c.example").healthy, "FailSafe: third site not quarantined while active");
    Expect(!hr.AvoidSite("c.example", 1094), "FailSafe: does not avoid new site while active");
}

void Test_FailSafeSameSiteDoesNotTrip() {
    auto now = std::chrono::steady_clock::now();
    OpenVerifyHostReliability hr(FastFailCfg(2, std::chrono::seconds(60)), [&now] { return now; });

    hr.RecordVerifyFailure("a.example", 1094, 100);
    hr.RecordVerifySuccess("a.example", 1094);  // recover
    hr.RecordVerifyFailure("a.example", 1094, 100);
    Expect(!FindSite(hr, "a.example").healthy, "FailSafeSameSite: re-quarantined");
    Expect(!hr.GetFailSafeSnapshot().active, "FailSafeSameSite: unique-site count is 1");
    Expect(hr.GetFailSafeSnapshot().recent_sites == 1, "FailSafeSameSite: one unique entry");
}

void Test_FailSafeClearsAfterHold() {
    auto now = std::chrono::steady_clock::now();
    OpenVerifyHostReliability hr(FastFailCfg(2, std::chrono::seconds(60)), [&now] { return now; });

    hr.RecordVerifyFailure("a.example", 1094, 100);
    hr.RecordVerifyFailure("b.example", 1094, 100);
    Expect(hr.GetFailSafeSnapshot().active, "FailSafeHold: tripped");

    now += std::chrono::seconds(59);
    Expect(hr.AvoidSite("a.example", 1094) == false, "FailSafeHold: still held just before expiry");
    Expect(hr.GetFailSafeSnapshot().active, "FailSafeHold: still active at T-1s");

    now += std::chrono::seconds(1);
    Expect(!hr.AvoidSite("a.example", 1094), "FailSafeHold: AvoidSite prunes/clears at T");
    Expect(!hr.GetFailSafeSnapshot().active, "FailSafeHold: cleared after hold");
    Expect(hr.GetFailSafeSnapshot().recent_sites == 0, "FailSafeHold: window reset on clear");

    hr.RecordVerifyFailure("c.example", 1094, 100);
    Expect(!FindSite(hr, "c.example").healthy, "FailSafeHold: can quarantine again after clear");
    Expect(hr.AvoidSite("c.example", 1094), "FailSafeHold: avoids newly quarantined site");
    Expect(!hr.GetFailSafeSnapshot().active, "FailSafeHold: single site does not re-trip");
}

void Test_FailSafeDisabled() {
    auto now = std::chrono::steady_clock::now();
    OpenVerifyHostReliability hr(FastFailCfg(0, std::chrono::seconds(60)), [&now] { return now; });

    hr.RecordVerifyFailure("a.example", 1094, 100);
    hr.RecordVerifyFailure("b.example", 1094, 100);
    hr.RecordVerifyFailure("c.example", 1094, 100);
    Expect(!FindSite(hr, "a.example").healthy, "FailSafeOff: a quarantined");
    Expect(!FindSite(hr, "b.example").healthy, "FailSafeOff: b quarantined");
    Expect(!FindSite(hr, "c.example").healthy, "FailSafeOff: c quarantined");
    Expect(hr.AvoidSite("a.example", 1094), "FailSafeOff: still avoids");
    Expect(!hr.GetFailSafeSnapshot().active, "FailSafeOff: never trips when max_sites=0");
    Expect(hr.GetFailSafeSnapshot().trips == 0, "FailSafeOff: no trips");
}

}  // namespace

int main() {
    Test_DefaultConfig();
    Test_InvalidEnvFallsBack();
    Test_EnvOverridesAndRecoverClamp();
    Test_QuarantineAndRecover();
    Test_MinAttemptsHoldsQuarantine();
    Test_FailSafeTripsAndReleases();
    Test_FailSafeSameSiteDoesNotTrip();
    Test_FailSafeClearsAfterHold();
    Test_FailSafeDisabled();

    if (g_failures) {
        std::cerr << g_failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "All tests passed.\n";
    return 0;
}
