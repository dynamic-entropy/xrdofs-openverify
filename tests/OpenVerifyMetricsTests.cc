#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "OpenVerifyMetrics.hh"

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

bool ReadCacheMiss(const std::string& path, uint64_t& out) {
    std::ifstream in(path);
    if (!in) return false;
    const std::string needle = "xrootd_openverify_cache_lookups_total{result=\"miss\"";
    std::string line;
    while (std::getline(in, line)) {
        if (line.compare(0, needle.size(), needle) != 0) continue;
        const auto sp = line.rfind(' ');
        if (sp == std::string::npos) return false;
        out = std::strtoull(line.c_str() + sp + 1, nullptr, 10);
        return true;
    }
    return false;
}

// Prometheus treats any decrease of a counter as a reset; the textfile must be monotonic.
void Test_ConcurrentFlushNeverGoesBackwards() {
    const std::string path = "/tmp/openverify_metrics_test_" + std::to_string(getpid()) + ".prom";
    setenv("XRD_OPENVERIFY_METRICS_PATH", path.c_str(), 1);
    setenv("XRD_OPENVERIFY_METRICS_INSTANCE", "test", 1);

    OpenVerifyMetrics metrics;
    constexpr int kWriters = 8;
    constexpr int kPerWriter = 2000;

    std::atomic<bool> writers_done{false};
    uint64_t regressions = 0;
    uint64_t last = 0;
    std::thread reader([&]() {
        while (!writers_done.load()) {
            uint64_t v = 0;
            if (ReadCacheMiss(path, v)) {
                if (v < last) ++regressions;
                last = v;
            }
        }
    });

    std::vector<std::thread> writers;
    for (int i = 0; i < kWriters; ++i) {
        writers.emplace_back([&]() {
            for (int j = 0; j < kPerWriter; ++j) metrics.RecordCacheMiss();
        });
    }
    std::vector<std::thread> flushers;
    for (int i = 0; i < 2; ++i) {
        flushers.emplace_back([&]() {
            while (!writers_done.load()) metrics.FlushNow();
        });
    }
    for (auto& t : writers) t.join();
    writers_done = true;
    for (auto& t : flushers) t.join();
    metrics.FlushNow();
    writers_done = true;
    reader.join();

    uint64_t final_value = 0;
    Expect(ReadCacheMiss(path, final_value), "metrics file readable");
    Expect(final_value == static_cast<uint64_t>(kWriters) * kPerWriter,
           "final file holds the last value (got " + std::to_string(final_value) + ")");
    Expect(regressions == 0, "counter never decreases in the file (regressions=" + std::to_string(regressions) + ")");

    std::remove(path.c_str());
    unsetenv("XRD_OPENVERIFY_METRICS_PATH");
}

}  // namespace

int main() {
    Test_ConcurrentFlushNeverGoesBackwards();
    if (g_failures) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "All metrics tests passed\n";
    return 0;
}
