#pragma once

#include <cstdlib>
#include <ctime>

// XRD_OPENVERIFY_VERIFY_TIMEOUT: outbound open_verify timeout in seconds (default 5).
inline time_t OpenVerifyTimeoutSeconds() {
    const char* p = std::getenv("XRD_OPENVERIFY_VERIFY_TIMEOUT");
    if (!p || !*p) return 5;
    const long long v = std::strtoll(p, nullptr, 10);
    return v > 0 ? static_cast<time_t>(v) : static_cast<time_t>(5);
}

// FIFO wait limit. Default is twice the verify timeout so waiters can inherit
// a slot after one generation of slow probes. XRD_OPENVERIFY_QUEUE_TIMEOUT_MS
// overrides (milliseconds) when set to a positive value (tests / ops).
inline int OpenVerifyQueueTimeoutMs() {
    const char* p = std::getenv("XRD_OPENVERIFY_QUEUE_TIMEOUT_MS");
    if (p && *p) {
        const int v = std::atoi(p);
        if (v > 0) return v;
    }
    return static_cast<int>(OpenVerifyTimeoutSeconds()) * 2 * 1000;
}
