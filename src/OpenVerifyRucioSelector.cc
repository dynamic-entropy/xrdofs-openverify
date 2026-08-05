#include "OpenVerifyRucioSelector.hh"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <random>

namespace {

std::string ToLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

}  // namespace

void OpenVerifyRucioRandomSelector::Order(std::vector<OpenVerifyRucioCandidate>& candidates,
                                          const OpenVerifyRucioSelectContext& /*ctx*/) const {
    if (candidates.size() < 2) return;
    if (m_has_seed) {
        std::mt19937 rng(static_cast<std::mt19937::result_type>(m_seed));
        std::shuffle(candidates.begin(), candidates.end(), rng);
        return;
    }
    thread_local std::mt19937 rng{std::random_device{}()};
    std::shuffle(candidates.begin(), candidates.end(), rng);
}

void OpenVerifyRucioPrioritySelector::Order(std::vector<OpenVerifyRucioCandidate>& candidates,
                                            const OpenVerifyRucioSelectContext& /*ctx*/) const {
    std::stable_sort(candidates.begin(), candidates.end(),
                     [](const OpenVerifyRucioCandidate& a, const OpenVerifyRucioCandidate& b) {
                         return a.priority < b.priority;
                     });
}

void OpenVerifyRucioGeoIpSelector::Order(std::vector<OpenVerifyRucioCandidate>& candidates,
                                         const OpenVerifyRucioSelectContext& ctx) const {
    // TODO: rank by distance from ctx.client_ip (MaxMind / site geo map).
    // Keep try-on-failure walk; only the order changes once geo ranking lands.
    (void)ctx;
    m_fallback.Order(candidates, ctx);
}

std::string OpenVerifyRucioSelectorNameFromEnv() {
    const char* v = std::getenv("XRD_OPENVERIFY_RUCIO_SELECT");
    if (!v || !*v) return "random";
    return ToLower(v);
}

std::unique_ptr<OpenVerifyRucioSelector> OpenVerifyRucioMakeSelector(const std::string& name) {
    const std::string n = ToLower(name);
    if (n == "priority") return std::make_unique<OpenVerifyRucioPrioritySelector>();
    if (n == "geoip") return std::make_unique<OpenVerifyRucioGeoIpSelector>();
    // Default / unknown → random
    return std::make_unique<OpenVerifyRucioRandomSelector>();
}
