#pragma once

#include <memory>
#include <string>
#include <vector>

#include "OpenVerifyRucio.hh"

// Pluggable try-order for Rucio PFN candidates.
//
// OpenVerify always walks candidates sequentially and only advances on failure
// (observe: first only). The selector only chooses the order.
//
// XRD_OPENVERIFY_RUCIO_SELECT:
//   random   — shuffle (default)
//   priority — Rucio PFN priority ascending (previous behaviour)
//   geoip    — reserved; currently falls back to random until geo ranking lands

struct OpenVerifyRucioSelectContext {
    std::string client_ip;
};

class OpenVerifyRucioSelector {
   public:
    virtual ~OpenVerifyRucioSelector() = default;
    virtual const char* Name() const = 0;
    // Reorder in-place. Must not drop or invent candidates.
    virtual void Order(std::vector<OpenVerifyRucioCandidate>& candidates,
                       const OpenVerifyRucioSelectContext& ctx) const = 0;
};

// Fisher–Yates shuffle. Optional fixed seed for tests.
class OpenVerifyRucioRandomSelector final : public OpenVerifyRucioSelector {
   public:
    OpenVerifyRucioRandomSelector() = default;
    explicit OpenVerifyRucioRandomSelector(uint64_t seed) : m_seed(seed), m_has_seed(true) {}

    const char* Name() const override { return "random"; }
    void Order(std::vector<OpenVerifyRucioCandidate>& candidates,
               const OpenVerifyRucioSelectContext& ctx) const override;

   private:
    uint64_t m_seed{0};
    bool m_has_seed{false};
};

// Stable sort by Rucio priority (lower first).
class OpenVerifyRucioPrioritySelector final : public OpenVerifyRucioSelector {
   public:
    const char* Name() const override { return "priority"; }
    void Order(std::vector<OpenVerifyRucioCandidate>& candidates,
               const OpenVerifyRucioSelectContext& ctx) const override;
};

// Placeholder for client geo-IP / distance ranking. Falls back to random.
class OpenVerifyRucioGeoIpSelector final : public OpenVerifyRucioSelector {
   public:
    const char* Name() const override { return "geoip"; }
    void Order(std::vector<OpenVerifyRucioCandidate>& candidates,
               const OpenVerifyRucioSelectContext& ctx) const override;

   private:
    OpenVerifyRucioRandomSelector m_fallback;
};

// Build selector from env name ("random"|"priority"|"geoip"). Unknown → random.
std::unique_ptr<OpenVerifyRucioSelector> OpenVerifyRucioMakeSelector(const std::string& name);
std::string OpenVerifyRucioSelectorNameFromEnv();
