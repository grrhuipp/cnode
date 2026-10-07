#pragma once

#include <cstdint>
#include <string_view>

namespace acpp::session {
struct Context;
}

namespace acpp::routing {

enum class DomainStrategy : uint8_t {
    AsIs,
    IPIfNonMatch,
    IPOnDemand,
};

struct RouteDecision {
    // Borrowed from the immutable Router; valid for its entire lifetime.
    std::string_view outbound_tag;
    bool matched = false;
    uint32_t rule_index = 0;
};

// Worker-local, immutable rule lookup. Configuration and matcher construction
// belong to the implementation's cold path; fallback belongs to Dispatcher.
class Router {
public:
    virtual ~Router() noexcept = default;

    [[nodiscard]] virtual RouteDecision Route(const session::Context& ctx) const = 0;
    [[nodiscard]] virtual routing::DomainStrategy DomainStrategy() const noexcept = 0;
};

}  // namespace acpp::routing
