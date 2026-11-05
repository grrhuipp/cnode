#pragma once

#include <memory>
#include <string_view>

namespace acpp {
class Outbound;
}  // namespace acpp

namespace acpp::features::outbound {

// ============================================================================
// HandlerLookup - dispatcher-facing outbound handler lookup. Returned handles
// own the selected handler for the complete dispatcher/outbound coroutine
// lifetime.
// ============================================================================
class HandlerLookup {
public:
    using HandlerPtr = std::shared_ptr<Outbound>;

    virtual ~HandlerLookup() noexcept = default;

    [[nodiscard]] virtual HandlerPtr GetHandler(std::string_view tag) = 0;
};

}  // namespace acpp::features::outbound
