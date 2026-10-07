#pragma once

#include <memory>
#include <string_view>

namespace acpp {
class Outbound;
}  // namespace acpp

namespace acpp::features::outbound {

// ============================================================================
// Manager - outbound feature manager interface. Returned handles own the
// selected handler for the complete dispatcher/outbound coroutine lifetime.
// ============================================================================
class Manager {
public:
    using HandlerPtr = std::shared_ptr<Outbound>;

    virtual ~Manager() noexcept = default;

    [[nodiscard]] virtual HandlerPtr GetHandler(std::string_view tag) noexcept = 0;
};

}  // namespace acpp::features::outbound
