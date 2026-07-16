#pragma once

#include <string_view>

namespace acpp {
class Outbound;
}  // namespace acpp

namespace acpp::features::outbound {

// ============================================================================
// Manager - outbound feature manager interface
// ============================================================================
class Manager {
public:
    virtual ~Manager() noexcept = default;

    [[nodiscard]] virtual Outbound* GetHandler(std::string_view tag) noexcept = 0;
    [[nodiscard]] virtual Outbound* GetDefaultHandler() noexcept = 0;
};

}  // namespace acpp::features::outbound
