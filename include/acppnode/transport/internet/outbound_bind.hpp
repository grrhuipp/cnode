#pragma once

#include "acppnode/common/asio_types.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace acpp {

class OutboundBind {
public:
    enum class Mode : uint8_t {
        None,
        Auto,
        Explicit,
    };

    OutboundBind() = default;

    [[nodiscard]] Mode GetMode() const noexcept { return mode_; }
    [[nodiscard]] const std::optional<net::ip::address>& ExplicitAddress() const noexcept {
        return explicit_address_;
    }

    [[nodiscard]] static OutboundBind Auto() noexcept;
    [[nodiscard]] static std::optional<OutboundBind> Parse(std::string_view value);

private:
    Mode mode_ = Mode::None;
    std::optional<net::ip::address> explicit_address_;
};

}  // namespace acpp
