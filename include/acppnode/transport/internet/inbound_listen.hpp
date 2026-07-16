#pragma once

#include "acppnode/common/asio_types.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace acpp {

class InboundListen {
public:
    InboundListen() noexcept;

    [[nodiscard]] bool IsAuto() const noexcept { return candidate_count_ == 2; }
    [[nodiscard]] std::span<const net::ip::address> Candidates() const noexcept {
        return {candidates_.data(), candidate_count_};
    }

    [[nodiscard]] static std::optional<InboundListen> Parse(std::string_view value);

private:
    std::array<net::ip::address, 2> candidates_{};
    uint8_t candidate_count_ = 2;
};

}  // namespace acpp
