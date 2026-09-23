#pragma once

#include "acppnode/common/asio_types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace acpp {

class OutboundBind {
public:
    enum class Mode : uint8_t {
        None,
        Auto,
        Explicit,
        Ordered,
    };

    enum class ChoicePolicy : uint8_t { Random, SourceHash };

    struct Selection {
        std::optional<net::ip::address> address; // Empty only when no same-family entry exists.
    };

    OutboundBind() = default;

    [[nodiscard]] Mode GetMode() const noexcept { return mode_; }
    [[nodiscard]] bool PrefersIPv6() const noexcept {
        return mode_ == Mode::Ordered && entries_ && !entries_->empty() && entries_->front().is_v6;
    }
    [[nodiscard]] const std::optional<net::ip::address>& ExplicitAddress() const noexcept {
        return explicit_address_;
    }

    [[nodiscard]] static OutboundBind Auto() noexcept;
    [[nodiscard]] static std::optional<OutboundBind> Parse(std::string_view value);
    [[nodiscard]] static std::optional<OutboundBind> ParseCandidates(
        std::span<const std::string_view> entries, ChoicePolicy policy);
    [[nodiscard]] Selection Select(
        const net::ip::address& remote,
        std::string_view inbound_source_ip,
        uint16_t inbound_source_port) const noexcept;

private:
    struct Entry {
        bool is_v6 = false;
        net::ip::address network_or_ip;
        uint8_t prefix_length = 0;
    };

    Mode mode_ = Mode::None;
    ChoicePolicy policy_ = ChoicePolicy::SourceHash;
    std::optional<net::ip::address> explicit_address_;
    std::shared_ptr<const std::vector<Entry>> entries_; // Immutable cold-path snapshot.
};

}  // namespace acpp
