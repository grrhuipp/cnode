#pragma once

#include "common/asio_types.hpp"
#include "common/ip_address.hpp"
#include "common/constants.hpp"
#include "common/ascii.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>


namespace transport {

class InboundListen {
public:
    InboundListen() noexcept {
        candidates_[0] = net::ip::address_v4::any();
        candidates_[1] = net::ip::address_v6::any();
    }

    [[nodiscard]] std::span<const net::ip::address> Candidates() const noexcept {
        return {candidates_.data(), candidate_count_};
    }

    [[nodiscard]] static std::optional<InboundListen> Parse(std::string_view value) {
        if (value.empty() || common::EqualsAsciiCI(value, common::kAuto)) {
            return InboundListen{};
        }
        auto address = common::ParseLiteral(value);
        if (!address) {
            return std::nullopt;
        }

        InboundListen listen;
        listen.candidates_[0] = common::NormalizeAddress(*address);
        listen.candidate_count_ = 1;
        return listen;
    }

    // The listener reserves its requested address space, including auto-mode
    // candidates unavailable on this host. IPv6 sockets are always v6-only.
    [[nodiscard]] bool Overlaps(const InboundListen& other) const noexcept {
        for (const auto& address : Candidates()) {
            for (const auto& candidate : other.Candidates()) {
                if (address.is_v4() == candidate.is_v4() &&
                    (address == candidate || address.is_unspecified() || candidate.is_unspecified())) {
                    return true;
                }
            }
        }
        return false;
    }

    [[nodiscard]] bool operator==(const InboundListen& other) const noexcept {
        const auto addresses = Candidates();
        const auto candidates = other.Candidates();
        if (addresses.size() != candidates.size()) return false;
        for (size_t index = 0; index < addresses.size(); ++index) {
            if (addresses[index] != candidates[index]) return false;
        }
        return true;
    }
private:
    std::array<net::ip::address, 2> candidates_{};
    uint8_t candidate_count_ = 2;
};

}  // namespace transport

