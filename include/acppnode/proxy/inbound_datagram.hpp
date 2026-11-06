#pragma once

#include "acppnode/app/udp_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/common/user_profile.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace acpp {

class ConnectionLimiter;
class UserOnlineTracker;


class InboundDatagramResponse {
public:
    virtual ~InboundDatagramResponse() noexcept = default;

    [[nodiscard]] virtual buf::MultiBuffer Encode(UDPPacketView packet) = 0;
};

struct InboundDatagramOwner {
    static constexpr size_t kMaxBytes = 32;

    [[nodiscard]] bool Assign(std::span<const uint8_t> value) noexcept {
        if (value.empty() || value.size() > bytes.size()) {
            size = 0;
            return false;
        }
        std::copy(value.begin(), value.end(), bytes.begin());
        size = static_cast<uint8_t>(value.size());
        return true;
    }

    [[nodiscard]] bool Same(const InboundDatagramOwner& other) const noexcept {
        return size == other.size &&
            std::equal(bytes.begin(), bytes.begin() + size, other.bytes.begin());
    }


    std::array<uint8_t, kMaxBytes> bytes{};
    uint8_t size = 0;
};

struct InboundDatagramRequest {
    std::string_view tag;
    std::span<const uint8_t> payload;
};

struct InboundDatagramResult {
    TargetAddress target;
    buf::MultiBuffer payload;
    // Absent means that the normalized client endpoint identifies the session.
    std::optional<uint64_t> session_id;
    // Protocol session IDs are scoped by the authenticated credential.
    InboundDatagramOwner session_owner;
    // The authenticated credential's profile. Borrowed only until the
    // synchronous datagram handoff completes; a new association copies it.
    const UserProfile* user = nullptr;
    // Admission handles of the authenticating protocol runtime. A new
    // association copies them and holds its reservations through them; the
    // runtime's tracker and the Worker's limiter outlive every association.
    // An authenticated result without a tracker cannot start an association.
    UserOnlineTracker* tracker = nullptr;
    ConnectionLimiter* limiter = nullptr;
};

}  // namespace acpp
