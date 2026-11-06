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
    // The ingress directory commits replay only after authenticated ownership
    // resolution. Standalone protocol callers retain synchronous replay checks.
    bool deferred_replay = false;
};

struct InboundDatagramResult {
    TargetAddress target;
    buf::MultiBuffer payload;
    // Absent means that the normalized client endpoint identifies the session.
    std::optional<uint64_t> session_id;
    // Protocol session IDs are scoped by the authenticated credential.
    InboundDatagramOwner session_owner;
    // Present only with an authenticated, replay-protected protocol session.
    std::optional<uint64_t> packet_id;
    // Production authentication aliases an owned credential snapshot. The raw
    // view is synchronous-only for protocols without an owning snapshot;
    // ingress must copy the profile before any asynchronous handoff.
    std::shared_ptr<const UserProfile> user_owner;
    const UserProfile* user = nullptr;
    // Standalone injected dispatchers must supply an owning admission tracker.
    // Production datagrams use their stable session capability's tracker instead.
    std::shared_ptr<UserOnlineTracker> tracker;
    ConnectionLimiter* limiter = nullptr;
};

}  // namespace acpp
