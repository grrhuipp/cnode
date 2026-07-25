#pragma once

#include "acppnode/app/udp_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/target_address.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace acpp {

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

    [[nodiscard]] std::string ScopeSessionKey(
        std::string_view protocol_session_key) const {
        if (size == 0 || protocol_session_key.empty()) {
            return {};
        }
        std::string scoped;
        scoped.reserve(1 + size + protocol_session_key.size());
        scoped.push_back(static_cast<char>(size));
        scoped.append(
            reinterpret_cast<const char*>(bytes.data()),
            static_cast<size_t>(size));
        scoped.append(protocol_session_key);
        return scoped;
    }

    std::array<uint8_t, kMaxBytes> bytes{};
    uint8_t size = 0;
};

struct InboundDatagramRequest {
    std::string_view tag;
    std::string_view client_ip;
    std::span<const uint8_t> payload;
};

struct InboundDatagramResult {
    TargetAddress target;
    buf::MultiBuffer payload;
    // Empty means that the client endpoint is the protocol session key.
    std::string session_key;
    // Protocol session IDs are scoped by the authenticated credential.
    InboundDatagramOwner session_owner;
    int64_t user_id = 0;
    std::string user_email;
    uint64_t speed_limit = 0;
    std::shared_ptr<InboundDatagramResponse> response;
};

}  // namespace acpp
