#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/app/udp_types.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace acpp::proxyman::inbound {

class UdpResponseContext {
public:
    virtual ~UdpResponseContext() noexcept = default;

    [[nodiscard]] virtual buf::MultiBuffer Encode(
        ::acpp::UDPPacketView packet) = 0;
};

struct UdpSessionOwner {
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

    [[nodiscard]] bool Same(const UdpSessionOwner& other) const noexcept {
        return size == other.size &&
            std::equal(bytes.begin(), bytes.begin() + size, other.bytes.begin());
    }

    // Protocol session IDs are only unique inside one authenticated identity.
    // Prefix the opaque protocol key with the credential identity so two users
    // can never block or reuse each other's relay when their IDs collide.
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

struct UdpDecodeResult {
    TargetAddress target;
    buf::MultiBuffer payload;
    // Optional protocol-provided opaque session key. Empty means "use client endpoint".
    // UdpWorker does not inspect the value; it only uses it to group datagrams.
    std::string session_key;
    // Authenticated credential identity. UdpWorker scopes the protocol session
    // key by this identity; a collision must never transfer or block a relay,
    // response cipher, or accounting context owned by another credential.
    UdpSessionOwner session_owner;
    int64_t user_id = 0;
    std::string user_email;
    uint64_t speed_limit = 0;
    std::shared_ptr<UdpResponseContext> response_context;
};

class UdpHandler {
public:
    virtual ~UdpHandler() noexcept = default;

    // Called by the owning Worker before an atomic handler replacement. Only
    // protocol-local security/lifecycle state may move; live session objects
    // keep their already captured response contexts.
    virtual void AdoptWorkerStateFrom(UdpHandler&) noexcept {}

    // Called only by the owning Worker. Protocol decoders may update
    // Worker-local session state such as replay windows after authentication.
    [[nodiscard]] virtual std::optional<UdpDecodeResult> DecodeUdp(
        std::string_view tag,
        std::string_view client_ip,
        const uint8_t* data,
        size_t len) = 0;
};

}  // namespace acpp::proxyman::inbound
