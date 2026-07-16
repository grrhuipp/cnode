#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/app/udp_types.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace acpp::proxyman::inbound {

class UdpResponseContext {
public:
    virtual ~UdpResponseContext() noexcept = default;
};

struct UdpDecodeResult {
    TargetAddress target;
    buf::MultiBuffer payload;
    // Optional protocol-provided opaque session key. Empty means "use client endpoint".
    // UdpWorker does not inspect the value; it only uses it to group datagrams.
    std::string session_key;
    int64_t user_id = 0;
    std::string user_email;
    uint64_t speed_limit = 0;
    std::shared_ptr<const UdpResponseContext> response_context;
};

class UdpHandler {
public:
    virtual ~UdpHandler() noexcept = default;

    // Called only by the owning Worker. Protocol decoders may update
    // Worker-local session state such as replay windows after authentication.
    [[nodiscard]] virtual std::optional<UdpDecodeResult> DecodeUdp(
        std::string_view tag,
        std::string_view client_ip,
        const uint8_t* data,
        size_t len) = 0;

    [[nodiscard]] virtual buf::MultiBuffer EncodeUdpResponse(
        ::acpp::UDPPacketView packet,
        const UdpResponseContext& response_context) const = 0;
};

}  // namespace acpp::proxyman::inbound
