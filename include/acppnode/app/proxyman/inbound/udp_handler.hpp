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
    int64_t user_id = 0;
    std::string user_email;
    uint64_t speed_limit = 0;
    std::shared_ptr<const UdpResponseContext> response_context;
};

class UdpHandler {
public:
    virtual ~UdpHandler() noexcept = default;

    [[nodiscard]] virtual std::optional<UdpDecodeResult> DecodeUdp(
        std::string_view tag,
        std::string_view client_ip,
        const uint8_t* data,
        size_t len) const = 0;

    [[nodiscard]] virtual buf::MultiBuffer EncodeUdpResponse(
        ::acpp::UDPPacketView packet,
        const UdpResponseContext& response_context) const = 0;

    virtual void SetBanTrackingEnabled(bool enabled) noexcept = 0;
};

}  // namespace acpp::proxyman::inbound
