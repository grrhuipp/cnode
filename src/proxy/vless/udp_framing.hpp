#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/buf/length_prefixed_packet_buffer.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/transport/link.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace acpp::vless {

inline constexpr std::string_view kPacketAddrMagicAddress =
    "sp.packet-addr.v2fly.arpa";

[[nodiscard]] bool IsPacketAddrMagic(const TargetAddress& target) noexcept;

struct FramedUdpPacket {
    std::optional<TargetAddress> target;
    buf::MultiBuffer payload;
};

class UdpFramer {
public:
    explicit UdpFramer(bool packet_addr) noexcept
        : packet_addr_(packet_addr) {}

    void Feed(buf::MultiBuffer input);
    [[nodiscard]] bool Next(FramedUdpPacket& out);
    void Finish() const;

private:
    bool packet_addr_ = false;
    bool failed_ = false;
    buf::LengthPrefixedPacketBuffer pending_;
};

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    buf::MultiBuffer payload,
    bool packet_addr,
    const TargetAddress* fixed_target = nullptr);

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    std::span<const net::const_buffer> payload);

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    const TargetAddress& target,
    bool packet_addr,
    std::span<const net::const_buffer> payload);

}  // namespace acpp::vless
