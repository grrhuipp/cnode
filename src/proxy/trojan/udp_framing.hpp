#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace acpp::trojan {

struct FramedUdpPacket {
    TargetAddress target;
    buf::MultiBuffer payload;
};

// Owns stream fragments until one complete datagram can be transferred.
class UdpFramer {
public:
    void Feed(buf::MultiBuffer input);
    [[nodiscard]] bool Next(FramedUdpPacket& out);
    void Finish() const;

private:
    buf::MultiBuffer pending_;
    std::optional<TargetAddress> target_;
    size_t payload_size_ = 0;
    bool failed_ = false;
};

net::awaitable<buf::MultiBuffer> ReadUdpDatagram(
    AsyncStream& stream,
    UdpFramer& framer);

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    buf::MultiBuffer payload);

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    const TargetAddress& target,
    std::span<const net::const_buffer> payload);

}  // namespace acpp::trojan
