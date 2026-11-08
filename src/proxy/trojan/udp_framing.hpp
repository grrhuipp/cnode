#pragma once

#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/target_address.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace trojan {

struct FramedUdpPacket {
    TargetAddress target;
    buf::MultiBuffer payload;
};

// Owns stream fragments until one complete tagged datagram, including an empty
// payload, can be transferred. An empty container is reserved for stream EOF.
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

}  // namespace trojan
