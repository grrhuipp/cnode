#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/transport/link.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace acpp::trojan {

struct FramedUdpPacket {
    TargetAddress target;
    buf::MultiBuffer payload;
};

// Trojan UDP wire frames are contiguous on the stream but their logical
// payload may span many internal 8KB Buffers.
class UdpFramer {
public:
    void Feed(const uint8_t* data, size_t len);
    [[nodiscard]] bool Next(FramedUdpPacket& out);

private:
    void Parse();
    void CompactPending();

    memory::ByteVector pending_;
    size_t pending_offset_ = 0;
    memory::ThreadLocalDeque<FramedUdpPacket> queue_;
    bool shrink_queue_on_drain_ = false;
};

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    buf::MultiBuffer payload);

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    const TargetAddress& target,
    std::span<const net::const_buffer> payload);

}  // namespace acpp::trojan
