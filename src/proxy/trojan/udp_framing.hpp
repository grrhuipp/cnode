#pragma once

#include "../outbound_stream_endpoint.hpp"
#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/target_address.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

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
    void Finish();
    [[nodiscard]] bool Finished() const noexcept { return state_ == State::Finished; }

private:
    enum class State : uint8_t { Active, Finished, Failed };
    void Fail() noexcept;

    buf::MultiBuffer pending_;
    std::optional<TargetAddress> target_;
    size_t payload_size_ = 0;
    State state_ = State::Active;
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

class UdpStreamEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    explicit UdpStreamEndpoint(
        AsyncStream& stream,
        TargetAddress fallback_target = {},
        transport::EofAction read_eof_action = transport::EofAction::ShutdownPeerWrite)
        : OutboundStreamEndpointBase(stream)
        , fallback_target_(std::move(fallback_target))
        , read_eof_action_(read_eof_action) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        return ReadUdpDatagram(stream_, framer_);
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return WriteUdpDatagram(stream_, std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        return WriteUdpDatagram(stream_, fallback_target_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return stream_.AsyncShutdownWrite();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return read_eof_action_;
    }

private:
    TargetAddress fallback_target_;
    UdpFramer framer_;
    transport::EofAction read_eof_action_;
};

}  // namespace trojan
