#pragma once

#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "common/target_address.hpp"
#include "transport/link.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "common/error.hpp"
#include <utility>

namespace vless {

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
    void Finish();

    // Returns one framed datagram whose buffers carry its packet address, or
    // `session_target` without one; an empty datagram owns a tagged zero-length
    // Buffer, while an empty container means clean EOF. Partial frames stay
    // in this framer when `src` throws or is cancelled.
    net::awaitable<buf::MultiBuffer> ReadDatagram(
        transport::MultiBufferReader& src,
        const TargetAddress& session_target);

private:
    bool packet_addr_ = false;
    buf::LengthPrefixedPacketBuffer pending_;
};

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    buf::MultiBuffer payload,
    bool packet_addr,
    const TargetAddress* fixed_target = nullptr);

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    const TargetAddress& target,
    bool packet_addr,
    std::span<const net::const_buffer> payload);


class UdpStreamEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    UdpStreamEndpoint(transport::MultiBufferReader& src,
                      transport::MultiBufferWriter& dst,
                      const TargetAddress& target,
                      bool packet_addr)
        : src_(src)
        , dst_(dst)
        , target_(packet_addr ? TargetAddress{} : target)
        , framer_(packet_addr)
        , packet_addr_(packet_addr) {}

    transport::CancellationSource& Cancellation() noexcept override {
        return src_.Cancellation();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return src_.ReadEofAction();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        return framer_.ReadDatagram(src_, target_);
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return WriteUdpDatagram(dst_, std::move(mb), packet_addr_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (packet_addr_) {
            throw IoSystemError(
                io_error::invalid_argument,
                "packet-address VLESS UDP write requires a target");
        }
        return WriteUdpDatagram(dst_, target_, false, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return dst_.AsyncShutdownWrite();
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return dst_.WriteShutdownClosesLink();
    }

private:
    transport::MultiBufferReader& src_;
    transport::MultiBufferWriter& dst_;
    TargetAddress target_;
    UdpFramer framer_;
    bool packet_addr_ = false;
};
}  // namespace vless
