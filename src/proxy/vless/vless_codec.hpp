#pragma once

#include "common/address_codec.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/binary_text_codec.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"
#include "core/naming.hpp"
#include "transport/link.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
namespace vless {

// Parses a UUID string, or maps a 1-30 byte VLESS custom id to UUIDv5.
[[nodiscard]] inline std::optional<std::array<uint8_t, 16>>
ParseUuidBytes(std::string_view uuid) noexcept {
    if (auto parsed = ::ParseUuid(uuid)) {
        return parsed;
    }
    if (!uuid.empty() && uuid.size() <= 30) {
        std::array<uint8_t, 16 + 30> input{};
        std::memcpy(input.data() + 16, uuid.data(), uuid.size());

        std::array<uint8_t, SHA_DIGEST_LENGTH> digest{};
        SHA1(input.data(), 16 + uuid.size(), digest.data());

        std::array<uint8_t, 16> out{};
        std::copy_n(digest.begin(), out.size(), out.begin());
        out[6] = static_cast<uint8_t>((out[6] & 0x0f) | 0x50);
        out[8] = static_cast<uint8_t>((out[8] & 0x3f) | 0x80);
        return out;
    }
    return std::nullopt;
}

[[nodiscard]] inline std::string NormalizeFlow(std::string_view flow) {
    return naming::LowerAscii(std::string(flow));
}

inline constexpr uint8_t kVersion = 0x00;

// Version, UUID, addons length, 255 addon bytes, command and the largest
// port-first address (port, type, length, 253-byte domain).
inline constexpr size_t kMaxRequestHeaderSize = 1 + 16 + 1 + 255 + 1 + kMaxEncodedAddressSize;

// The server never sends response addons.
inline constexpr std::array<uint8_t, 2> kResponseHeader{kVersion, 0};

enum class Command : uint8_t {
    TCP = 0x01,
    UDP = 0x02,
    MUX = 0x03,
};

struct RequestHeader {
    std::array<uint8_t, 16> uuid{};
    memory::ThreadLocalString flow;
    Command command = Command::TCP;
    TargetAddress target;
    std::optional<ForwardedMetadata> forwarded;
};

enum class RequestHeaderDecodeStatus : uint8_t {
    Complete,
    Incomplete,
    InvalidVersion,
    InvalidCommand,
    InvalidAddress,
    InvalidAddons,
};

struct RequestHeaderDecodeResult {
    RequestHeaderDecodeStatus status = RequestHeaderDecodeStatus::Incomplete;
    RequestHeader header;
    // Complete only: bytes belonging to the header.
    size_t consumed = 0;
    // Incomplete only: minimum total prefix length needed for the next stage.
    size_t required = 0;
};

// Re-submit the same growing prefix until it is complete or invalid; every
// Incomplete result names the next structural boundary, never a guess.
[[nodiscard]] RequestHeaderDecodeResult DecodeRequestHeader(
    std::span<const uint8_t> data);

[[nodiscard]] size_t EncodeRequestHeaderTo(
    const std::array<uint8_t, 16>& uuid,
    Command command,
    const TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    std::string_view flow = {},
    ForwardedMetadataView forwarded = {});


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
