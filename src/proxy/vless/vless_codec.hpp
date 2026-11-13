#pragma once

#include "common/address_codec.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/binary_text_codec.hpp"
#include "common/length_prefixed_packet_buffer.hpp"
#include "common/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"
#include <openssl/mem.h>
#include "common/constants.hpp"
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
#include <vector>
namespace proxy {

// Parses a UUID string, or maps a 1-30 byte VLESS custom id to UUIDv5.
[[nodiscard]] inline std::optional<std::array<uint8_t, 16>>
ParseUuidBytes(std::string_view uuid) noexcept {
    if (auto parsed = ::common::ParseUuid(uuid)) {
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
    return common::LowerAscii(std::string(flow));
}

inline constexpr uint8_t kVlessVersion = 0x00;

// Version, UUID, addons length, 255 addon bytes, command and the largest
// port-first address (port, type, length, 253-byte domain).
inline constexpr size_t kVlessMaxRequestHeaderSize = 1 + 16 + 1 + 255 + 1 + common::kMaxEncodedAddressSize;

// The server never sends response addons.
inline constexpr std::array<uint8_t, 2> kResponseHeader{kVlessVersion, 0};

enum class VlessCommand : uint8_t {
    TCP = 0x01,
    UDP = 0x02,
    MUX = 0x03,
};

struct VlessRequestHeader {
    std::array<uint8_t, 16> uuid{};
    std::string flow;
    VlessCommand command = VlessCommand::TCP;
    common::TargetAddress target;
    std::optional<common::ForwardedMetadata> forwarded;
};

enum class VlessRequestDecodeStatus : uint8_t {
    Complete,
    Incomplete,
    InvalidVersion,
    InvalidCommand,
    InvalidAddress,
    InvalidAddons,
};

struct VlessRequestDecodeResult {
    VlessRequestDecodeStatus status = VlessRequestDecodeStatus::Incomplete;
    VlessRequestHeader header;
    // Complete only: bytes belonging to the header.
    size_t consumed = 0;
    // Incomplete only: minimum total prefix length needed for the next stage.
    size_t required = 0;
};

// Re-submit the same growing prefix until it is complete or invalid; every
// Incomplete result names the next structural boundary, never a guess.
[[nodiscard]] VlessRequestDecodeResult DecodeVlessRequestHeader(
    std::span<const uint8_t> data);

[[nodiscard]] size_t EncodeRequestHeaderTo(
    const std::array<uint8_t, 16>& uuid,
    VlessCommand command,
    const common::TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    std::string_view flow = {},
    common::ForwardedMetadataView forwarded = {});


inline constexpr std::string_view kPacketAddrMagicAddress =
    "sp.packet-addr.v2fly.arpa";

[[nodiscard]] bool IsPacketAddrMagic(const common::TargetAddress& target) noexcept;

struct VlessFramedUdpPacket {
    std::optional<common::TargetAddress> target;
    common::MultiBuffer payload;
};

class VlessUdpFramer {
public:
    explicit VlessUdpFramer(bool packet_addr) noexcept : packet_addr_(packet_addr) {}

    // Malformed/truncated input, budget overflow and use after EOF/failure
    // throw LinkError(PROTOCOL_DECODE_FAILED); allocation and source I/O
    // exceptions retain their original types.
    void Feed(common::MultiBuffer input);
    [[nodiscard]] bool Next(VlessFramedUdpPacket& out);
    void Finish();

    // Returns one framed datagram whose buffers carry its packet address, or
    // `session_target` without one; an empty datagram owns a tagged zero-length
    // Buffer, while an empty container means clean EOF. Partial frames stay
    // in this framer when `src` throws or is cancelled.
    net::awaitable<common::MultiBuffer> ReadDatagram(
        transport::MultiBufferReader& src,
        const common::TargetAddress& session_target);

private:
    bool packet_addr_ = false;
    common::LengthPrefixedPacketBuffer pending_;
};

net::awaitable<void> WriteVlessUdpDatagram(
    transport::MultiBufferWriter& writer,
    common::MultiBuffer payload,
    bool packet_addr,
    const common::TargetAddress* fixed_target = nullptr);

net::awaitable<void> WriteVlessUdpDatagram(
    transport::MultiBufferWriter& writer,
    const common::TargetAddress& target,
    bool packet_addr,
    std::span<const net::const_buffer> payload);

class VlessUdpStreamEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    VlessUdpStreamEndpoint(transport::MultiBufferReader& src,
                      transport::MultiBufferWriter& dst,
                      const common::TargetAddress& target,
                      bool packet_addr)
        : src_(src)
        , dst_(dst)
        , target_(packet_addr ? common::TargetAddress{} : target)
        , framer_(packet_addr)
        , packet_addr_(packet_addr) {}

    transport::CancellationSource& Cancellation() noexcept override {
        return src_.Cancellation();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return src_.ReadEofAction();
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        return framer_.ReadDatagram(src_, target_);
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        return WriteVlessUdpDatagram(dst_, std::move(mb), packet_addr_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (packet_addr_) {
            throw IoSystemError(
                io_error::invalid_argument,
                "packet-address VLESS UDP write requires a target");
        }
        return WriteVlessUdpDatagram(dst_, target_, false, buffers);
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
    common::TargetAddress target_;
    VlessUdpFramer framer_;
    bool packet_addr_ = false;
};

inline constexpr std::string_view kVisionFlow = "xtls-rprx-vision";

[[nodiscard]] bool IsVisionFlow(std::string_view flow) noexcept;


inline constexpr size_t kVisionFrameContentLimit = 8192 - 21;
// `random` is uniform in [0,499] for long TLS padding, otherwise [0,255].
[[nodiscard]] constexpr uint16_t VisionPaddingSize(
    size_t content, bool long_padding, uint16_t random) noexcept {
    const size_t padding = content < 900 && long_padding
        ? random + 900 - content : random;
    const size_t available = content < kVisionFrameContentLimit
        ? kVisionFrameContentLimit - content : 0;
    return static_cast<uint16_t>(padding < available ? padding : available);
}


// Both directions observe the same TLS handshake, as in Xray TrafficState.
// Access is confined to the connection's owning Worker.
struct VisionTrafficState {
    int packets_to_filter = 8;
    bool is_tls = false;
    bool is_tls12_or_above = false;
    int32_t remaining_server_hello = -1;
    bool tls_classified = false;

    void FilterTLS(std::span<const uint8_t> data) noexcept;
};

class VisionReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return src_.ReadEofAction(); }

    VisionReader(transport::MultiBufferReader& src,
                 std::array<uint8_t, 16> user_uuid,
                 VisionTrafficState& traffic);
    ~VisionReader() noexcept override {
        OPENSSL_cleanse(user_uuid_.data(), user_uuid_.size());
        OPENSSL_cleanse(header_.data(), header_.size());
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override;

private:
    transport::MultiBufferReader& src_;
    std::array<uint8_t, 16> user_uuid_{};
    VisionTrafficState& traffic_;
    // Streaming frame cursor: header bytes, content and padding may each be
    // split across reads; content is moved out as soon as it arrives.
    common::MultiBuffer pending_;
    std::array<uint8_t, 16 + 5> header_{};
    size_t header_read_ = 0;
    size_t content_remaining_ = 0;
    size_t padding_remaining_ = 0;
    uint8_t command_ = 0;
    bool frame_active_ = false;
    bool read_process_ = true;
    bool expect_uuid_ = true;

    void Decode(common::MultiBuffer& out);
    net::awaitable<common::MultiBuffer> ReadFramedMultiBuffer();
};

class VisionWriter final : public transport::MultiBufferWriter {
public:
    VisionWriter(transport::MultiBufferWriter& dst,
                 std::array<uint8_t, 16> user_uuid,
                 VisionTrafficState& traffic);
    ~VisionWriter() noexcept override {
        OPENSSL_cleanse(user_uuid_.data(), user_uuid_.size());
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool WriteShutdownClosesLink() const noexcept override {
        return dst_.WriteShutdownClosesLink();
    }

private:
    net::awaitable<void> WriteFramedMultiBuffer(common::MultiBuffer mb);
    net::awaitable<void> WriteFramedBuffers(std::span<const net::const_buffer> buffers);
    transport::MultiBufferWriter& dst_;
    std::array<uint8_t, 16> user_uuid_{};
    bool write_process_ = true;
    bool send_uuid_ = true;
    VisionTrafficState& traffic_;
};
}  // namespace proxy
