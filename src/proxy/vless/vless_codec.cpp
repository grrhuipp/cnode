#include "proxy/vless/vless_codec.hpp"
#include "proxy/udp_datagram_frame.hpp"
#include "common/address_codec.hpp"
#include "common/const_buffer_span.hpp"
#include "common/eof_cancellation.hpp"
#include "common/multi_buffer.hpp"
#include "common/byte_reader.hpp"
#include "common/error.hpp"

#include <array>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <optional>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <cstdint>
#include <list>

namespace proxy {

namespace {

constexpr uint64_t kProtoWireLengthDelimited = 2;
constexpr uint64_t kProtoAddonsFlowField = 1;

bool ParseHeaderAddons(std::span<const uint8_t> data,
                       VlessRequestHeader& request) {
    common::ByteReader reader(data);
    bool seen_flow = false;
    while (!reader.Empty()) {
        auto tag = reader.ReadVarintU64();
        if (!tag || *tag == 0) {
            return false;
        }
        const uint64_t field_number = *tag >> 3;
        const uint64_t wire_type = *tag & 0x07;
        if (field_number != kProtoAddonsFlowField ||
            wire_type != kProtoWireLengthDelimited ||
            seen_flow) {
            return false;
        }
        auto flow_len = reader.ReadVarintU64();
        if (!flow_len || *flow_len == 0 || *flow_len > reader.Remaining()) {
            return false;
        }
        const auto flow = reader.ReadStringView(static_cast<size_t>(*flow_len));
        if (!reader.Ok()) {
            return false;
        }
        request.flow.assign(flow.data(), flow.size());
        seen_flow = true;
    }
    return reader.Ok();
}

size_t EncodedAddonsSize(std::string_view flow) noexcept {
    if (flow.empty()) {
        return 0;
    }
    return 1 + common::VarintU64Size(flow.size()) + flow.size();
}

bool WriteHeaderAddons(common::ByteWriter& writer, std::string_view flow) noexcept {
    const size_t addons_len = EncodedAddonsSize(flow);
    if (addons_len > std::numeric_limits<uint8_t>::max()) {
        return false;
    }
    if (!writer.WriteU8(static_cast<uint8_t>(addons_len))) {
        return false;
    }
    if (addons_len == 0) {
        return true;
    }
    constexpr uint8_t flow_tag =
        static_cast<uint8_t>((kProtoAddonsFlowField << 3) | kProtoWireLengthDelimited);
    return writer.WriteU8(flow_tag) &&
           writer.WriteVarintU64(flow.size()) &&
           writer.WriteString(flow);
}


constexpr size_t kPacketAddrV4HeaderSize = 1 + sizeof(net::ip::address_v4::bytes_type) + sizeof(uint16_t);
constexpr size_t kPacketAddrV6HeaderSize = 1 + sizeof(net::ip::address_v6::bytes_type) + sizeof(uint16_t);
constexpr size_t kMaxUdpHeaderSize = sizeof(uint16_t) + kPacketAddrV6HeaderSize;

struct PacketAddrHeader {
    common::TargetAddress target;
    size_t consumed = 0;
};

size_t EncodePacketAddrHeaderTo(const common::TargetAddress& target,
                                uint8_t* out,
                                size_t capacity) noexcept {
    if (!target.resolved_addr) {
        return 0;
    }
    if (target.resolved_addr->is_v4()) {
        if (capacity < kPacketAddrV4HeaderSize) {
            return 0;
        }
        out[0] = 0x01;
        const auto bytes = target.resolved_addr->to_v4().to_bytes();
        std::memcpy(out + 1, bytes.data(), bytes.size());
        out[5] = static_cast<uint8_t>(target.port >> 8);
        out[6] = static_cast<uint8_t>(target.port);
        return kPacketAddrV4HeaderSize;
    }
    if (target.resolved_addr->is_v6()) {
        if (capacity < kPacketAddrV6HeaderSize) {
            return 0;
        }
        out[0] = 0x02;
        const auto bytes = target.resolved_addr->to_v6().to_bytes();
        std::memcpy(out + 1, bytes.data(), bytes.size());
        out[17] = static_cast<uint8_t>(target.port >> 8);
        out[18] = static_cast<uint8_t>(target.port);
        return kPacketAddrV6HeaderSize;
    }
    return 0;
}

std::optional<PacketAddrHeader> DecodePacketAddrHeader(
    std::span<const uint8_t> data) noexcept {
    if (data.empty()) {
        return std::nullopt;
    }

    if (data[0] == 0x01) {
        if (data.size() < 7) {
            return std::nullopt;
        }
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + 1, bytes.size());
        const uint16_t port = common::LoadU16BE(&data[5]);
        return PacketAddrHeader{
            common::TargetAddress(net::ip::make_address_v4(bytes), port), 7};
    }

    if (data[0] == 0x02) {
        if (data.size() < 19) {
            return std::nullopt;
        }
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + 1, bytes.size());
        const uint16_t port = common::LoadU16BE(&data[17]);
        return PacketAddrHeader{
            common::TargetAddress(net::ip::make_address_v6(bytes), port), 19};
    }

    return std::nullopt;
}

size_t EncodeRequiredUdpHeaderTo(const common::TargetAddress& target,
                         bool packet_addr,
                         size_t payload_size,
                         std::span<uint8_t> out) {
    if (!target.IsValid()) throw transport::LinkError(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
    if (payload_size > proxy::kMaxFramedDatagramPayload)
        throw transport::LinkError(common::ErrorCode::PROTOCOL_ENCODE_FAILED);

    std::array<uint8_t, kPacketAddrV6HeaderSize> address{};
    const size_t address_size = packet_addr
        ? EncodePacketAddrHeaderTo(target, address.data(), address.size())
        : 0;
    if (packet_addr && address_size == 0)
        throw transport::LinkError(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
    if (address_size > std::numeric_limits<uint16_t>::max() - payload_size ||
        out.size() < address_size + 2)
        throw transport::LinkError(common::ErrorCode::PROTOCOL_ENCODE_FAILED);

    const size_t frame_payload_size = address_size + payload_size;
    out[0] = static_cast<uint8_t>(frame_payload_size >> 8);
    out[1] = static_cast<uint8_t>(frame_payload_size);
    if (address_size > 0) {
        std::memcpy(out.data() + 2, address.data(), address_size);
    }
    return address_size + 2;
}

constexpr size_t kVisionBaseHeaderLen = 1 + 2 + 2;
constexpr size_t kVisionUuidHeaderLen = 16 + kVisionBaseHeaderLen;


constexpr uint8_t kCommandPaddingContinue = 0x00;
constexpr uint8_t kCommandPaddingEnd = 0x01;
constexpr uint8_t kCommandPaddingDirect = 0x02;

constexpr std::array<uint8_t, 2> kTlsClientHandshakeStart{0x16, 0x03};
constexpr std::array<uint8_t, 3> kTlsServerHandshakeStart{0x16, 0x03, 0x03};
constexpr std::array<uint8_t, 3> kTlsApplicationDataStart{0x17, 0x03, 0x03};
constexpr std::array<uint8_t, 6> kTls13SupportedVersions{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
constexpr std::array<uint8_t, 2048> kZeroPadding{};

[[nodiscard]] bool StartsWith(std::span<const uint8_t> data,
                              std::span<const uint8_t> prefix) noexcept {
    return data.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), data.begin());
}

[[nodiscard]] size_t FindBytes(std::span<const uint8_t> data,
                               std::span<const uint8_t> needle) noexcept {
    if (needle.empty() || data.size() < needle.size()) {
        return std::string_view::npos;
    }
    auto it = std::search(data.begin(), data.end(), needle.begin(), needle.end());
    return it == data.end()
        ? std::string_view::npos
        : static_cast<size_t>(it - data.begin());
}

[[nodiscard]] bool ContainsBytes(std::span<const uint8_t> data,
                                 std::span<const uint8_t> needle) noexcept {
    return FindBytes(data, needle) != std::string_view::npos;
}

[[nodiscard]] uint16_t RandomU16(uint16_t limit) noexcept {
    if (limit == 0) {
        return 0;
    }
    uint16_t value;
    const uint32_t bound = 65536u - (65536u % limit);
    do {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
            std::abort();
        }
    } while (value >= bound);
    return static_cast<uint16_t>(value % limit);
}

[[nodiscard]] uint16_t PaddingLen(size_t content_len, bool padding_tls) noexcept {
    return VisionPaddingSize(content_len, padding_tls,
        RandomU16(content_len < 900 && padding_tls ? 500 : 256));
}

[[noreturn]] void ThrowVisionAllocationFailure() {
    throw IoSystemError(io_error::fault, "VLESS Vision buffer allocation failed");
}

// Xray IsCompleteRecord, without flattening the scatter/gather payload.
struct CompleteRecords {
    std::array<uint8_t, 5> header{};
    size_t header_bytes = 0;
    size_t remaining = 0;
    bool valid = true;
    bool seen = false;

    void Add(std::span<const uint8_t> bytes) noexcept {
        while (valid && !bytes.empty()) {
            seen = true;
            if (remaining != 0) {
                const auto n = std::min(remaining, bytes.size());
                remaining -= n;
                bytes = bytes.subspan(n);
                continue;
            }
            const size_t n = std::min(header.size() - header_bytes, bytes.size());
            std::memcpy(header.data() + header_bytes, bytes.data(), n);
            header_bytes += n;
            bytes = bytes.subspan(n);
            if (header_bytes == header.size()) {
                valid = StartsWith(header, kTlsApplicationDataStart);
                remaining = common::LoadU16BE(header.data() + 3);
                valid = valid && remaining != 0;
                header_bytes = 0;
            }
        }
    }

    [[nodiscard]] bool Complete() const noexcept {
        return valid && seen && remaining == 0 && header_bytes == 0;
    }
};


using VisionFrameBufferBuilder =
    common::ConstBufferSpanBuilder<common::MultiBuffer::kInlineCapacity * 3>;

class VisionHeaderArena {
public:
    uint8_t* Allocate(size_t len) {
        if (inline_used_ + len <= inline_.size()) {
            uint8_t* ptr = inline_.data() + inline_used_;
            inline_used_ += len;
            return ptr;
        }
        if (overflow_.empty() || overflow_used_ + len > kBlockSize) {
            overflow_.emplace_back();
            overflow_used_ = 0;
        }
        uint8_t* ptr = overflow_.back().data() + overflow_used_;
        overflow_used_ += len;
        return ptr;
    }

private:
    static constexpr size_t kBlockSize = 128;
    std::array<uint8_t, kBlockSize> inline_{};
    size_t inline_used_ = 0;
    std::list<std::array<uint8_t, kBlockSize>> overflow_;
    size_t overflow_used_ = 0;
};

void AppendVisionFrameBuffers(
    VisionHeaderArena& header_owner,
    VisionFrameBufferBuilder& out,
    std::span<uint8_t, 16> user_uuid,
    bool& send_uuid,
    std::span<const uint8_t> content,
    uint8_t command,
    bool long_padding) {
    const uint16_t padding_len = PaddingLen(content.size(), long_padding);
    const size_t header_len = send_uuid
        ? kVisionUuidHeaderLen
        : kVisionBaseHeaderLen;

    uint8_t* tail = header_owner.Allocate(header_len);
    size_t pos = 0;
    if (send_uuid) {
        std::memcpy(tail, user_uuid.data(), user_uuid.size());
        OPENSSL_cleanse(user_uuid.data(), user_uuid.size());
        pos += user_uuid.size();
        send_uuid = false;
    }
    tail[pos++] = command;
    common::StoreU16BE(tail + pos, static_cast<uint16_t>(content.size()));
    pos += 2;
    common::StoreU16BE(tail + pos, padding_len);
    pos += 2;
    out.Append(net::const_buffer(tail, pos));
    if (!content.empty()) {
        out.Append(net::const_buffer(content.data(), content.size()));
    }

    size_t remaining_padding = padding_len;
    while (remaining_padding > 0) {
        const size_t n = std::min(remaining_padding, kZeroPadding.size());
        out.Append(net::const_buffer(kZeroPadding.data(), n));
        remaining_padding -= n;
    }
}

void AppendVisionFramed(
    VisionHeaderArena& header_owner,
    VisionFrameBufferBuilder& out,
    std::span<uint8_t, 16> user_uuid,
    bool& send_uuid,
    bool& write_process,
    const VisionTrafficState& traffic,
    std::span<const uint8_t> bytes,
    bool complete_records,
    bool last_buffer,
    bool& ending,
    bool& long_padding) {
    while (!bytes.empty()) {
        if (!write_process) {
            out.Append(net::const_buffer(bytes.data(), bytes.size()));
            return;
        }

        // Match Xray ReshapeMultiBuffer: prefer the last application record
        // boundary when it leaves room for the Vision header.
        size_t n = bytes.size();
        if (n >= kVisionFrameContentLimit) {
            const auto window = bytes.first(kVisionFrameContentLimit);
            const auto it = std::find_end(window.begin(), window.end(),
                kTlsApplicationDataStart.begin(), kTlsApplicationDataStart.end());
            const size_t index = static_cast<size_t>(it - window.begin());
            n = (it != window.end() && index >= kVisionUuidHeaderLen)
                ? index : std::min<size_t>(n, 4096);
        }
        const auto chunk = bytes.first(n);
        const bool application = traffic.is_tls && chunk.size() >= 6 &&
            StartsWith(chunk, kTlsApplicationDataStart) && complete_records;
        uint8_t command = kCommandPaddingContinue;
        bool frame_long_padding = long_padding;
        if (application) {
            ending = true;
            frame_long_padding = true;
            long_padding = false;
        } else if (!traffic.is_tls12_or_above && traffic.packets_to_filter <= 1) {
            command = kCommandPaddingEnd;
            write_process = false;
        }
        if (ending && last_buffer && n == bytes.size()) {
            command = kCommandPaddingEnd;
            write_process = false;
        }
        AppendVisionFrameBuffers(
            header_owner, out, user_uuid, send_uuid, chunk, command, frame_long_padding);
        bytes = bytes.subspan(n);
    }
}

template <typename BufferRange>
net::awaitable<void> WriteVisionFramed(
    transport::MultiBufferWriter& dst,
    std::span<uint8_t, 16> user_uuid,
    bool& send_uuid,
    bool& write_process,
    VisionTrafficState& traffic,
    const BufferRange& buffers) {
    CompleteRecords records;
    const bool filter = traffic.packets_to_filter > 0;
    size_t remaining_bytes = 0;
    for (const auto& buffer : buffers) {
        const auto bytes = common::ChunkBytes(buffer);
        if (!bytes.empty()) {
            if (filter) {
                traffic.FilterTLS(bytes);
            }
            if (filter || traffic.is_tls) {
                records.Add(bytes);
            }
            remaining_bytes += bytes.size();
        }
    }
    bool ending = false;
    bool long_padding = traffic.is_tls;
    VisionHeaderArena header_owner;
    VisionFrameBufferBuilder out;
    for (const auto& buffer : buffers) {
        const auto bytes = common::ChunkBytes(buffer);
        if (!bytes.empty()) {
            remaining_bytes -= bytes.size();
            AppendVisionFramed(
                header_owner, out, user_uuid, send_uuid, write_process, traffic,
                bytes, records.Complete(), remaining_bytes == 0, ending, long_padding);
        }
    }
    if (!out.empty()) {
        co_await dst.WriteBuffers(out.Span());
    }
}
}  // namespace

VlessRequestDecodeResult DecodeVlessRequestHeader(std::span<const uint8_t> data) {
    constexpr size_t kUuidOffset = 1;
    constexpr size_t kAddonsLenOffset = kUuidOffset + 16;
    VlessRequestDecodeResult result;
    if (data.empty()) {
        result.required = 1;
        return result;
    }
    if (data[0] != kVlessVersion) {
        result.status = VlessRequestDecodeStatus::InvalidVersion;
        return result;
    }
    if (data.size() <= kAddonsLenOffset) {
        result.required = kAddonsLenOffset + 2;
        return result;
    }
    const uint8_t addons_len = data[kAddonsLenOffset];
    const size_t command_offset = kAddonsLenOffset + 1 + addons_len;
    if (data.size() <= command_offset) {
        result.required = command_offset + 1;
        return result;
    }

    VlessRequestHeader& header = result.header;
    const uint8_t command = data[command_offset];
    size_t consumed = command_offset + 1;
    if (command == static_cast<uint8_t>(VlessCommand::MUX)) {
        header.target = common::TargetAddress("v1.mux.cool", 9527);
    } else if (command == static_cast<uint8_t>(VlessCommand::TCP) ||
               command == static_cast<uint8_t>(VlessCommand::UDP)) {
        auto address = common::DecodeAddress(
            data.subspan(consumed), common::AddressWireFormat::PortFirst,
            {.require_non_empty_domain = true, .allow_metadata = true});
        if (address.status == common::AddressDecodeStatus::Invalid) {
            result.status = VlessRequestDecodeStatus::InvalidAddress;
            return result;
        }
        if (address.status == common::AddressDecodeStatus::Incomplete) {
            result.required = consumed + address.required;
            return result;
        }
        header.target = std::move(address.target);
        header.forwarded = std::move(address.forwarded);
        if (!header.target.IsValid() &&
            !(command == static_cast<uint8_t>(VlessCommand::UDP) &&
              IsPacketAddrMagic(header.target))) {
            result.status = VlessRequestDecodeStatus::InvalidAddress;
            return result;
        }
        consumed += address.consumed;
    } else {
        result.status = VlessRequestDecodeStatus::InvalidCommand;
        return result;
    }

    header.command = static_cast<VlessCommand>(command);
    std::memcpy(header.uuid.data(), data.data() + kUuidOffset, header.uuid.size());
    if (!ParseHeaderAddons(data.subspan(kAddonsLenOffset + 1, addons_len), header)) {
        result.status = VlessRequestDecodeStatus::InvalidAddons;
        return result;
    }
    result.status = VlessRequestDecodeStatus::Complete;
    result.consumed = consumed;
    return result;
}

size_t EncodeRequestHeaderTo(
    const std::array<uint8_t, 16>& uuid,
    VlessCommand command,
    const common::TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    std::string_view flow,
    common::ForwardedMetadataView forwarded) {
    const size_t addons_len = EncodedAddonsSize(flow);
    if (addons_len > std::numeric_limits<uint8_t>::max()) {
        return 0;
    }
    size_t address_size = 0;
    if (command != VlessCommand::MUX) {
        if (target.IsDomain() && (target.host.empty() || target.host.size() > 253)) {
            return 0;
        }
        address_size = common::AddressEncodedSize(target, forwarded);
        if (address_size == 0) {
            return 0;
        }
    }
    if (1 + uuid.size() + 1 + addons_len + 1 + address_size > output_size) {
        return 0;
    }

    common::ByteWriter writer(output, output_size);
    writer.WriteU8(kVlessVersion);
    writer.WriteBytes(uuid.data(), uuid.size());
    if (!WriteHeaderAddons(writer, flow)) {
        return 0;
    }
    writer.WriteU8(static_cast<uint8_t>(command));
    if (!writer.Ok()) {
        return 0;
    }
    if (command == VlessCommand::MUX) {
        return writer.Position();
    }
    const size_t encoded = common::EncodeAddressTo(target, output + writer.Position(),
        output_size - writer.Position(), common::AddressWireFormat::PortFirst, forwarded);
    return encoded == 0 ? 0 : writer.Position() + encoded;
}


bool IsPacketAddrMagic(const common::TargetAddress& target) noexcept {
    return target.IsDomain() && target.host == kPacketAddrMagicAddress;
}

void VlessUdpFramer::Feed(common::MultiBuffer input) {
    if (!pending_.Append(std::move(input))) {
        throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
}

bool VlessUdpFramer::Next(VlessFramedUdpPacket& out) {
    out = {};
    common::MultiBuffer payload;
    switch (pending_.Pop(payload)) {
    case common::LengthPrefixedPacketBuffer::PopResult::NeedMore:
    case common::LengthPrefixedPacketBuffer::PopResult::Finished:
        return false;
    case common::LengthPrefixedPacketBuffer::PopResult::Invalid:
        throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    case common::LengthPrefixedPacketBuffer::PopResult::Packet:
        break;
    }
    if (packet_addr_) {
        std::array<uint8_t, 19> address{};
        const size_t copied = payload.CopyPrefixTo(address);
        auto header = DecodePacketAddrHeader(
            std::span<const uint8_t>(address.data(), copied));
        if (!header || !header->target.IsValid()) {
            pending_.Fail();
            throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        out.target = std::move(header->target);
        (void)payload.DropPrefixBytes(header->consumed);
    }
    out.payload = std::move(payload);
    return true;
}

void VlessUdpFramer::Finish() {
    if (!pending_.Finish()) {
        throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
}

net::awaitable<common::MultiBuffer> VlessUdpFramer::ReadDatagram(
    transport::MultiBufferReader& src,
    const common::TargetAddress& session_target) {
    if (pending_.Finished()) co_return common::MultiBuffer{};
    for (;;) {
        VlessFramedUdpPacket packet;
        if (Next(packet)) {
            const common::TargetAddress& target = packet.target
                ? *packet.target
                : session_target;
            if (!common::SetUdpTarget(packet.payload, target)) {
                pending_.Fail();
                throw std::bad_alloc();
            }
            co_return std::move(packet.payload);
        }

        common::MultiBuffer raw = co_await src.ReadMultiBuffer();
        if (raw.byte_size() == 0) {
            co_await common::ThrowIfCancelledOnEof();
            Finish();
            co_return common::MultiBuffer{};
        }
        Feed(std::move(raw));
    }
}

net::awaitable<void> WriteVlessUdpDatagram(
    transport::MultiBufferWriter& writer, common::MultiBuffer payload,
    bool packet_addr, const common::TargetAddress* fixed_target) {
    const auto datagram = proxy::RequireUdpDatagram(
        payload, packet_addr ? nullptr : fixed_target);
    if (!datagram) co_return;
    std::array<uint8_t, kMaxUdpHeaderSize> header{};
    const auto size = EncodeRequiredUdpHeaderTo(
        *datagram->target, packet_addr, datagram->payload_size, header);
    co_await proxy::WriteFramedDatagram(writer, std::span(header).first(size), payload);
}

net::awaitable<void> WriteVlessUdpDatagram(
    transport::MultiBufferWriter& writer, const common::TargetAddress& target,
    bool packet_addr, std::span<const net::const_buffer> payload) {
    const auto payload_size = proxy::RequireUdpPayloadSize(payload);
    std::array<uint8_t, kMaxUdpHeaderSize> header{};
    const auto size = EncodeRequiredUdpHeaderTo(target, packet_addr, payload_size, header);
    co_await proxy::WriteFramedDatagram(writer, std::span(header).first(size), payload);
}

bool IsVisionFlow(std::string_view flow) noexcept {
    return flow == kVisionFlow;
}

VisionReader::VisionReader(transport::MultiBufferReader& src,
                           std::array<uint8_t, 16> user_uuid,
                           VisionTrafficState& traffic)
    : src_(src)
    , user_uuid_(user_uuid)
    , traffic_(traffic) {}

void VisionReader::Decode(common::MultiBuffer& out) {
    while (read_process_) {
        if (frame_active_) {
            if (content_remaining_ > 0) {
                const size_t n = std::min(content_remaining_, pending_.byte_size());
                if (n == 0) {
                    return;
                }
                if (!pending_.MovePrefixTo(out, n)) {
                    ThrowVisionAllocationFailure();
                }
                content_remaining_ -= n;
                continue;
            }
            if (padding_remaining_ > 0) {
                padding_remaining_ -= pending_.DropPrefixBytes(
                    std::min(padding_remaining_, pending_.byte_size()));
                if (padding_remaining_ > 0) {
                    return;
                }
            }
            frame_active_ = false;
            if (command_ != kCommandPaddingContinue) {
                if (command_ == kCommandPaddingDirect && !src_.EnableRawRead()) {
                    throw IoSystemError(io_error::connection_reset,
                                        "VLESS Vision direct read transition failed");
                }
                read_process_ = false;
            }
            continue;
        }

        const size_t header_len = expect_uuid_
            ? kVisionUuidHeaderLen
            : kVisionBaseHeaderLen;
        header_read_ += pending_.ConsumePrefixTo(
            std::span<uint8_t>(header_).subspan(header_read_, header_len - header_read_));
        if (header_read_ < header_len) {
            return;
        }
        header_read_ = 0;

        const uint8_t* fields = header_.data();
        if (expect_uuid_) {
            if (CRYPTO_memcmp(fields, user_uuid_.data(), user_uuid_.size()) != 0) {
                OPENSSL_cleanse(user_uuid_.data(), user_uuid_.size());
                OPENSSL_cleanse(header_.data(), user_uuid_.size());
                throw IoSystemError(io_error::connection_reset, "VLESS Vision UUID mismatch");
            }
            fields += user_uuid_.size();
            OPENSSL_cleanse(user_uuid_.data(), user_uuid_.size());
            expect_uuid_ = false;
        }
        command_ = fields[0];
        if (command_ != kCommandPaddingContinue &&
            command_ != kCommandPaddingEnd &&
            command_ != kCommandPaddingDirect) {
            throw IoSystemError(io_error::connection_reset, "VLESS Vision command invalid");
        }
        content_remaining_ = common::LoadU16BE(fields + 1);
        padding_remaining_ = common::LoadU16BE(fields + 3);
        frame_active_ = true;
    }
    // After the final padded frame the rest of the stream is raw.
    pending_.MoveTo(out);
    pending_.ReleaseIfIdle();
}

net::awaitable<common::MultiBuffer> VisionReader::ReadMultiBuffer() {
    if (!read_process_ && pending_.empty() && traffic_.packets_to_filter <= 0) {
        return src_.ReadMultiBuffer();
    }
    return ReadFramedMultiBuffer();
}

net::awaitable<common::MultiBuffer> VisionReader::ReadFramedMultiBuffer() {
    while (true) {
        common::MultiBuffer out;
        Decode(out);
        if (out.byte_size() != 0) {
            if (traffic_.packets_to_filter > 0) {
                for (const auto* buffer : out) {
                    traffic_.FilterTLS(buffer->Bytes());
                }
            }
            co_return out;
        }

        if (!read_process_) {
            common::MultiBuffer raw = co_await src_.ReadMultiBuffer();
            if (raw.byte_size() == 0) {
                co_await common::ThrowIfCancelledOnEof();
            }
            co_return raw;
        }

        common::MultiBuffer raw = co_await src_.ReadMultiBuffer();
        if (raw.byte_size() == 0) {
            co_await common::ThrowIfCancelledOnEof();
            if (read_process_ && (header_read_ != 0 || frame_active_ || expect_uuid_)) {
                throw IoSystemError(io_error::connection_reset, "VLESS Vision frame truncated");
            }
            co_return common::MultiBuffer{};
        }
        raw.MoveTo(pending_);
    }
}

VisionWriter::VisionWriter(transport::MultiBufferWriter& dst,
                           std::array<uint8_t, 16> user_uuid,
                           VisionTrafficState& traffic)
    : dst_(dst)
    , user_uuid_(user_uuid)
    , traffic_(traffic) {}

void VisionTrafficState::FilterTLS(std::span<const uint8_t> data) noexcept {
    if (data.empty() || tls_classified || packets_to_filter <= 0) {
        return;
    }
    --packets_to_filter;
    if (data.size() >= 6) {
        if (StartsWith(data, kTlsServerHandshakeStart) && data[5] == 0x02) {
            remaining_server_hello = common::LoadU16BE(data.data() + 3) + 5;
            is_tls12_or_above = true;
            is_tls = true;
        } else if (StartsWith(data, kTlsClientHandshakeStart) && data[5] == 0x01) {
            is_tls = true;
        }
    }
    if (remaining_server_hello > 0) {
        const auto end = std::min<size_t>(data.size(), remaining_server_hello);
        remaining_server_hello -= static_cast<int32_t>(data.size());
        if (ContainsBytes(data.first(end), kTls13SupportedVersions) ||
            remaining_server_hello <= 0) {
            packets_to_filter = 0;
            tls_classified = true;
        }
    }
}


net::awaitable<void> VisionWriter::WriteMultiBuffer(common::MultiBuffer mb) {
    if (!write_process_) {
        return dst_.WriteMultiBuffer(std::move(mb));
    }
    return WriteFramedMultiBuffer(std::move(mb));
}

net::awaitable<void> VisionWriter::WriteFramedMultiBuffer(common::MultiBuffer mb) {
    co_await WriteVisionFramed(
        dst_, user_uuid_, send_uuid_, write_process_, traffic_, mb);
    mb.clear();
}

net::awaitable<void> VisionWriter::WriteBuffers(std::span<const net::const_buffer> buffers) {
    if (!write_process_) {
        return dst_.WriteBuffers(buffers);
    }
    return WriteFramedBuffers(buffers);
}

net::awaitable<void> VisionWriter::WriteFramedBuffers(std::span<const net::const_buffer> buffers) {
    co_await WriteVisionFramed(
        dst_, user_uuid_, send_uuid_, write_process_, traffic_, buffers);
}

net::awaitable<void> VisionWriter::AsyncShutdownWrite() {
    return dst_.AsyncShutdownWrite();
}
}  // namespace proxy
