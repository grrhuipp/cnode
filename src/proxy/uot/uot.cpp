#include "uot.hpp"

#include "acppnode/common/buffer_util.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <utility>

namespace acpp::proxy::uot {
namespace {

enum class PendingStatus : uint8_t {
    Ready,
    Eof,
};

struct DecodedAddress {
    TargetAddress destination;
    size_t consumed = 0;
};

void PutU16BE(uint8_t* out, uint16_t value) noexcept {
    out[0] = static_cast<uint8_t>(value >> 8);
    out[1] = static_cast<uint8_t>(value);
}

uint16_t ReadU16BE(const uint8_t* in) noexcept {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(in[0]) << 8) |
        static_cast<uint16_t>(in[1]));
}

size_t EncodeAddressTo(const TargetAddress& target,
                       uint8_t* out,
                       size_t capacity,
                       bool socks_address) noexcept {
    if (!target.IsValid() || !out || capacity < 1 + 2) {
        return 0;
    }

    size_t pos = 0;
    if (target.IsIPv4() && target.resolved_addr && target.resolved_addr->is_v4()) {
        if (capacity < 1 + 4 + 2) {
            return 0;
        }
        out[pos++] = socks_address ? 0x01 : 0x00;
        const auto bytes = target.resolved_addr->to_v4().to_bytes();
        std::memcpy(out + pos, bytes.data(), bytes.size());
        pos += bytes.size();
    } else if (target.IsIPv6() && target.resolved_addr && target.resolved_addr->is_v6()) {
        if (capacity < 1 + 16 + 2) {
            return 0;
        }
        out[pos++] = socks_address ? 0x04 : 0x01;
        const auto bytes = target.resolved_addr->to_v6().to_bytes();
        std::memcpy(out + pos, bytes.data(), bytes.size());
        pos += bytes.size();
    } else if (target.IsDomain() && !target.host.empty() && target.host.size() <= 255) {
        if (capacity < 1 + 1 + target.host.size() + 2) {
            return 0;
        }
        out[pos++] = socks_address ? 0x03 : 0x02;
        out[pos++] = static_cast<uint8_t>(target.host.size());
        std::memcpy(out + pos, target.host.data(), target.host.size());
        pos += target.host.size();
    } else {
        return 0;
    }

    PutU16BE(out + pos, target.port);
    return pos + 2;
}

std::expected<DecodedAddress, ErrorCode> DecodeAddress(
    std::span<const uint8_t> data,
    bool socks_address) {
    if (data.empty()) {
        return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    size_t pos = 1;
    const uint8_t type = data[0];
    if (type == (socks_address ? 0x01 : 0x00)) {
        if (data.size() < 1 + 4 + 2) {
            return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + pos, bytes.size());
        pos += bytes.size();
        const uint16_t port = ReadU16BE(data.data() + pos);
        if (port == 0) {
            return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        return DecodedAddress{
            TargetAddress(net::ip::make_address_v4(bytes), port),
            pos + 2};
    }
    if (type == (socks_address ? 0x04 : 0x01)) {
        if (data.size() < 1 + 16 + 2) {
            return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + pos, bytes.size());
        pos += bytes.size();
        const uint16_t port = ReadU16BE(data.data() + pos);
        if (port == 0) {
            return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        return DecodedAddress{
            TargetAddress(net::ip::make_address_v6(bytes), port),
            pos + 2};
    }
    if (type == (socks_address ? 0x03 : 0x02)) {
        if (data.size() < 2) {
            return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        const size_t host_len = data[pos++];
        if (host_len == 0 || data.size() < 1 + 1 + host_len + 2) {
            return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        const std::string_view host(
            reinterpret_cast<const char*>(data.data() + pos), host_len);
        pos += host_len;
        const uint16_t port = ReadU16BE(data.data() + pos);
        if (port == 0) {
            return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        return DecodedAddress{TargetAddress(host, port), pos + 2};
    }
    return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
}

size_t AddressEncodedSizeFromPrefix(std::span<const uint8_t> prefix,
                                    bool socks_address) noexcept {
    if (prefix.empty()) {
        return 0;
    }
    const uint8_t type = prefix[0];
    if (type == (socks_address ? 0x01 : 0x00)) {
        return 1 + 4 + 2;
    }
    if (type == (socks_address ? 0x04 : 0x01)) {
        return 1 + 16 + 2;
    }
    if (type == (socks_address ? 0x03 : 0x02)) {
        return prefix.size() >= 2
            ? 1 + 1 + static_cast<size_t>(prefix[1]) + 2
            : 0;
    }
    return std::numeric_limits<size_t>::max();
}

net::awaitable<PendingStatus> EnsurePending(
    transport::MultiBufferReader& reader,
    buf::MultiBuffer& pending,
    size_t required) {
    while (buf::TotalLen(pending) < required) {
        auto next = co_await reader.ReadMultiBuffer();
        if (!buf::HasData(next)) {
            co_return PendingStatus::Eof;
        }
        next.MoveTo(pending, true);
    }
    co_return PendingStatus::Ready;
}

net::awaitable<std::expected<DecodedAddress, ErrorCode>> ReadAddress(
    transport::MultiBufferReader& reader,
    buf::MultiBuffer& pending,
    size_t offset,
    bool socks_address) {
    const size_t initial_need = offset + 2;
    if (co_await EnsurePending(reader, pending, initial_need) != PendingStatus::Ready) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    std::array<uint8_t, kMaxAddressSize + 1> prefix{};
    const size_t copied = pending.CopyPrefixTo(
        std::span<uint8_t>(prefix.data(), initial_need));
    if (copied != initial_need) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    const auto address_prefix = std::span<const uint8_t>(prefix).subspan(offset);
    const size_t address_size = AddressEncodedSizeFromPrefix(
        address_prefix, socks_address);
    if (address_size == 0 || address_size == std::numeric_limits<size_t>::max()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    if (co_await EnsurePending(reader, pending, offset + address_size) !=
        PendingStatus::Ready) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    const size_t need = offset + address_size;
    if (pending.CopyPrefixTo(std::span<uint8_t>(prefix.data(), need)) != need) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    co_return DecodeAddress(
        std::span<const uint8_t>(prefix.data() + offset, address_size),
        socks_address);
}

[[noreturn]] void ThrowDecodeFailure() {
    throw IoSystemError(io_error::connection_reset, "invalid UoT stream");
}

}  // namespace

std::optional<Version> VersionFromMagicAddress(
    const TargetAddress& target) noexcept {
    if (!target.IsDomain()) {
        return std::nullopt;
    }
    if (target.host == kMagicAddress) {
        return Version::V2;
    }
    if (target.host == kV1MagicAddress) {
        return Version::V1;
    }
    return std::nullopt;
}

std::expected<EncodedRequest, ErrorCode> EncodeRequest(
    bool is_connect,
    const TargetAddress& destination) {
    EncodedRequest out;
    out.bytes[0] = is_connect ? 0x01 : 0x00;
    const size_t address_size = EncodeAddressTo(
        destination,
        out.bytes.data() + 1,
        out.bytes.size() - 1,
        true);
    if (address_size == 0) {
        return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    out.size = 1 + address_size;
    return out;
}

net::awaitable<std::expected<Request, ErrorCode>> ReadRequest(
    transport::MultiBufferReader& reader,
    buf::MultiBuffer& pending) {
    if (co_await EnsurePending(reader, pending, 1) != PendingStatus::Ready) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    std::array<uint8_t, 1> first{};
    if (pending.CopyPrefixTo(first) != first.size() || first[0] > 1) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto address = co_await ReadAddress(reader, pending, 1, true);
    if (!address || !address->destination.IsValid()) {
        co_return std::unexpected(address
            ? ErrorCode::PROTOCOL_INVALID_ADDRESS
            : address.error());
    }

    Request request;
    request.is_connect = first[0] != 0;
    request.destination = std::move(address->destination);
    request.consumed = 1 + address->consumed;
    pending.DropPrefixBytes(request.consumed);
    co_return request;
}

PacketReader::PacketReader(transport::MultiBufferReader& reader,
                           bool is_connect,
                           TargetAddress destination,
                           buf::MultiBuffer pending)
    : reader_(reader)
    , is_connect_(is_connect)
    , destination_(std::move(destination))
    , pending_(std::move(pending)) {}

void PacketReader::SetInitialDecoded(buf::MultiBuffer packet) noexcept {
    initial_decoded_ = std::move(packet);
}

net::awaitable<buf::MultiBuffer> PacketReader::ReadMultiBuffer() {
    if (buf::HasData(initial_decoded_)) {
        co_return std::move(initial_decoded_);
    }

    for (;;) {
        TargetAddress packet_target = destination_;
        size_t header_size = 0;
        if (is_connect_) {
            if (co_await EnsurePending(reader_, pending_, 2) != PendingStatus::Ready) {
                if (!buf::HasData(pending_)) {
                    co_return buf::MultiBuffer{};
                }
                ThrowDecodeFailure();
            }
            header_size = 2;
        } else {
            auto address = co_await ReadAddress(reader_, pending_, 0, false);
            if (!address || !address->destination.IsValid()) {
                ThrowDecodeFailure();
            }
            packet_target = std::move(address->destination);
            header_size = address->consumed + 2;
            if (co_await EnsurePending(reader_, pending_, header_size) != PendingStatus::Ready) {
                ThrowDecodeFailure();
            }
        }

        std::array<uint8_t, kMaxAddressSize + 2> header{};
        if (pending_.CopyPrefixTo(
                std::span<uint8_t>(header.data(), header_size)) != header_size) {
            ThrowDecodeFailure();
        }
        const size_t length_offset = header_size - 2;
        const size_t payload_size = ReadU16BE(header.data() + length_offset);
        if (co_await EnsurePending(reader_, pending_, header_size + payload_size) !=
            PendingStatus::Ready) {
            ThrowDecodeFailure();
        }

        pending_.DropPrefixBytes(header_size);
        if (payload_size == 0) {
            continue;
        }
        buf::MultiBuffer packet;
        if (!pending_.MovePrefixTo(packet, payload_size)) {
            ThrowDecodeFailure();
        }
        for (buf::Buffer* buffer : packet) {
            if (buffer) {
                buffer->SetUDP(packet_target);
            }
        }
        co_return packet;
    }
}

PacketWriter::PacketWriter(transport::MultiBufferWriter& writer,
                           bool is_connect,
                           TargetAddress destination)
    : writer_(writer)
    , is_connect_(is_connect)
    , destination_(std::move(destination)) {}

net::awaitable<void> PacketWriter::WritePacket(
    const TargetAddress& destination,
    std::span<const net::const_buffer> payload) {
    size_t payload_size = 0;
    for (const auto& buffer : payload) {
        if (buffer.size() >
            std::numeric_limits<uint16_t>::max() - payload_size) {
            ThrowDecodeFailure();
        }
        payload_size += buffer.size();
    }

    std::array<uint8_t, kMaxAddressSize + 2> header{};
    size_t header_size = 0;
    if (!is_connect_) {
        header_size = EncodeAddressTo(
            destination, header.data(), header.size() - 2, false);
        if (header_size == 0) {
            ThrowDecodeFailure();
        }
    }
    PutU16BE(header.data() + header_size, static_cast<uint16_t>(payload_size));
    header_size += 2;

    ConstBufferSpanBuilder<8> buffers;
    buffers.Append(net::buffer(header.data(), header_size));
    buffers.AppendBuffers(payload);
    co_await writer_.WriteBuffers(buffers.Span());
}

net::awaitable<void> PacketWriter::WriteMultiBuffer(buf::MultiBuffer mb) {
    const TargetAddress* target = nullptr;
    if (is_connect_) {
        if (!destination_.IsValid()) {
            ThrowDecodeFailure();
        }
        target = std::addressof(destination_);
    } else {
        const auto datagram = buf::InspectUdpDatagram(mb);
        if (datagram.status == buf::UdpDatagramStatus::Empty) {
            co_return;
        }
        if (!datagram.Valid() || !datagram.target->IsValid()) {
            ThrowDecodeFailure();
        }
        target = datagram.target;
    }

    ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> payload;
    for (const buf::Buffer* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        payload.Append(net::const_buffer(bytes.data(), bytes.size()));
    }
    if (!payload.empty()) {
        co_await WritePacket(*target, payload.Span());
    }
}

net::awaitable<void> PacketWriter::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (!destination_.IsValid()) {
        ThrowDecodeFailure();
    }
    co_await WritePacket(destination_, buffers);
}

net::awaitable<void> PacketWriter::AsyncShutdownWrite() {
    co_await writer_.AsyncShutdownWrite();
}

}  // namespace acpp::proxy::uot
