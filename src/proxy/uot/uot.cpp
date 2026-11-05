#include "uot.hpp"
#include "acppnode/common/byte_reader.hpp"
#include "acppnode/common/address_codec.hpp"

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



net::awaitable<PendingStatus> EnsurePending(
    transport::MultiBufferReader& reader,
    buf::MultiBuffer& pending,
    size_t required) {
    while (pending.byte_size() < required) {
        auto next = co_await reader.ReadMultiBuffer();
        if (next.byte_size() == 0) {
            co_return PendingStatus::Eof;
        }
        next.MoveTo(pending, true);
    }
    co_return PendingStatus::Ready;
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

tl::expected<EncodedRequest, ErrorCode> EncodeRequest(
    bool is_connect,
    const TargetAddress& destination) {
    EncodedRequest out;
    out.bytes[0] = is_connect ? 0x01 : 0x00;
    const size_t address_size = destination.IsValid()
        ? EncodeAddressTo(destination, out.bytes.data() + 1,
                          out.bytes.size() - 1, AddressWireFormat::Socks5)
        : 0;
    if (address_size == 0) {
        return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    out.size = 1 + address_size;
    return out;
}

net::awaitable<tl::expected<Request, ErrorCode>> ReadRequest(
    transport::MultiBufferReader& reader,
    buf::MultiBuffer& pending) {
    if (co_await EnsurePending(reader, pending, 1) != PendingStatus::Ready) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    std::array<uint8_t, 1> first{};
    if (pending.CopyPrefixTo(first) != first.size() || first[0] > 1) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto address = co_await acpp::ReadAddress(
        reader, pending, AddressWireFormat::Socks5, 1, {255, true});
    if (!address || !address->target.IsValid()) {
        co_return tl::unexpected(address
            ? ErrorCode::PROTOCOL_INVALID_ADDRESS
            : address.error());
    }

    Request request;
    request.is_connect = first[0] != 0;
    request.destination = std::move(address->target);
    pending.DropPrefixBytes(1 + address->consumed);
    pending.ReleaseIfIdle();
    co_return request;
}

net::awaitable<tl::expected<PreparedRequest, ErrorCode>> ReadUotRequestHeader(
    Version version,
    transport::MultiBufferReader& reader,
    buf::MultiBuffer pending,
    ErrorCode v1_eof_error) {
    PreparedRequest out;
    if (version == Version::V2) {
        auto request = co_await ReadRequest(reader, pending);
        if (!request || !request->destination.IsValid()) {
            co_return tl::unexpected(request
                ? ErrorCode::PROTOCOL_INVALID_ADDRESS
                : request.error());
        }
        out.is_connect = request->is_connect;
        out.destination = std::move(request->destination);
        out.pending = std::move(pending);
        co_return out;
    }

    PacketReader packet_reader(reader, false, TargetAddress{}, std::move(pending));
    try {
        auto first_packet = co_await packet_reader.ReadMultiBuffer();
        if (first_packet.byte_size() == 0) {
            co_return tl::unexpected(v1_eof_error);
        }
        for (const buf::Buffer* buffer : first_packet) {
            if (buffer && buffer->HasUDP()) {
                out.destination = buffer->UDP();
                break;
            }
        }
        if (!out.destination.IsValid()) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        out.pending = packet_reader.TakePending();
        out.initial_decoded = std::move(first_packet);
        co_return out;
    } catch (const IoSystemError& e) {
        co_return tl::unexpected(MapAsioError(e.code()));
    }
}

PacketReader::PacketReader(transport::MultiBufferReader& reader,
                           bool is_connect,
                           TargetAddress destination,
                           buf::MultiBuffer pending)
    : reader_(reader)
    , is_connect_(is_connect)
    , destination_(std::move(destination))
    , pending_(std::move(pending)) {}

PacketReader::PacketReader(transport::MultiBufferReader& reader,
                           PreparedRequest prepared)
    : reader_(reader)
    , is_connect_(prepared.is_connect)
    , destination_(std::move(prepared.destination))
    , pending_(std::move(prepared.pending))
    , initial_decoded_(std::move(prepared.initial_decoded)) {}

buf::MultiBuffer PacketReader::TakePending() noexcept {
    buf::MultiBuffer out = std::move(pending_);
    pending_.ReleaseIfIdle();
    return out;
}
net::awaitable<buf::MultiBuffer> PacketReader::ReadMultiBuffer() {
    if (initial_decoded_.byte_size() != 0) {
        co_return std::move(initial_decoded_);
    }

    for (;;) {
        if (co_await EnsurePending(reader_, pending_, 1) != PendingStatus::Ready)
            co_return buf::MultiBuffer{};
        TargetAddress packet_target = destination_;
        size_t header_size = 0;
        if (is_connect_) {
            if (co_await EnsurePending(reader_, pending_, 2) != PendingStatus::Ready) {
                if (pending_.byte_size() == 0) {
                    co_return buf::MultiBuffer{};
                }
                ThrowDecodeFailure();
            }
            header_size = 2;
        } else {
            auto address = co_await acpp::ReadAddress(
                reader_, pending_, AddressWireFormat::Uot, 0, {255, true});
            if (!address || !address->target.IsValid()) {
                ThrowDecodeFailure();
            }
            packet_target = std::move(address->target);
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
        const size_t payload_size = LoadU16BE(header.data() + length_offset);
        if (co_await EnsurePending(reader_, pending_, header_size + payload_size) !=
            PendingStatus::Ready) {
            ThrowDecodeFailure();
        }

        pending_.DropPrefixBytes(header_size);
        if (payload_size == 0) {
            pending_.ReleaseIfIdle();
            continue;
        }
        buf::MultiBuffer packet;
        if (!pending_.MovePrefixTo(packet, payload_size)) {
            ThrowDecodeFailure();
        }
        pending_.ReleaseIfIdle();
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
            destination, header.data(), header.size() - 2, AddressWireFormat::Uot);
        if (header_size == 0) {
            ThrowDecodeFailure();
        }
    }
    StoreU16BE(header.data() + header_size, static_cast<uint16_t>(payload_size));
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
