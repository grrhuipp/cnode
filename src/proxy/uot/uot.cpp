#include "proxy/uot/uot.hpp"
#include "app/relay.hpp"
#include "proxy/inbound_admission.hpp"
#include "proxy/udp_datagram_frame.hpp"
#include "proxy/buffered_stream_reader.hpp"
#include "common/byte_reader.hpp"
#include "common/address_codec.hpp"

#include "common/eof_cancellation.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"

#include <array>
#include <cstring>
#include <memory>
#include <new>
#include <utility>

namespace proxy::uot {
namespace {

[[noreturn]] void ThrowDecodeFailure() {
    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
}

using PacketHeader = std::array<uint8_t, kMaxBaseEncodedAddressSize + 2>;

// Returns the encoded size. The caller's frame owns `header` across the write.
size_t EncodePacketHeader(bool is_connect,
                          const TargetAddress& destination,
                          uint16_t payload_size,
                          PacketHeader& header) {
    size_t header_size = 0;
    if (!is_connect) {
        header_size = EncodeAddressTo(
            destination, header.data(), header.size() - 2, AddressWireFormat::Uot);
        if (header_size == 0) {
            throw transport::LinkError(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
    }
    StoreU16BE(header.data() + header_size, payload_size);
    return header_size + 2;
}

// V2: an explicit request precedes the packet stream.
net::awaitable<tl::expected<PreparedRequest, ErrorCode>> ReadV2Request(
    transport::MultiBufferReader& reader,
    buf::MultiBuffer pending) {
    if (!co_await BufferedStreamReader::EnsureBufferedFrom(reader, pending, 1, buf::kPacketStreamPendingLimit)) {
        co_return tl::unexpected(ErrorCode::SOCKET_EOF);
    }
    std::array<uint8_t, 1> first{};
    if (pending.CopyPrefixTo(first) != first.size() || first[0] > 1) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto address = co_await ::ReadAddress(
        reader, pending, AddressWireFormat::Socks5, 1,
        {.require_non_empty_domain = true, .allow_metadata = true});
    if (!address || !address->target.IsValid()) {
        co_return tl::unexpected(address
            ? ErrorCode::PROTOCOL_INVALID_ADDRESS
            : address.error());
    }

    PreparedRequest out;
    out.is_connect = first[0] != 0;
    out.destination = std::move(address->target);
    out.forwarded = std::move(address->forwarded);
    pending.DropPrefixBytes(1 + address->consumed);
    pending.ReleaseIfIdle();
    out.pending = std::move(pending);
    co_return out;
}

// V1: the first packet's target is the request target.
net::awaitable<tl::expected<PreparedRequest, ErrorCode>> ReadV1Request(
    transport::MultiBufferReader& reader,
    buf::MultiBuffer pending) {
    PacketReader packet_reader(reader, false, TargetAddress{}, std::move(pending));
    auto first_packet = co_await packet_reader.ReadMultiBuffer();
    if (first_packet.empty()) {
        co_return tl::unexpected(ErrorCode::SOCKET_EOF);
    }
    PreparedRequest out;
    const auto datagram = buf::InspectUdpDatagram(first_packet);
    if (datagram.Valid()) {
        out.destination = *datagram.target;
    }
    if (!out.destination.IsValid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    out.pending = packet_reader.TakePending();
    out.initial_decoded = std::move(first_packet);
    co_return out;
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
    const TargetAddress& destination,
    ForwardedMetadataView forwarded) {
    EncodedRequest out;
    out.bytes[0] = is_connect ? 0x01 : 0x00;
    const size_t address_size = destination.IsValid()
        ? EncodeAddressTo(destination, out.bytes.data() + 1,
                          out.bytes.size() - 1, AddressWireFormat::Socks5,
                          forwarded)
        : 0;
    if (address_size == 0) {
        return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    out.size = 1 + address_size;
    return out;
}

net::awaitable<tl::expected<PreparedRequest, ErrorCode>> ReadUotRequestHeader(
    Version version,
    transport::MultiBufferReader& reader,
    buf::MultiBuffer pending) {
    try {
        co_return version == Version::V2
            ? co_await ReadV2Request(reader, std::move(pending))
            : co_await ReadV1Request(reader, std::move(pending));
    } catch (const transport::LinkError& e) {
        co_return tl::unexpected(e.code());
    } catch (const IoSystemError& e) {
        co_return tl::unexpected(MapAsioError(e.code()));
    }
}

net::awaitable<RelayResult> DispatchPreparedUotRequest(
    PreparedRequest prepared,
    std::unique_ptr<AsyncStream> stream,
    transport::MultiBufferReader& request_reader,
    transport::MultiBufferWriter& response_writer,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& dispatch_policy,
    net::io_context& io_context,
    session::Context& ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts) {
    const bool is_connect = prepared.is_connect;
    InitialPayload initial_payload{std::move(prepared.initial_decoded)};
    proxy::BindInboundRequestTarget(
        ctx,
        proxy::InboundRequestTarget{
            Network::UDP,
            prepared.destination,
            std::move(prepared.forwarded)});
    PacketReader uot_reader(request_reader, std::move(prepared));
    PacketWriter uot_writer(response_writer, is_connect, ctx.outbound.target);
    co_return co_await dispatcher.Dispatch(
        io_context,
        dispatch_policy,
        std::move(stream),
        transport::Link{&uot_reader, &uot_writer},
        std::move(initial_payload),
        ctx,
        stats,
        timeouts);
}

PacketReader::PacketReader(transport::MultiBufferReader& reader,
                           bool is_connect,
                           TargetAddress destination,
                           buf::MultiBuffer pending)
    : reader_(reader)
    , is_connect_(is_connect)
    , destination_(is_connect ? std::move(destination) : TargetAddress{})
    , pending_(std::move(pending)) {}

PacketReader::PacketReader(transport::MultiBufferReader& reader,
                           PreparedRequest prepared)
    : reader_(reader)
    , is_connect_(prepared.is_connect)
    , destination_(prepared.is_connect ? std::move(prepared.destination) : TargetAddress{})
    , pending_(std::move(prepared.pending)) {}

buf::MultiBuffer PacketReader::TakePending() noexcept {
    buf::MultiBuffer out = std::move(pending_);
    pending_.ReleaseIfIdle();
    return out;
}
net::awaitable<buf::MultiBuffer> PacketReader::ReadMultiBuffer() {
    if (pending_.byte_size() < 1 &&
        !co_await BufferedStreamReader::EnsureBufferedFrom(reader_, pending_, 1, buf::kPacketStreamPendingLimit))
        co_return buf::MultiBuffer{};
    TargetAddress packet_target;
    if (!is_connect_) {
        auto address = co_await ::ReadAddress(
            reader_, pending_, AddressWireFormat::Uot, 0,
            {.require_non_empty_domain = true, .allow_metadata = false});
        if (!address || !address->target.IsValid()) {
            ThrowDecodeFailure();
        }
        packet_target = std::move(address->target);
        (void)pending_.DropPrefixBytes(address->consumed);
    }
    if (pending_.byte_size() < 2 &&
        !co_await BufferedStreamReader::EnsureBufferedFrom(reader_, pending_, 2, buf::kPacketStreamPendingLimit)) {
        ThrowDecodeFailure();
    }

    std::array<uint8_t, 2> len_bytes{};
    if (pending_.CopyPrefixTo(len_bytes) != len_bytes.size()) {
        ThrowDecodeFailure();
    }
    const size_t payload_size = LoadU16BE(len_bytes.data());
    (void)pending_.DropPrefixBytes(len_bytes.size());
    if (pending_.byte_size() < payload_size &&
        !co_await BufferedStreamReader::EnsureBufferedFrom(reader_, pending_, payload_size, buf::kPacketStreamPendingLimit)) {
        ThrowDecodeFailure();
    }
    buf::MultiBuffer packet;
    if (!pending_.MovePrefixTo(packet, payload_size)) {
        ThrowDecodeFailure();
    }
    pending_.ReleaseIfIdle();
    if (!buf::SetUdpTarget(packet, is_connect_ ? destination_ : packet_target)) {
        throw std::bad_alloc();
    }
    co_return packet;
}

PacketWriter::PacketWriter(transport::MultiBufferWriter& writer,
                           bool is_connect,
                           TargetAddress destination)
    : writer_(writer)
    , is_connect_(is_connect)
    , destination_(std::move(destination)) {}

net::awaitable<void> PacketWriter::WriteMultiBuffer(buf::MultiBuffer mb) {
    // Connect mode frames carry no address: the response is bound to the
    // session destination whatever endpoint the datagram reports.
    const auto datagram = RequireUdpDatagram(mb, nullptr);
    if (!datagram) {
        co_return;
    }
    if (is_connect_ && !destination_.IsValid()) {
        throw transport::LinkError(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    PacketHeader header{};
    const size_t header_size = EncodePacketHeader(
        is_connect_, is_connect_ ? destination_ : *datagram->target,
        static_cast<uint16_t>(datagram->payload_size), header);
    co_await WriteFramedDatagram(
        writer_, std::span<const uint8_t>(header.data(), header_size), mb);
}

net::awaitable<void> PacketWriter::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (!destination_.IsValid()) {
        throw transport::LinkError(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    const size_t payload_size = RequireUdpPayloadSize(buffers);
    PacketHeader header{};
    const size_t header_size = EncodePacketHeader(
        is_connect_, destination_, static_cast<uint16_t>(payload_size), header);
    co_await WriteFramedDatagram(
        writer_, std::span<const uint8_t>(header.data(), header_size), buffers);
}

net::awaitable<void> PacketWriter::AsyncShutdownWrite() {
    return writer_.AsyncShutdownWrite();
}

}  // namespace proxy::uot
