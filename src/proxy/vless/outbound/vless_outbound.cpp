#include "vless_outbound.hpp"
#include "common/domain_name.hpp"
#include "common/ip_address.hpp"

#include "../vless_codec.hpp"
#include "../vless_encryption.hpp"
#include "../vless_encryption_io.hpp"
#include "../vless_encryption_runtime.hpp"
#include "../vless_buffered_reader.hpp"
#include "../udp_framing.hpp"
#include "../vless_vision.hpp"
#include "../../handshake_timeout.hpp"
#include "../../outbound_server.hpp"
#include "../../outbound_stream_endpoint.hpp"
#include "app/dns/dns.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "app/session_group_executor.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "infra/json_field.hpp"
#include "app/relay.hpp"
#include "common/allocator.hpp"
#include "common/buffer_util.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "common/error.hpp"
#include "common/mux/mux_codec.hpp"
#include "common/session.hpp"
#include "core/constants.hpp"
#include "core/naming.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "../credentials.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/link.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <array>
#include <cctype>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>


namespace {

using ::vless::VlessBufferedReader;
using ::vless::WriteVlessBytes;

// Version, addons length, then addons this client ignores. Progress lives in
// the endpoint so a cancelled read resumes at the same stream offset.
struct VlessResponseHeaderState {
    std::array<uint8_t, 2> fixed{};
    size_t fixed_read = 0;
    size_t addons_read = 0;
    bool complete = false;
};

net::awaitable<void> ReadVlessResponseHeader(VlessBufferedReader& reader,
                                             VlessResponseHeaderState& state,
                                             const char* failure) {
    if (state.complete) {
        co_return;
    }
    if (!co_await reader.ReadExact(
            state.fixed.data(), state.fixed.size(), false, &state.fixed_read) ||
        state.fixed[0] != vless::kVersion) {
        throw IoSystemError(io_error::connection_reset, failure);
    }
    std::array<uint8_t, 255> ignored_addons;
    if (!co_await reader.ReadExact(
            ignored_addons.data(), state.fixed[1], false, &state.addons_read)) {
        throw IoSystemError(io_error::connection_reset, failure);
    }
    state.complete = true;
}

class VlessOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    struct VisionIoState : memory::ThreadAllocated {
        ::vless::VisionTrafficState traffic;
        ::vless::VisionReader reader;
        ::vless::VisionWriter writer;

        VisionIoState(VlessBufferedReader& src,
                      transport::MultiBufferWriter& dst,
                      std::array<uint8_t, 16> user_uuid)
            : reader(src, user_uuid, traffic)
            , writer(dst, user_uuid, traffic) {}
    };
    struct UdpIoState : memory::ThreadAllocated {
        explicit UdpIoState(bool packet_addr) : framer(packet_addr) {}
        ::vless::UdpFramer framer;
    };

    VlessOutboundEndpoint(AsyncStream& control,
                          VlessBufferedReader& reader,
                          transport::MultiBufferWriter& writer,
                          bool is_udp,
                          TargetAddress udp_target,
                          bool packet_addr,
                          bool vision,
                          std::array<uint8_t, 16> user_uuid)
        : OutboundStreamEndpointBase(control)
        , reader_(reader)
        , writer_(writer)
        , is_udp_(is_udp)
        , udp_target_(std::move(udp_target))
        , packet_addr_(packet_addr) {
        if (is_udp_) {
            io_state_.emplace<UdpIoState>(packet_addr);
        } else if (vision) {
            io_state_.emplace<VisionIoState>(reader_, writer_, user_uuid);
        }
        OPENSSL_cleanse(user_uuid.data(), user_uuid.size());
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        co_await ReadVlessResponseHeader(
            reader_, response_header_, "VLESS response header read failed");
        if (auto* udp_io = std::get_if<UdpIoState>(&io_state_)) {
            co_return co_await udp_io->framer.ReadDatagram(reader_, udp_target_);
        }
        if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
            co_return co_await vision_io->reader.ReadMultiBuffer();
        }
        co_return co_await reader_.ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!is_udp_) {
            if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
                return vision_io->writer.WriteMultiBuffer(std::move(mb));
            }
            return writer_.WriteMultiBuffer(std::move(mb));
        }

        return ::vless::WriteUdpDatagram(
            writer_, std::move(mb), packet_addr_,
            packet_addr_ ? nullptr : &udp_target_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!is_udp_) {
            if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
                return vision_io->writer.WriteBuffers(buffers);
            }
            return writer_.WriteBuffers(buffers);
        }

        return ::vless::WriteUdpDatagram(
            writer_, udp_target_, packet_addr_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return writer_.AsyncShutdownWrite();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : reader_.ReadEofAction();
    }

private:
    VlessBufferedReader& reader_;
    transport::MultiBufferWriter& writer_;
    VlessResponseHeaderState response_header_;
    bool is_udp_ = false;
    TargetAddress udp_target_;
    bool packet_addr_ = false;
    std::variant<std::monostate, VisionIoState, UdpIoState> io_state_;
};


class VlessMuxUdpEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    VlessMuxUdpEndpoint(AsyncStream& control,
                        VlessBufferedReader& reader,
                        transport::MultiBufferWriter& writer,
                        TargetAddress udp_target,
                        ForwardedMetadataView forwarded)
        : OutboundStreamEndpointBase(control)
        , reader_(reader)
        , writer_(writer)
        , udp_target_(std::move(udp_target)) {
        if (!forwarded.Empty()) {
            auto& owned = forwarded_.emplace();
            owned.user_id = forwarded.user_id;
            owned.user_email.assign(forwarded.user_email.data(), forwarded.user_email.size());
            owned.client_ip = forwarded.client_ip;
            owned.inbound_tag.assign(forwarded.inbound_tag.data(), forwarded.inbound_tag.size());
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (peer_ended_) {
            co_return buf::MultiBuffer{};
        }
        co_await ReadVlessResponseHeader(
            reader_, response_header_, "VLESS mux response header read failed");

        while (true) {
            auto header = mux::DecodeFrame(pending_);
            if (header) {
                if (header->frame_size == 0) {
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (header->status == mux::SessionStatus::KEEPALIVE) {
                    (void)pending_.DropPrefixBytes(header->frame_size);
                    pending_.ReleaseIfIdle();
                    continue;
                }
                if (header->status == mux::SessionStatus::NEW) {
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (header->session_id != session_id_) {
                    throw IoSystemError(
                        io_error::connection_reset,
                        "VLESS mux response session id mismatch");
                }
                if ((header->option & mux::kOptionError) != 0) {
                    throw IoSystemError(
                        io_error::connection_reset,
                        "VLESS mux response error frame");
                }
                if (header->has_target && header->network != mux::NetworkType::UDP) {
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                buf::MultiBuffer payload;
                if (header->data_len == 0) {
                    (void)pending_.DropPrefixBytes(header->frame_size);
                } else {
                    (void)pending_.DropPrefixBytes(header->frame_size - header->data_len);
                    if (!pending_.MovePrefixTo(payload, header->data_len)) {
                        throw std::bad_alloc();
                    }
                }
                pending_.ReleaseIfIdle();
                if (header->status == mux::SessionStatus::END) {
                    peer_ended_ = true;
                    pending_.clear();
                    if (!header->has_data) {
                        co_return buf::MultiBuffer{};
                    }
                }
                if (!header->has_data) continue;
                const TargetAddress& src = header->has_target
                    ? header->target
                    : udp_target_;
                if (!buf::SetUdpTarget(payload, src)) {
                    throw std::bad_alloc();
                }
                co_return payload;
            }

            buf::MultiBuffer raw = co_await ReadMultiBufferOrThrowOnCancel(reader_);
            if (raw.byte_size() == 0) {
                if (pending_.byte_size() != 0) {
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                co_return buf::MultiBuffer{};
            }
            buf::AppendPacketStreamInput(pending_, std::move(raw));
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        const auto datagram = buf::InspectUdpDatagram(mb);
        if (datagram.status == buf::UdpDatagramStatus::Empty) {
            co_return;
        }
        if (!datagram.Valid() || !datagram.target->IsValid()) {
            throw IoSystemError(
                io_error::invalid_argument,
                "VLESS mux datagram contains missing or mixed targets");
        }
        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> payload;
        payload.AppendMultiBuffer(mb);
        co_await WriteDatagram(*datagram.target, payload.Span());
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        co_await WriteDatagram(udp_target_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (session_started_ && !end_sent_) {
            std::array<uint8_t, 6> write_frame{};
            const size_t header_len = mux::EncodeEndTo(write_frame, session_id_);
            co_await WriteVlessBytes(
                writer_, std::span<const uint8_t>(write_frame.data(), header_len));
            end_sent_ = true;
        }
        co_await writer_.AsyncShutdownWrite();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::WaitForPeer;
    }

private:
    net::awaitable<void> WriteDatagram(
        const TargetAddress& target,
        std::span<const net::const_buffer> payload) {
        const auto payload_size = buf::TrySumBufferSizes(
            payload, std::numeric_limits<uint16_t>::max());
        if (!payload_size) {
            throw IoSystemError(
                io_error::message_size,
                "VLESS mux datagram exceeds wire length");
        }

        std::array<uint8_t, mux::kMaxFrameHeaderBytes> write_frame{};
        const size_t header_len = !session_started_
            ? mux::EncodeNewHeaderTo(
                  write_frame, session_id_, mux::NetworkType::UDP,
                  target, *payload_size, true,
                  forwarded_ ? forwarded_->View() : ForwardedMetadataView{})
            : mux::EncodeKeepUDPHeaderTo(
                  write_frame, session_id_, target, *payload_size);
        if (header_len == 0) {
            throw IoSystemError(
                io_error::connection_reset,
                "VLESS mux request encode failed");
        }

        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity + 1> frame;
        frame.Append(net::const_buffer(write_frame.data(), header_len));
        frame.AppendBuffers(payload);
        co_await writer_.WriteBuffers(frame.Span());
        session_started_ = true;
        forwarded_.reset();
    }

    VlessBufferedReader& reader_;
    transport::MultiBufferWriter& writer_;
    TargetAddress udp_target_;
    std::optional<ForwardedMetadata> forwarded_;
    VlessResponseHeaderState response_header_;
    bool session_started_ = false;
    bool end_sent_ = false;
    bool peer_ended_ = false;
    uint16_t session_id_ = 1;
    buf::MultiBuffer pending_;
};

net::awaitable<tl::expected<void, ErrorCode>>
SendVlessHandshake(
    AsyncStream& stream,
    const VlessOutboundConfig& config,
    ::vless::VlessEncryptionClientTicketCache* encryption_tickets,
    const TargetAddress& target,
    bool is_udp,
    bool use_vision,
    bool use_xudp,
    bool use_packet_addr,
    std::chrono::seconds handshake_timeout,
    VlessBufferedReader& protocol_reader,
    transport::MultiBufferWriter& protocol_writer,
    std::unique_ptr<::vless::VlessEncryptedIo>& encrypted_io,
    VlessBufferedReader*& active_reader,
    transport::MultiBufferWriter*& active_writer,
    const OutboundDialer& dialer,
    const session::Context& ctx) {
    stream.SetIdleTimeout(handshake_timeout);
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream.StartPhaseDeadline(handshake_timeout);

    if (config.encryption) {
        try {
            auto runtime =
                co_await ::vless::RunVlessEncryptionClientHandshake(
                    protocol_reader,
                    protocol_writer,
                    *config.encryption,
                    encryption_tickets);
            if (!runtime) {
                if (proxy::ConsumeOutboundHandshakeTimeout(
                        stream, outbound_protocol_deadline)) {
                    co_return tl::unexpected(ErrorCode::TIMEOUT);
                }
                if (runtime.error() == ::vless::VlessEncryptionHandshakeFailure::Truncated) {
                    co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
                }
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            encrypted_io = std::make_unique<::vless::VlessEncryptedIo>(
                protocol_reader, protocol_writer, std::move(*runtime));
            active_reader = &encrypted_io->plain_reader;
            active_writer = &encrypted_io->writer;
        } catch (...) {
            co_return tl::unexpected(
                proxy::ClassifyOutboundHandshakeException(
                    stream,
                    outbound_protocol_deadline,
                    ErrorCode::PROTOCOL_DECODE_FAILED));
        }
    }

    std::array<uint8_t, ::vless::kMaxRequestHeaderSize> header_buf{};
    const TargetAddress packet_magic_target = use_packet_addr
        ? TargetAddress(::vless::kPacketAddrMagicAddress, 0)
        : TargetAddress{};
    const TargetAddress& request_target = use_packet_addr ? packet_magic_target : target;
    const size_t header_len = ::vless::EncodeRequestHeaderTo(
        config.uuid_bytes,
        use_xudp
            ? ::vless::Command::MUX
            : (is_udp ? ::vless::Command::UDP : ::vless::Command::TCP),
        request_target,
        header_buf.data(),
        header_buf.size(),
        use_vision ? std::string_view(config.flow) : std::string_view{},
        dialer.ForwardedMetadata(ctx));
    if (header_len == 0) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    try {
        co_await WriteVlessBytes(
            *active_writer, std::span<const uint8_t>(header_buf.data(), header_len));
    } catch (...) {
        OPENSSL_cleanse(header_buf.data(), header_len);
        const ErrorCode classified = proxy::ClassifyOutboundHandshakeException(
            stream, outbound_protocol_deadline);
        if (encrypted_io && classified != ErrorCode::CANCELLED) {
            encrypted_io->reader.ClearDeferredTicket();
        }
        co_return tl::unexpected(classified);
    }
    OPENSSL_cleanse(header_buf.data(), header_len);
    co_return tl::expected<void, ErrorCode>{};
}

}  // namespace

proxy::vless::outbound::Handler::Handler(
    std::shared_ptr<const VlessOutboundConfig> config)
    : config_(std::move(config))
    , encryption_tickets_(config_->encryption
          ? std::make_shared<::vless::VlessEncryptionClientTicketCache>()
          : nullptr)
    , ticket_domain_(ExecutionDomain::Current())
    , has_ticket_domain_(static_cast<bool>(ExecutionDomain::Current())) {}

proxy::vless::outbound::Handler::~Handler() = default;

net::awaitable<OutboundProcessResult>
proxy::vless::outbound::Handler::Process(
    session::Context& ctx,
    transport::Link inbound,
    OutboundDialer& dialer,
    const TimeoutsConfig& timeouts,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!config_->flow.empty() && ctx.content.network != Network::TCP) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const auto& target = ctx.outbound.target;
    auto dialed = co_await dialer.Dial(ctx, config_->server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);

    auto fail_abortive = [&](ErrorCode error) {
        if (stream) {
            stream->CloseAbortive();
        }
        return tl::unexpected(error);
    };

    const bool is_udp = ctx.content.network == Network::UDP;
    const bool use_vision = !config_->flow.empty();
    const bool use_xudp = is_udp && config_->packet_xudp;
    const bool use_packet_addr = is_udp && config_->packet_addr;
    // Only the stable host reads/writes the cache. The deferred 0-RTT reader
    // holds a private snapshot; rejection clears only that exact ticket identity,
    // never a ticket published by a concurrent successful handshake.
    struct TicketLease {
        std::shared_ptr<::vless::VlessEncryptionClientTicketCache> cache{};
        std::shared_ptr<ExecutionDomain> domain{};
        bool has_domain = false;
        ::vless::VlessEncryptionClientTicketCache local{};
        std::array<uint8_t, ::vless::kVlessEncryptionTicketSize> identity{};
        std::chrono::steady_clock::time_point original_expiry{};

        net::awaitable<void> Acquire() {
            if (!cache || (has_domain && !domain)) co_return;
            auto read = [&]() -> net::awaitable<::vless::VlessEncryptionClientTicketCache> {
                co_return *cache;
            };
            local = domain
                ? co_await net::co_spawn(domain->Executor(), read(),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable))
                : co_await read();
            identity = local.ticket;
            original_expiry = local.expires_at;
        }
        net::awaitable<void> Publish() {
            if (!cache || (has_domain && !domain) ||
                (local.ticket == identity && local.expires_at == original_expiry))
                co_return;
            auto publish = [&]() -> net::awaitable<void> {
                if (cache->ticket == identity) *cache = local;
                co_return;
            };
            if (domain) {
                co_await net::co_spawn(domain->Executor(), publish(),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
            } else {
                co_await publish();
            }
            identity = local.ticket;
        }
        ~TicketLease() {
            if (!cache || (has_domain && !domain) ||
                local.expires_at != std::chrono::steady_clock::time_point{}) return;
            auto invalidate = [cache = std::move(cache), identity = identity] {
                if (cache->ticket == identity) cache->Clear();
            };
            if (domain) domain->Execute(std::move(invalidate));
            else invalidate();
        }
    } tickets{
        .cache = encryption_tickets_,
        .domain = ticket_domain_.lock(),
        .has_domain = has_ticket_domain_,
        .local = {},
        .identity = {},
        .original_expiry = {},
    };
    co_await tickets.Acquire();
    VlessBufferedReader protocol_reader(*stream);
    transport::MultiBufferWriter& protocol_writer = *stream;
    VlessBufferedReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = &protocol_writer;
    std::unique_ptr<::vless::VlessEncryptedIo> encrypted_io;

    if (auto ok = co_await SendVlessHandshake(
            *stream, *config_, encryption_tickets_ ? &tickets.local : nullptr, target,
            is_udp, use_vision, use_xudp, use_packet_addr,
            timeouts.HandshakeTimeout(), protocol_reader, protocol_writer,
            encrypted_io, active_reader, active_writer, dialer, ctx); !ok) {
        co_return fail_abortive(ok.error());
    }
    co_await tickets.Publish();
    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    if (use_xudp) {
        VlessMuxUdpEndpoint target_endpoint(
            *stream,
            *active_reader,
            *active_writer,
            target,
            dialer.ForwardedMetadata(ctx));
        auto res = co_await DoRelayLink(
            dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
            target_endpoint, ctx, stats, relay_config, std::move(first_payload));
        if (encrypted_io && !res) {
            encrypted_io->reader.ClearDeferredTicket();
        }
        co_return res;
    }

    VlessOutboundEndpoint target_endpoint(
        *stream,
        *active_reader,
        *active_writer,
        is_udp,
        target,
        use_packet_addr,
        use_vision,
        config_->uuid_bytes);
    auto res = co_await DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        target_endpoint, ctx, stats, relay_config, std::move(first_payload));
    if (encrypted_io && !res) {
        encrypted_io->reader.ClearDeferredTicket();
    }
    co_return res;
}


namespace {
const bool kVlessRegistered = (::proxyman::outbound::RegisterProxy(
    ::constants::protocol::kVless,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::proxyman::outbound::PreparedOutboundProxy> {
        // A present field of the wrong type is a configuration error, never
        // an implicit default.
        bool invalid_field = false;
        auto json_string = [&](const ::json::object& obj,
                               std::string_view key) -> std::string {
            auto parsed = ::ParseJsonString(obj, key);
            if (!parsed) {
                LOG_ERROR("VLESS outbound '{}': {}", cfg.tag, parsed.error());
                invalid_field = true;
                return {};
            }
            return std::move(*parsed).value_or(std::string{});
        };

        ::VlessOutboundConfig vless_config;
        std::string address;
        uint16_t port = 443;
        std::string uuid;
        std::string encryption;

        const auto& s = cfg.settings;
        std::string packet_encoding;
        if (const auto* vnext_p = s.if_contains("vnext");
                vnext_p && vnext_p->is_array() && !vnext_p->as_array().empty() &&
                vnext_p->as_array()[0].is_object()) {
            const auto& server = vnext_p->as_array()[0].as_object();
            address = json_string(server, "address");
            const auto source_port = ::ReadJsonPort(server, "port");
            if (source_port.Invalid()) {
                return std::nullopt;
            }
            if (source_port.Valid()) {
                port = source_port.value;
            }

            if (const auto* users_p = server.if_contains("users");
                    users_p && users_p->is_array() && !users_p->as_array().empty() &&
                    users_p->as_array()[0].is_object()) {
                const auto& user = users_p->as_array()[0].as_object();
                uuid = json_string(user, "id");
                if (uuid.empty()) {
                    uuid = json_string(user, "uuid");
                }
                encryption = json_string(user, "encryption");
                vless_config.flow = json_string(user, "flow");
                const std::string user_packet_encoding = json_string(user, "packetEncoding");
                if (!user_packet_encoding.empty()) {
                    packet_encoding = user_packet_encoding;
                }
            }
            if (encryption.empty()) {
                encryption = json_string(s, "encryption");
            }
        } else {
            address = json_string(s, "address");
            const auto source_port = ::ReadJsonPort(s, "port");
            if (source_port.Invalid()) {
                return std::nullopt;
            }
            if (source_port.Valid()) {
                port = source_port.value;
            }
            uuid = json_string(s, "id");
            encryption = json_string(s, "encryption");
            vless_config.flow = json_string(s, "flow");
            packet_encoding = json_string(s, "packetEncoding");
        }
        if (packet_encoding.empty()) {
            packet_encoding = json_string(s, "packetEncoding");
        }
        if (invalid_field) {
            return std::nullopt;
        }

        if (!::vless::IsNoVlessEncryption(encryption)) {
            auto parsed = ::vless::ParseVlessClientEncryption(
                encryption);
            if (!parsed) {
                LOG_WARN("VLESS outbound '{}': invalid encryption: {}",
                         cfg.tag,
                         ::vless::VlessEncryptionParseErrorMessage(
                             parsed.error));
                return std::nullopt;
            }
            vless_config.encryption = std::make_shared<const ::vless::VlessEncryptionConfig>(
                std::move(*parsed.config));
        }

        packet_encoding = ::naming::LowerAscii(std::move(packet_encoding));
        if (packet_encoding.empty() || packet_encoding == "xudp") {
            vless_config.packet_xudp = true;
            vless_config.packet_addr = false;
        } else if (packet_encoding == "none" || packet_encoding == "raw") {
            vless_config.packet_xudp = false;
            vless_config.packet_addr = false;
        } else if (packet_encoding == "packetaddr" ||
                   packet_encoding == "packet-addr" ||
                   packet_encoding == "packet") {
            vless_config.packet_xudp = false;
            vless_config.packet_addr = true;
        } else {
            LOG_WARN("VLESS outbound '{}': packet encoding '{}' is not supported",
                     cfg.tag, packet_encoding);
            return std::nullopt;
        }

        vless_config.flow = ::vless::NormalizeFlow(vless_config.flow);
        if (!vless_config.flow.empty() &&
            !::vless::IsVisionFlow(vless_config.flow)) {
            LOG_WARN("VLESS outbound '{}': flow '{}' is not supported",
                     cfg.tag, vless_config.flow);
            return std::nullopt;
        }

        const auto uuid_bytes = ::vless::ParseUuidBytes(uuid);
        if (!uuid_bytes) {
            LOG_ERROR("VLESS outbound '{}': invalid UUID", cfg.tag);
            return std::nullopt;
        }
        vless_config.uuid_bytes = *uuid_bytes;
        auto next_hop = ::proxy::PrepareNextHop(
            cfg, std::move(address), port, ::OutboundStreamDefaults{});
        if (!next_hop) {
            return std::nullopt;
        }
        const auto& stream_settings = next_hop->sender.stream_settings;
        if (!vless_config.flow.empty() &&
            (!(stream_settings.IsTlsLike() || vless_config.encryption != nullptr) ||
             stream_settings.network_mode != ::NetworkMode::Tcp)) {
            LOG_ERROR("VLESS outbound '{}': Vision requires TCP with TLS, Reality, or VLESS Encryption", cfg.tag);
            return std::nullopt;
        }
        vless_config.server = std::move(next_hop->server);
        const bool persistent_state = bool(vless_config.encryption);

        return ::proxyman::outbound::PreparedOutboundProxy{
            .create = ::proxyman::outbound::MakePreparedOutboundCreator<
                ::VlessOutboundConfig,
                +[](std::string_view,
                    std::shared_ptr<const ::VlessOutboundConfig> cfg_state,
                    ::net::io_context& /*io_context*/,
                    ::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::Outbound> {
                    return std::make_unique<::proxy::vless::outbound::Handler>(
                        std::move(cfg_state));
                }>(std::move(vless_config), persistent_state),
            .sender = std::move(next_hop->sender),
        };
    }), true);
}  // namespace
