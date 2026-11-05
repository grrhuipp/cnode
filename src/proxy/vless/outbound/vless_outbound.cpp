#include "vless_outbound.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"

#include "../vless_codec.hpp"
#include "../vless_encryption.hpp"
#include "../vless_encryption_io.hpp"
#include "../vless_encryption_runtime.hpp"
#include "../vless_buffered_reader.hpp"
#include "../udp_framing.hpp"
#include "../vless_vision.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "acppnode/infra/json_field.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/buf/length_prefixed_packet_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/mux/mux_codec.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/config_types.hpp"
#include "../credentials.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/link.hpp"

#include <array>
#include <cctype>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace acpp {

namespace {

using ::acpp::vless::VlessBufferedReader;
using ::acpp::vless::WriteVlessBytes;

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

class VlessOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    struct VisionIoState : memory::ThreadAllocated {
        ::acpp::vless::VisionTrafficState traffic;
        ::acpp::vless::VisionReader reader;
        ::acpp::vless::VisionWriter writer;

        VisionIoState(VlessBufferedReader& src,
                      transport::MultiBufferWriter& dst,
                      std::array<uint8_t, 16> user_uuid)
            : reader(src, user_uuid, traffic)
            , writer(dst, user_uuid, traffic) {}
    };
    struct UdpIoState : memory::ThreadAllocated {
        explicit UdpIoState(bool packet_addr) : framer(packet_addr) {}
        ::acpp::vless::UdpFramer framer;
    };

    VlessOutboundEndpoint(AsyncStream& control,
                          VlessBufferedReader& reader,
                          transport::MultiBufferWriter& writer,
                          bool is_udp,
                          const TargetAddress& udp_target,
                          bool packet_addr,
                          bool vision,
                          std::array<uint8_t, 16> user_uuid)
        : control_(control)
        , reader_(reader)
        , writer_(writer)
        , is_udp_(is_udp)
        , udp_target_(udp_target)
        , packet_addr_(packet_addr) {
        if (vision) {
            vision_io_ = std::make_unique<VisionIoState>(reader_, writer_, user_uuid);
        }
        if (is_udp_) {
            udp_io_ = std::make_unique<UdpIoState>(packet_addr);
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        co_await ReadVlessResponseHeader(
            reader_, response_header_, "VLESS response header read failed");
        if (is_udp_) {
            co_return co_await udp_io_->framer.ReadDatagram(reader_, udp_target_);
        }
        if (vision_io_) {
            co_return co_await vision_io_->reader.ReadMultiBuffer();
        }
        co_return co_await reader_.ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!is_udp_) {
            if (vision_io_) {
                co_await vision_io_->writer.WriteMultiBuffer(std::move(mb));
                co_return;
            }
            co_await writer_.WriteMultiBuffer(std::move(mb));
            co_return;
        }

        co_await ::acpp::vless::WriteUdpDatagram(
            writer_, std::move(mb), packet_addr_,
            packet_addr_ ? nullptr : &udp_target_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!is_udp_) {
            if (vision_io_) {
                co_await vision_io_->writer.WriteBuffers(buffers);
                co_return;
            }
            co_await writer_.WriteBuffers(buffers);
            co_return;
        }

        co_await ::acpp::vless::WriteUdpDatagram(
            writer_, udp_target_, packet_addr_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        co_await writer_.AsyncShutdownWrite();
    }

    bool ConsumeIdleTimeout() noexcept {
        return control_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return control_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return control_.ConsumeWriteTimeout();
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        return control_.StartPhaseDeadline(timeout);
    }

    void ClearPhaseDeadline() {
        control_.ClearPhaseDeadline();
    }

    bool ConsumePhaseDeadline() noexcept {
        return control_.ConsumePhaseDeadline();
    }

    void Cancel() noexcept {
        control_.Cancel();
    }

    transport::CancellationSource& Cancellation() noexcept override { return control_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : reader_.ReadEofAction();
    }

private:
    AsyncStream& control_;
    VlessBufferedReader& reader_;
    transport::MultiBufferWriter& writer_;
    VlessResponseHeaderState response_header_;
    bool is_udp_ = false;
    const TargetAddress& udp_target_;
    bool packet_addr_ = false;
    std::unique_ptr<VisionIoState> vision_io_;
    std::unique_ptr<UdpIoState> udp_io_;
};


class VlessMuxUdpEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    VlessMuxUdpEndpoint(AsyncStream& control,
                        VlessBufferedReader& reader,
                        transport::MultiBufferWriter& writer,
                        const TargetAddress& udp_target)
        : control_(control)
        , reader_(reader)
        , writer_(writer)
        , udp_target_(udp_target) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        co_await ReadVlessResponseHeader(
            reader_, response_header_, "VLESS mux response header read failed");

        while (true) {
            auto header = mux::DecodeFrame(pending_);
            if (header) {
                if (header->frame_size == 0) {
                    throw IoSystemError(
                        io_error::invalid_argument, "invalid VLESS mux response frame");
                }
                (void)pending_.DropPrefixBytes(header->frame_size - header->data_len);
                buf::MultiBuffer payload;
                if (!pending_.MovePrefixTo(payload, header->data_len)) {
                    throw std::bad_alloc();
                }
                pending_.ReleaseIfIdle();
                if (header->status == mux::SessionStatus::KEEPALIVE) continue;
                if (header->session_id != session_id_) {
                    throw IoSystemError(
                        io_error::connection_reset,
                        "VLESS mux response session id mismatch");
                }
                if (header->status == mux::SessionStatus::END) {
                    co_return buf::MultiBuffer{};
                }
                if (payload.byte_size() == 0) continue;
                const TargetAddress& src = header->has_target
                    ? header->target
                    : udp_target_;
                for (buf::Buffer* buffer : payload) {
                    if (buffer && !buffer->IsEmpty()) buffer->SetUDP(src);
                }
                co_return payload;
            }

            buf::MultiBuffer raw = co_await reader_.ReadMultiBuffer();
            if (raw.byte_size() == 0) {
                if (pending_.byte_size() != 0) {
                    throw IoSystemError(
                        io_error::invalid_argument, "truncated VLESS mux response frame");
                }
                co_return buf::MultiBuffer{};
            }
            buf::AppendPacketStreamInput(pending_, std::move(raw));
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        const TargetAddress* target = nullptr;
        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> payload;
        for (const buf::Buffer* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const TargetAddress& buffer_target = buffer->HasUDP()
                ? buffer->UDP()
                : udp_target_;
            if (!target) {
                target = std::addressof(buffer_target);
            } else if (!target->SameEndpoint(buffer_target)) {
                throw IoSystemError(
                    io_error::invalid_argument,
                    "VLESS mux datagram contains mixed targets");
            }
            const auto bytes = buffer->Bytes();
            payload.Append(net::const_buffer(bytes.data(), bytes.size()));
        }
        if (!target || payload.empty()) {
            mb.clear();
            co_return;
        }

        co_await WriteDatagram(*target, payload.Span());
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        co_await WriteDatagram(udp_target_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (session_started_ && !end_sent_) {
            mux::EncodeEndTo(write_frame_, session_id_);
            co_await WriteVlessBytes(writer_, write_frame_);
            end_sent_ = true;
        }
        co_await writer_.AsyncShutdownWrite();
    }

    bool ConsumeIdleTimeout() noexcept {
        return control_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return control_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return control_.ConsumeWriteTimeout();
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        return control_.StartPhaseDeadline(timeout);
    }

    void ClearPhaseDeadline() {
        control_.ClearPhaseDeadline();
    }

    bool ConsumePhaseDeadline() noexcept {
        return control_.ConsumePhaseDeadline();
    }

    void Cancel() noexcept {
        control_.Cancel();
    }

    transport::CancellationSource& Cancellation() noexcept override { return control_.Cancellation(); }

private:
    net::awaitable<void> WriteDatagram(
        const TargetAddress& target,
        std::span<const net::const_buffer> payload) {
        size_t payload_size = 0;
        for (const auto& buffer : payload) {
            if (buffer.size() >
                std::numeric_limits<uint16_t>::max() - payload_size) {
                throw IoSystemError(
                    io_error::message_size,
                    "VLESS mux datagram exceeds wire length");
            }
            payload_size += buffer.size();
        }
        if (payload_size == 0) {
            co_return;
        }

        const bool encoded = !session_started_
            ? mux::EncodeNewHeaderTo(
                  write_frame_, session_id_, mux::NetworkType::UDP,
                  target, payload_size)
            : mux::EncodeKeepUDPHeaderTo(
                  write_frame_, session_id_, target, payload_size);
        if (!encoded || write_frame_.empty()) {
            throw IoSystemError(
                io_error::connection_reset,
                "VLESS mux request encode failed");
        }

        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity + 1> frame;
        frame.Append(net::const_buffer(write_frame_.data(), write_frame_.size()));
        frame.AppendBuffers(payload);
        co_await writer_.WriteBuffers(frame.Span());
        session_started_ = true;
    }

    AsyncStream& control_;
    VlessBufferedReader& reader_;
    transport::MultiBufferWriter& writer_;
    const TargetAddress& udp_target_;
    VlessResponseHeaderState response_header_;
    bool session_started_ = false;
    bool end_sent_ = false;
    uint16_t session_id_ = 1;
    buf::MultiBuffer pending_;
    memory::ByteVector write_frame_;
};

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
DialOutboundStream(
    net::io_context& io_context,
    app::dns::DNS& dns_service,
    const VlessOutboundConfig& config,
    const TransportSecurity& security,
    std::chrono::seconds dial_timeout,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx) {
    auto transport_target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
        .dns_service = &dns_service,
        .address = config.address,
        .literal_address = config.literal_address,
        .port = config.port,
        .stream_settings = &config.stream_settings,
        .security = &security,
        .timeout = dial_timeout,
        .send_through = &config.send_through,
        .inbound_local_addr = inbound_local_addr,
        .inbound_source_ip = ctx.inbound.source_ip,
        .inbound_source_port = ctx.inbound.source_port,
        .tls_server_name = ResolveOutboundTlsServerName(
            config.stream_settings, config.address),
        .ws_host = config.address,
    });
    if (!transport_target) {
        if (transport_target.error() == ErrorCode::DNS_RESOLVE_FAILED) {
            LOG_CONN_WARN(ctx, "DNS resolve failed for {}", config.address);
        }
        co_return tl::unexpected(transport_target.error());
    }
    auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
    if (!dial_result.Ok()) {
        if (dial_result.error != ErrorCode::CANCELLED &&
            dial_result.error != ErrorCode::CONNECTION_CLOSED &&
            dial_result.error != ErrorCode::SOCKET_EOF) {
            LOG_CONN_WARN(ctx, "dial failed {} -> {} > {}",
                          ctx.inbound.source_ip, ctx.outbound.target, dial_result.error_msg);
        }
        co_return tl::unexpected(dial_result.error);
    }
    auto stream = std::move(dial_result.stream);
    if (auto local_ep = stream->LocalEndpoint();
        local_ep && !local_ep->address().is_unspecified()) {
        ctx.outbound.connected_local_addr = local_ep->address();
    }
    LOG_ACCESS(FormatAccessLog(ctx));
    co_return std::move(stream);
}

net::awaitable<tl::expected<void, ErrorCode>>
SendVlessHandshake(
    AsyncStream& stream,
    const VlessOutboundConfig& config,
    ::acpp::vless::VlessEncryptionClientTicketCache* encryption_tickets,
    const TargetAddress& target,
    bool is_udp,
    bool use_vision,
    bool use_xudp,
    bool use_packet_addr,
    std::chrono::seconds handshake_timeout,
    VlessBufferedReader& protocol_reader,
    transport::MultiBufferWriter& protocol_writer,
    std::unique_ptr<::acpp::vless::VlessEncryptedIo>& encrypted_io,
    VlessBufferedReader*& active_reader,
    transport::MultiBufferWriter*& active_writer) {
    stream.SetIdleTimeout(handshake_timeout);
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream.StartPhaseDeadline(handshake_timeout);

    if (config.encryption) {
        try {
            auto runtime =
                co_await ::acpp::vless::RunVlessEncryptionClientHandshake(
                    protocol_reader,
                    protocol_writer,
                    *config.encryption,
                    encryption_tickets);
            if (!runtime) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            encrypted_io = std::make_unique<::acpp::vless::VlessEncryptedIo>(
                protocol_reader, protocol_writer, std::move(*runtime));
            active_reader = &encrypted_io->plain_reader;
            active_writer = &encrypted_io->writer;
        } catch (const IoSystemError&) {
            co_return tl::unexpected(outbound_protocol_deadline.Expired()
                ? ErrorCode::TIMEOUT
                : ErrorCode::SOCKET_READ_FAILED);
        } catch (...) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }

    std::array<uint8_t, ::acpp::vless::kMaxRequestHeaderSize> header_buf{};
    const TargetAddress packet_magic_target = use_packet_addr
        ? TargetAddress(::acpp::vless::kPacketAddrMagicAddress, 0)
        : TargetAddress{};
    const TargetAddress& request_target = use_packet_addr ? packet_magic_target : target;
    const size_t header_len = ::acpp::vless::EncodeRequestHeaderTo(
        config.uuid_bytes,
        use_xudp
            ? ::acpp::vless::Command::MUX
            : (is_udp ? ::acpp::vless::Command::UDP : ::acpp::vless::Command::TCP),
        request_target,
        header_buf.data(),
        header_buf.size(),
        use_vision ? std::string_view(config.flow) : std::string_view{});
    if (header_len == 0) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    try {
        co_await WriteVlessBytes(
            *active_writer, std::span<const uint8_t>(header_buf.data(), header_len));
    } catch (...) {
        co_return tl::unexpected(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT : ErrorCode::SOCKET_WRITE_FAILED);
    }
    co_return tl::expected<void, ErrorCode>{};
}

}  // namespace

proxy::vless::outbound::Handler::Handler(
    std::string_view tag, std::shared_ptr<const VlessOutboundConfig> config,
    ::acpp::app::dns::DNS& dns_service, std::chrono::seconds dial_timeout)
    : tag_(tag), config_(std::move(config)),
      security_(config_->stream_settings, StreamEndpointRole::Outbound),
      dial_timeout_(dial_timeout), dns_service_(dns_service)
    , encryption_tickets_(config_->encryption
          ? std::make_unique<::acpp::vless::VlessEncryptionClientTicketCache>()
          : nullptr) {}

proxy::vless::outbound::Handler::~Handler() = default;

net::awaitable<OutboundProcessResult>
proxy::vless::outbound::Handler::Process(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    transport::Link inbound,
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
    auto dialed = co_await DialOutboundStream(
        io_context, dns_service_, *config_, security_, dial_timeout_,
        inbound_local_addr, ctx);
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
    VlessBufferedReader protocol_reader(*stream);
    transport::MultiBufferWriter& protocol_writer = *stream;
    VlessBufferedReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = &protocol_writer;
    std::unique_ptr<::acpp::vless::VlessEncryptedIo> encrypted_io;

    if (auto ok = co_await SendVlessHandshake(
            *stream, *config_, encryption_tickets_.get(), target,
            is_udp, use_vision, use_xudp, use_packet_addr,
            timeouts.HandshakeTimeout(), protocol_reader, protocol_writer,
            encrypted_io, active_reader, active_writer); !ok) {
        co_return fail_abortive(ok.error());
    }
    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    if (use_xudp) {
        VlessMuxUdpEndpoint target_endpoint(
            *stream,
            *active_reader,
            *active_writer,
            target);
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer, inbound.control,
            target_endpoint, ctx, stats, relay_config, std::move(first_payload));
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
    co_return co_await DoRelayLink(
        io_context, *inbound.reader, *inbound.writer, inbound.control,
        target_endpoint, ctx, stats, relay_config, std::move(first_payload));
}

}  // namespace acpp

namespace {
const bool kVlessRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kVless,
    [](const acpp::infra::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        // A present field of the wrong type is a configuration error, never
        // an implicit default.
        bool invalid_field = false;
        auto json_string = [&](const acpp::json::object& obj,
                               std::string_view key) -> std::string {
            auto parsed = acpp::ParseJsonString(obj, key);
            if (!parsed) {
                LOG_ERROR("VLESS outbound '{}': {}", cfg.tag, parsed.error());
                invalid_field = true;
                return {};
            }
            return std::move(*parsed).value_or(std::string{});
        };

        acpp::VlessOutboundConfig vless_config;
        std::string uuid;
        std::string encryption;

        const auto& s = cfg.settings;
        std::string packet_encoding;
        if (const auto* vnext_p = s.if_contains("vnext");
                vnext_p && vnext_p->is_array() && !vnext_p->as_array().empty() &&
                vnext_p->as_array()[0].is_object()) {
            const auto& server = vnext_p->as_array()[0].as_object();
            vless_config.address = json_string(server, "address");
            const auto port = acpp::ReadJsonPort(server, "port");
            if (port.Invalid()) {
                return std::nullopt;
            }
            if (port.Valid()) {
                vless_config.port = port.value;
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
            vless_config.address = json_string(s, "address");
            const auto port = acpp::ReadJsonPort(s, "port");
            if (port.Invalid()) {
                return std::nullopt;
            }
            if (port.Valid()) {
                vless_config.port = port.value;
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

        if (!acpp::vless::IsNoVlessEncryption(encryption)) {
            auto parsed = acpp::vless::ParseVlessClientEncryption(
                encryption);
            if (!parsed) {
                LOG_WARN("VLESS outbound '{}': invalid encryption: {}",
                         cfg.tag,
                         acpp::vless::VlessEncryptionParseErrorMessage(
                             parsed.error));
                return std::nullopt;
            }
            vless_config.encryption = std::make_shared<const acpp::vless::VlessEncryptionConfig>(
                std::move(*parsed.config));
        }

        packet_encoding = acpp::naming::LowerAscii(std::move(packet_encoding));
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

        vless_config.flow = acpp::vless::NormalizeFlow(vless_config.flow);
        if (!vless_config.flow.empty() &&
            !acpp::vless::IsVisionFlow(vless_config.flow)) {
            LOG_WARN("VLESS outbound '{}': flow '{}' is not supported",
                     cfg.tag, vless_config.flow);
            return std::nullopt;
        }

        vless_config.send_through = cfg.send_through.value_or(acpp::OutboundBind{});
        vless_config.stream_settings = acpp::NormalizeOutboundStreamSettings(
            cfg.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = false,
                .fallback_server_name = vless_config.address,
                .allow_insecure = false,
                .alpn = {},
            });

        const auto uuid_bytes = acpp::vless::ParseUuidBytes(uuid);
        if (vless_config.address.empty() || vless_config.port == 0 || !uuid_bytes) {
            return std::nullopt;
        }
        vless_config.uuid_bytes = *uuid_bytes;
        vless_config.literal_address = acpp::iputil::ParseLiteral(vless_config.address);
        if (!vless_config.literal_address && !acpp::domain::IsValidDnsHostname(
                vless_config.address, acpp::domain::TrailingDotPolicy::Allow)) {
            LOG_ERROR("vless outbound '{}': address must be an IP literal or DNS hostname", cfg.tag);
            return std::nullopt;
        }
        if (!vless_config.flow.empty() &&
            (!vless_config.stream_settings.IsTlsLike() ||
             vless_config.stream_settings.network_mode != acpp::NetworkMode::Tcp)) {
            LOG_ERROR("VLESS outbound '{}': Vision requires TCP with TLS or Reality", cfg.tag);
            return std::nullopt;
        }
        acpp::TransportSecurity::Prepare(
            vless_config.stream_settings, acpp::StreamEndpointRole::Outbound);
        const bool persistent_state = bool(vless_config.encryption);

        return acpp::proxyman::outbound::MakePreparedOutboundCreator<
            acpp::VlessOutboundConfig,
            +[](std::string_view tag,
                std::shared_ptr<const acpp::VlessOutboundConfig> cfg_state,
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                std::chrono::seconds timeout,
                acpp::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<acpp::proxy::vless::outbound::Handler>(
                    tag, std::move(cfg_state), dns, timeout);
            }>(std::move(vless_config), persistent_state);
    }), true);
}  // namespace
