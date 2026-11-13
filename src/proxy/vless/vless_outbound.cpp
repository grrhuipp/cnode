#include "common/domain_name.hpp"
#include "proxy/outbound_endpoint_base.hpp"
#include "common/ip_address.hpp"
#include <openssl/mem.h>
#include "proxy/outbound.hpp"
#include "proxy/vless/vless_codec.hpp"
#include "proxy/vless/vless_encryption.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/outbound_stream_endpoint.hpp"
#include "app/dns/dns.hpp"
#include "app/proxyman/outbound_handler.hpp"
#include "app/relay.hpp"
#include "common/const_buffer_span.hpp"
#include "common/asio_types.hpp"
#include "common/multi_buffer.hpp"
#include "common/length_prefixed_packet_buffer.hpp"
#include "common/error.hpp"
#include "common/mux_codec.hpp"
#include "proxy/udp_datagram_frame.hpp"
#include "common/session.hpp"
#include "common/constants.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "transport/async_stream.hpp"
#include "transport/outbound_target_builder.hpp"
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

#include <chrono>
#include <cstdint>

namespace proxy {

struct VlessOutboundConfig {
    transport::OutboundServer server;
    std::array<uint8_t, 16> uuid_bytes{};
    std::shared_ptr<const proxy::VlessEncryptionConfig> encryption;
    std::string flow;
    bool packet_xudp = true;
    bool packet_addr = false;

    VlessOutboundConfig() = default;
    VlessOutboundConfig(const VlessOutboundConfig&) = default;
    VlessOutboundConfig& operator=(const VlessOutboundConfig&) = default;
    VlessOutboundConfig(VlessOutboundConfig&&) noexcept = default;
    VlessOutboundConfig& operator=(VlessOutboundConfig&&) noexcept = default;
    ~VlessOutboundConfig() noexcept {
        OPENSSL_cleanse(uuid_bytes.data(), uuid_bytes.size());
    }
};

class VlessOutboundHandler final : public ::proxy::Outbound {
public:
    explicit VlessOutboundHandler(std::shared_ptr<const ::proxy::VlessOutboundConfig> config);

    ~VlessOutboundHandler() override;

    ::net::awaitable<::proxy::OutboundProcessResult> Process(
        ::common::Context& ctx,
        ::transport::Link inbound,
        ::transport::OutboundDialer& dialer,
        const ::infra::TimeoutsConfig& timeouts,
        ::app::StatsShard& stats,
        const ::app::RelayConfig& relay_config,
        ::common::MultiBufferBatch first_payload) override;

private:
    std::shared_ptr<const ::proxy::VlessOutboundConfig> config_;
    std::shared_ptr<::proxy::VlessEncryptionClientTicketCache> encryption_tickets_;
};

namespace {
// Version, addons length, then addons this client ignores. Progress lives in
// the endpoint so a cancelled read resumes at the same stream offset.
struct VlessResponseHeaderState {
    std::array<uint8_t, 2> fixed{};
    size_t fixed_read = 0;
    size_t addons_read = 0;
    bool complete = false;
};

net::awaitable<void> ReadVlessResponseHeader(proxy::BufferedStreamReader& reader,
                                             VlessResponseHeaderState& state,
                                             const char* failure) {
    if (state.complete) {
        co_return;
    }
    if (!co_await reader.ReadExact(
            state.fixed.data(), state.fixed.size(), &state.fixed_read) ||
        state.fixed[0] != proxy::kVlessVersion) {
        throw IoSystemError(io_error::connection_reset, failure);
    }
    if (state.fixed[1] != 0 &&
        !co_await reader.DiscardExact(state.fixed[1], &state.addons_read)) {
        throw IoSystemError(io_error::connection_reset, failure);
    }
    state.complete = true;
}

class VlessOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    struct VisionIoState {
        ::proxy::VisionTrafficState traffic;
        ::proxy::VisionReader reader;
        ::proxy::VisionWriter writer;

        VisionIoState(proxy::BufferedStreamReader& src,
                      transport::MultiBufferWriter& dst,
                      std::array<uint8_t, 16> user_uuid)
            : reader(src, user_uuid, traffic)
            , writer(dst, user_uuid, traffic) {}
    };

    VlessOutboundEndpoint(transport::AsyncStream& control,
                          proxy::BufferedStreamReader& reader,
                          transport::MultiBufferWriter& writer,
                          bool is_udp,
                          const common::TargetAddress& udp_target,
                          bool packet_addr,
                          bool vision,
                          std::array<uint8_t, 16> user_uuid)
        : OutboundStreamEndpointBase(control)
        , reader_(reader)
        , writer_(writer)
        , is_udp_(is_udp)
        , udp_target_(udp_target)
        , packet_addr_(packet_addr) {
        if (is_udp_) {
            io_state_.emplace<::proxy::VlessUdpFramer>(packet_addr);
        } else if (vision) {
            io_state_.emplace<VisionIoState>(reader_, writer_, user_uuid);
        }
        OPENSSL_cleanse(user_uuid.data(), user_uuid.size());
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        if (!response_header_.complete) {
            return ReadInitialMultiBuffer();
        }
        if (auto* udp_framer = std::get_if<::proxy::VlessUdpFramer>(&io_state_)) {
            return udp_framer->ReadDatagram(reader_, udp_target_);
        }
        if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
            return vision_io->reader.ReadMultiBuffer();
        }
        return reader_.ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        if (!is_udp_) {
            if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
                return vision_io->writer.WriteMultiBuffer(std::move(mb));
            }
            return writer_.WriteMultiBuffer(std::move(mb));
        }

        return ::proxy::WriteVlessUdpDatagram(
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

        return ::proxy::WriteVlessUdpDatagram(
            writer_, udp_target_, packet_addr_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return writer_.AsyncShutdownWrite();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : reader_.ReadEofAction();
    }

private:
    net::awaitable<common::MultiBuffer> ReadInitialMultiBuffer() {
        co_await ReadVlessResponseHeader(
            reader_, response_header_, "VLESS response header read failed");
        if (auto* udp_framer = std::get_if<::proxy::VlessUdpFramer>(&io_state_)) {
            co_return co_await udp_framer->ReadDatagram(reader_, udp_target_);
        }
        if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
            co_return co_await vision_io->reader.ReadMultiBuffer();
        }
        co_return co_await reader_.ReadMultiBuffer();
    }

    proxy::BufferedStreamReader& reader_;
    transport::MultiBufferWriter& writer_;
    VlessResponseHeaderState response_header_;
    bool is_udp_ = false;
    const common::TargetAddress& udp_target_;
    bool packet_addr_ = false;
    std::variant<std::monostate, VisionIoState, ::proxy::VlessUdpFramer> io_state_;
};


class VlessMuxUdpEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    VlessMuxUdpEndpoint(transport::AsyncStream& control,
                        proxy::BufferedStreamReader& reader,
                        transport::MultiBufferWriter& writer,
                        const common::TargetAddress& udp_target,
                        common::ForwardedMetadataView forwarded) noexcept
        : OutboundStreamEndpointBase(control)
        , reader_(reader)
        , writer_(writer)
        , udp_target_(udp_target)
        , forwarded_(forwarded) {}

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        if (read_failed_) {
            throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        if (peer_ended_) {
            co_return common::MultiBuffer{};
        }
        if (!response_header_.complete) {
            co_await ReadVlessResponseHeader(
                reader_, response_header_, "VLESS mux response header read failed");
        }

        while (true) {
            auto header = common::DecodeFrame(pending_);
            if (header) {
                if (header->frame_size == 0) {
                    throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (header->status == common::SessionStatus::KEEPALIVE) {
                    (void)pending_.DropPrefixBytes(header->frame_size);
                    pending_.ReleaseIfIdle();
                    continue;
                }
                if (header->status == common::SessionStatus::NEW) {
                    throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (header->session_id != session_id_) {
                    throw IoSystemError(
                        io_error::connection_reset,
                        "VLESS mux response session id mismatch");
                }
                if ((header->option & common::kOptionError) != 0) {
                    throw IoSystemError(
                        io_error::connection_reset,
                        "VLESS mux response error frame");
                }
                if (header->has_target && header->network != common::NetworkType::UDP) {
                    throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                common::MultiBuffer payload;
                if (header->data_len == 0) {
                    (void)pending_.DropPrefixBytes(header->frame_size);
                } else {
                    (void)pending_.DropPrefixBytes(header->frame_size - header->data_len);
                    if (!pending_.MovePrefixTo(payload, header->data_len)) {
                        throw std::bad_alloc();
                    }
                }
                pending_.ReleaseIfIdle();
                if (header->status == common::SessionStatus::END) {
                    peer_ended_ = true;
                    pending_.clear();
                    if (!header->has_data) {
                        co_return common::MultiBuffer{};
                    }
                }
                if (!header->has_data) continue;
                const common::TargetAddress& src = header->has_target
                    ? header->target
                    : udp_target_;
                if (!common::SetUdpTarget(payload, src)) {
                    throw std::bad_alloc();
                }
                co_return payload;
            }

            common::MultiBuffer raw = co_await reader_.ReadMultiBuffer();
            if (raw.byte_size() == 0) {
                co_await common::ThrowIfCancelledOnEof();
                if (pending_.byte_size() != 0) {
                    throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                co_return common::MultiBuffer{};
            }
            try {
                if (!common::AppendPacketStreamInput(pending_, std::move(raw))) {
                    throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                }
            } catch (...) {
                pending_.clear();
                read_failed_ = true;
                throw;
            }
        }
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        const auto datagram = proxy::RequireUdpDatagram(mb, &udp_target_);
        if (!datagram) co_return;
        common::ConstBufferSpanBuilder<1> payload;
        payload.AppendMultiBuffer(mb);
        co_await WriteDatagram(*datagram->target, payload.Span());
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return WriteDatagram(udp_target_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (session_started_ && !end_sent_) {
            std::array<uint8_t, 6> write_frame{};
            const size_t header_len = common::EncodeEndTo(write_frame, session_id_);
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
        const common::TargetAddress& target,
        std::span<const net::const_buffer> payload) {
        const auto payload_size = proxy::RequireUdpPayloadSize(payload);

        std::array<uint8_t, common::kMaxFrameHeaderBytes> write_frame{};
        const size_t header_len = !session_started_
            ? common::EncodeNewHeaderTo(
                  write_frame, session_id_, common::NetworkType::UDP,
                  target, payload_size, true, forwarded_)
            : common::EncodeKeepUDPHeaderTo(
                  write_frame, session_id_, target, payload_size);
        if (header_len == 0) {
            throw IoSystemError(
                io_error::connection_reset,
                "VLESS mux request encode failed");
        }

        co_await proxy::WriteFramedDatagram(
            writer_, std::span(write_frame).first(header_len), payload);
        session_started_ = true;
        forwarded_ = {};
    }

    proxy::BufferedStreamReader& reader_;
    transport::MultiBufferWriter& writer_;
    const common::TargetAddress& udp_target_;
    common::ForwardedMetadataView forwarded_;
    VlessResponseHeaderState response_header_;
    bool session_started_ = false;
    bool end_sent_ = false;
    bool peer_ended_ = false;
    bool read_failed_ = false;
    uint16_t session_id_ = 1;
    common::MultiBuffer pending_;
};

// 稳态只保留拒绝信号和身份；完整 PFS 快照仅属于握手子协程。
// 此对象先于 encrypted_io 构造，且禁止移动，保证延迟读端的借用有效。
struct VlessClientTicketLease {
    explicit VlessClientTicketLease(
        std::shared_ptr<::proxy::VlessEncryptionClientTicketCache> cache)
        : cache(std::move(cache)) {}

    VlessClientTicketLease(const VlessClientTicketLease&) = delete;
    VlessClientTicketLease& operator=(const VlessClientTicketLease&) = delete;
    VlessClientTicketLease(VlessClientTicketLease&&) = delete;
    VlessClientTicketLease& operator=(VlessClientTicketLease&&) = delete;

    void Acquire(::proxy::VlessEncryptionClientTicketCache& local) {
        if (!cache) return;
        local = *cache;
        identity = local.ticket;
    }

    void Publish(
        const ::proxy::VlessEncryptionClientTicketCache& local,
        std::chrono::steady_clock::time_point original_expiry) {
        if (!cache ||
            (CRYPTO_memcmp(local.ticket.data(), identity.data(), identity.size()) == 0 &&
             local.expires_at == original_expiry)) return;
        if (CRYPTO_memcmp(cache->ticket.data(), identity.data(), identity.size()) == 0) {
            *cache = local;
        }
        identity = local.ticket;
    }

    ~VlessClientTicketLease() {
        if (!cache || !rejection.rejected) return;
        if (CRYPTO_memcmp(cache->ticket.data(), identity.data(), identity.size()) == 0) {
            cache->Clear();
        }
    }

    std::shared_ptr<::proxy::VlessEncryptionClientTicketCache> cache;
    std::array<uint8_t, ::proxy::kVlessEncryptionTicketSize> identity{};
    ::proxy::VlessEncryptionTicketRejection rejection;
};

net::awaitable<tl::expected<::proxy::VlessActiveIo, common::ErrorCode>>
SendVlessHandshake(
    transport::AsyncStream& stream,
    const VlessOutboundConfig& config,
    VlessClientTicketLease& tickets,
    const common::TargetAddress& target,
    bool is_udp,
    bool use_vision,
    bool use_xudp,
    bool use_packet_addr,
    std::chrono::seconds handshake_timeout,
    proxy::BufferedStreamReader& protocol_reader,
    transport::MultiBufferWriter& protocol_writer,
    std::optional<::proxy::VlessEncryptedIo>& encrypted_io,
    const transport::OutboundDialer& dialer,
    const common::Context& ctx) {
    auto* active_reader = &protocol_reader;
    auto* active_writer = &protocol_writer;
    ::proxy::VlessEncryptionClientTicketCache local_tickets;
    tickets.Acquire(local_tickets);
    const auto original_expiry = local_tickets.expires_at;
    stream.SetIdleTimeout(handshake_timeout);
    transport::PhaseDeadlineToken outbound_protocol_deadline =
        stream.StartPhaseDeadline(handshake_timeout);

    if (config.encryption) {
        try {
            auto runtime =
                co_await ::proxy::RunVlessEncryptionClientHandshake(
                    protocol_reader,
                    protocol_writer,
                    *config.encryption,
                    tickets.cache ? &local_tickets : nullptr,
                    tickets.rejection);
            tickets.rejection.rejected =
                local_tickets.expires_at == std::chrono::steady_clock::time_point{};
            if (!runtime) {
                if (proxy::ConsumeOutboundHandshakeTimeout(
                        stream, outbound_protocol_deadline)) {
                    co_return tl::unexpected(common::ErrorCode::TIMEOUT);
                }
                co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            encrypted_io.emplace(
                protocol_reader, protocol_writer, std::move(*runtime));
            active_reader = &encrypted_io->plain_reader;
            active_writer = &encrypted_io->writer;
        } catch (...) {
            tickets.rejection.rejected =
                local_tickets.expires_at == std::chrono::steady_clock::time_point{};
            co_return tl::unexpected(
                proxy::ClassifyOutboundHandshakeException(
                    stream,
                    outbound_protocol_deadline,
                    common::ErrorCode::PROTOCOL_DECODE_FAILED));
        }
    }

    std::array<uint8_t, ::proxy::kVlessMaxRequestHeaderSize> header_buf{};
    const common::TargetAddress packet_magic_target = use_packet_addr
        ? common::TargetAddress(::proxy::kPacketAddrMagicAddress, 0)
        : common::TargetAddress{};
    const common::TargetAddress& request_target = use_packet_addr ? packet_magic_target : target;
    const size_t header_len = ::proxy::EncodeRequestHeaderTo(
        config.uuid_bytes,
        use_xudp
            ? ::proxy::VlessCommand::MUX
            : (is_udp ? ::proxy::VlessCommand::UDP : ::proxy::VlessCommand::TCP),
        request_target,
        header_buf.data(),
        header_buf.size(),
        use_vision ? std::string_view(config.flow) : std::string_view{},
        dialer.ForwardedMetadata(ctx));
    if (header_len == 0) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    try {
        co_await WriteVlessBytes(
            *active_writer, std::span<const uint8_t>(header_buf.data(), header_len));
    } catch (...) {
        OPENSSL_cleanse(header_buf.data(), header_len);
        const common::ErrorCode classified = proxy::ClassifyOutboundHandshakeException(
            stream, outbound_protocol_deadline);
        if (encrypted_io && classified != common::ErrorCode::CANCELLED) {
            encrypted_io->reader.RejectDeferredTicket();
        }
        co_return tl::unexpected(classified);
    }
    OPENSSL_cleanse(header_buf.data(), header_len);
    tickets.Publish(local_tickets, original_expiry);
    co_return ::proxy::VlessActiveIo{active_reader, active_writer};
}

}  // namespace

VlessOutboundHandler::VlessOutboundHandler(
    std::shared_ptr<const VlessOutboundConfig> config)
    : config_(std::move(config))
    , encryption_tickets_(config_->encryption
          ? std::make_shared<::proxy::VlessEncryptionClientTicketCache>()
          : nullptr) {}

VlessOutboundHandler::~VlessOutboundHandler() = default;

net::awaitable<OutboundProcessResult>
VlessOutboundHandler::Process(
    common::Context& ctx,
    transport::Link inbound,
    transport::OutboundDialer& dialer,
    const infra::TimeoutsConfig& timeouts,
    app::StatsShard& stats,
    const app::RelayConfig& relay_config,
    common::MultiBufferBatch first_payload) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!config_->flow.empty() && ctx.content.network != common::Network::TCP) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const auto& target = ctx.outbound.target;
    auto dialed = co_await dialer.Dial(ctx, config_->server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);

    auto fail_abortive = [&](common::ErrorCode error) {
        if (stream) {
            stream->CloseAbortive();
        }
        return tl::unexpected(error);
    };

    const bool is_udp = ctx.content.network == common::Network::UDP;
    const bool use_vision = !config_->flow.empty();
    const bool use_xudp = is_udp && config_->packet_xudp;
    const bool use_packet_addr = is_udp && config_->packet_addr;
    VlessClientTicketLease tickets(encryption_tickets_);
    proxy::BufferedStreamReader protocol_reader(*stream);
    transport::MultiBufferWriter& protocol_writer = *stream;
    proxy::BufferedStreamReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = &protocol_writer;
    std::optional<::proxy::VlessEncryptedIo> encrypted_io;

    auto handshake = co_await SendVlessHandshake(
            *stream, *config_, tickets, target,
            is_udp, use_vision, use_xudp, use_packet_addr,
            timeouts.HandshakeTimeout(), protocol_reader, protocol_writer,
            encrypted_io, dialer, ctx);
    if (!handshake) co_return fail_abortive(handshake.error());
    active_reader = handshake->reader;
    active_writer = handshake->writer;
    proxy::ApplyOutboundRelayTimeouts(*stream, relay_config);

    if (use_xudp) {
        VlessMuxUdpEndpoint target_endpoint(
            *stream,
            *active_reader,
            *active_writer,
            target,
            dialer.ForwardedMetadata(ctx));
        auto res = co_await app::DoRelayLink(
            dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
            target_endpoint, ctx, stats, relay_config, std::move(first_payload));
        if (encrypted_io && !res.Ok()) {
            encrypted_io->reader.RejectDeferredTicket();
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
    auto res = co_await app::DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        target_endpoint, ctx, stats, relay_config, std::move(first_payload));
    if (encrypted_io && !res.Ok()) {
        encrypted_io->reader.RejectDeferredTicket();
    }
    co_return res;
}


namespace {
const bool kVlessRegistered = (::app::RegisterProxy(
    ::common::kVless,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::app::PreparedOutboundProxy> {
        const auto* settings = std::get_if<::infra::VlessSettings>(&cfg.settings);
        if (!settings) return std::nullopt;
        ::proxy::VlessOutboundConfig vless_config;
        vless_config.uuid_bytes = settings->id;
        vless_config.flow = settings->flow;
        vless_config.encryption = settings->encryption;
        vless_config.packet_xudp = settings->packet_encoding == ::infra::PacketEncoding::Xudp;
        vless_config.packet_addr = settings->packet_encoding == ::infra::PacketEncoding::PacketAddr;
        auto next_hop = ::proxy::PrepareNextHop(cfg, settings->server, ::transport::OutboundStreamDefaults{});
        const auto& stream_settings = next_hop.sender.stream_settings;
        if (!vless_config.flow.empty() &&
            (!(stream_settings.IsTlsLike() || vless_config.encryption != nullptr) ||
             stream_settings.network_mode != ::transport::NetworkMode::Tcp)) {
            LOG_ERROR("VLESS outbound '{}': Vision requires TCP with TLS, Reality, or VLESS Encryption", cfg.tag);
            return std::nullopt;
        }
        vless_config.server = std::move(next_hop.server);
        return ::app::PreparedOutboundProxy{
            .create = ::app::MakePreparedOutboundCreator<
                ::proxy::VlessOutboundConfig,
                +[](std::string_view,
                    std::shared_ptr<const ::proxy::VlessOutboundConfig> cfg_state,
                    ::net::io_context& /*io_context*/,
                    ::common::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::proxy::Outbound> {
                    return std::make_unique<::proxy::VlessOutboundHandler>(
                        std::move(cfg_state));
                }>(std::move(vless_config)),
            .sender = std::move(next_hop.sender),
        };
    }), true);
}  // namespace

}  // namespace proxy
