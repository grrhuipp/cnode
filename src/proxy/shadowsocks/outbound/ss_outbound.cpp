#include "ss_outbound.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"
#include "ss_outbound_uot.hpp"
#include "../client.hpp"
#include "../ss_udp.hpp"
#include "../../uot/uot.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "acppnode/infra/json_port.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/app/udp_channel.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/contiguous_buffer_view.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <span>
#include <utility>

namespace acpp {

namespace {

class ShadowsocksOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    ShadowsocksOutboundEndpoint(std::unique_ptr<transport::MultiBufferWriter> request_writer,
                                const ss::SsCipherInfo& cipher_info,
                                const ss::KeyBytes& master_key,
                                const ss::KeyBytes& request_salt,
                                AsyncStream& stream)
        : request_writer_(std::move(request_writer))
        , cipher_info_(cipher_info)
        , master_key_(master_key)
        , request_salt_(request_salt)
        , stream_(stream) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_reader_) {
            auto reader_result = co_await ss::ReadTCPResponse(
                cipher_info_, master_key_, request_salt_, stream_);
            if (!reader_result) {
                throw IoSystemError(
                    io_error::connection_reset,
                    "Shadowsocks response header failed");
            }
            response_reader_ = std::move(reader_result.value());
        }
        co_return co_await response_reader_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!request_writer_) {
            mb.clear();
            throw IoSystemError(
                io_error::not_connected,
                "Shadowsocks request writer is not initialized");
        }
        co_await request_writer_->WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!request_writer_) {
            throw IoSystemError(
                io_error::not_connected,
                "Shadowsocks request writer is not initialized");
        }
        co_await request_writer_->WriteBuffers(buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        co_await stream_.AsyncShutdownWrite();
    }

    void SetIdleTimeout(std::chrono::seconds timeout) {
        stream_.SetIdleTimeout(timeout);
    }

    void SetReadTimeout(std::chrono::seconds timeout) {
        stream_.SetReadTimeout(timeout);
    }

    void SetWriteTimeout(std::chrono::seconds timeout) {
        stream_.SetWriteTimeout(timeout);
    }

    bool ConsumeIdleTimeout() noexcept {
        return stream_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return stream_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return stream_.ConsumeWriteTimeout();
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        return stream_.StartPhaseDeadline(timeout);
    }

    void ClearPhaseDeadline() {
        stream_.ClearPhaseDeadline();
    }

    bool ConsumePhaseDeadline() noexcept {
        return stream_.ConsumePhaseDeadline();
    }

    void Cancel() noexcept {
        stream_.Cancel();
    }

    transport::CancellationSource& Cancellation() noexcept override { return stream_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return stream_.ReadEofAction(); }

    void SetAbortiveClose(bool enable = true) noexcept {
        stream_.SetAbortiveClose(enable);
    }

private:
    std::unique_ptr<transport::MultiBufferWriter> request_writer_;
    ss::SsCipherInfo cipher_info_;
    ss::KeyBytes master_key_;
    ss::KeyBytes request_salt_;
    AsyncStream& stream_;
    std::unique_ptr<transport::MultiBufferReader> response_reader_;
};

class ShadowsocksUdpOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    ShadowsocksUdpOutboundEndpoint(net::io_context& io_context,
                                  std::shared_ptr<UDPSession> session,
                                  TargetAddress server,
                                  const ss::SsCipherInfo& cipher_info,
                                  const ss::KeyBytes& master_key,
                                  std::span<const ss::KeyBytes> psk_chain)
        : channel_(io_context, std::move(session)), server_(std::move(server)),
          cipher_info_(cipher_info), master_key_(master_key), psk_chain_(psk_chain) {
        if (ss::Is2022Cipher(cipher_info_)) {
            ss2022_state_.emplace();
            if (!ss::Init2022UdpSessionState(*ss2022_state_, cipher_info_, master_key_)) {
                throw IoSystemError(io_error::fault, "Shadowsocks 2022 UDP session initialization failed");
            }
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (true) {
            auto packet = co_await channel_.ReadMultiBuffer();
            if (!buf::HasData(packet)) co_return buf::MultiBuffer{};
            const buf::ContiguousBufferView view(packet);
            const auto bytes = view.Bytes();
            auto decoded = ss2022_state_
                ? ss::Decode2022UdpResponsePacket(bytes.data(), bytes.size(), *ss2022_state_)
                : ss::DecodeUdpPacketWithKey(bytes.data(), bytes.size(), master_key_.span(),
                    cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size);
            if (!decoded || !buf::HasData(decoded->payload)) continue;
            for (auto* buffer : decoded->payload) buffer->SetUDP(decoded->target);
            co_return std::move(decoded->payload);
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
        const auto datagram = buf::InspectUdpDatagram(payload);
        if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
        if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid()) {
            throw IoSystemError(io_error::invalid_argument, "Shadowsocks UDP requires one datagram target");
        }
        const buf::ContiguousBufferView view(payload);
        const auto bytes = view.Bytes();
        const size_t encoded_len = EncodedPacketSize(*datagram.target, bytes);
        if (encoded_len == 0) {
            throw IoSystemError(io_error::message_size, "invalid Shadowsocks UDP datagram size or target");
        }
        buf::MultiBuffer packet;
        if (encoded_len <= buf::Buffer::kSize) {
            buf::BufferGuard encoded{buf::Buffer::New()};
            if (!encoded) throw std::bad_alloc();
            if (EncodePacketTo(*datagram.target, bytes, encoded->Tail().data(), encoded->Available()) != encoded_len) {
                throw IoSystemError(io_error::fault, "Shadowsocks UDP encoding failed");
            }
            encoded->Produce(static_cast<uint32_t>(encoded_len));
            packet.push_back(std::move(encoded));
        } else {
            memory::ByteVector scratch(encoded_len);
            if (EncodePacketTo(*datagram.target, bytes, scratch.data(), scratch.size()) != encoded_len) {
                throw IoSystemError(io_error::fault, "Shadowsocks UDP encoding failed");
            }
            if (!buf::AppendSpanToMultiBuffer(scratch, packet)) throw std::bad_alloc();
        }
        for (auto* buffer : packet) buffer->SetUDP(server_);
        co_await channel_.WriteMultiBuffer(std::move(packet));
    }

    net::awaitable<void> AsyncShutdownWrite() override { co_await channel_.AsyncShutdownWrite(); }
    bool ForwardHalfCloseOnPeerEof() const noexcept { return true; }
    void Cancel() noexcept { channel_.Cancel(); }
    transport::CancellationSource& Cancellation() noexcept override { return channel_.Cancellation(); }
    void SetIdleTimeout(std::chrono::seconds timeout) { channel_.SetIdleTimeout(timeout); }
    void SetReadTimeout(std::chrono::seconds timeout) { channel_.SetReadTimeout(timeout); }
    void SetWriteTimeout(std::chrono::seconds timeout) { channel_.SetWriteTimeout(timeout); }
    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) { return channel_.StartPhaseDeadline(timeout); }
    void ClearPhaseDeadline() { channel_.ClearPhaseDeadline(); }
    bool ConsumeIdleTimeout() noexcept { return channel_.ConsumeIdleTimeout(); }
    bool ConsumeReadTimeout() noexcept { return channel_.ConsumeReadTimeout(); }
    bool ConsumeWriteTimeout() noexcept { return channel_.ConsumeWriteTimeout(); }
    bool ConsumePhaseDeadline() noexcept { return channel_.ConsumePhaseDeadline(); }

private:
    [[nodiscard]] size_t EncodedPacketSize(
        const TargetAddress& target,
        std::span<const uint8_t> payload) {
        if (ss2022_state_) {
            return ss::Encode2022UdpRequestPacketTo(
                target,
                payload.data(),
                payload.size(),
                *ss2022_state_,
                psk_chain_,
                nullptr,
                0);
        }
        return ss::EncodeUdpPacketTo(
            target,
            payload.data(),
            payload.size(),
            master_key_.span(),
            cipher_info_.type,
            cipher_info_.key_size,
            cipher_info_.salt_size,
            nullptr,
            0);
    }

    [[nodiscard]] size_t EncodePacketTo(const TargetAddress& target,
                                        std::span<const uint8_t> payload,
                                        uint8_t* output,
                                        size_t output_size) {
        if (ss2022_state_) {
            return ss::Encode2022UdpRequestPacketTo(
                target,
                payload.data(),
                payload.size(),
                *ss2022_state_,
                psk_chain_,
                output,
                output_size);
        }
        return ss::EncodeUdpPacketTo(
            target,
            payload.data(),
            payload.size(),
            master_key_.span(),
            cipher_info_.type,
            cipher_info_.key_size,
            cipher_info_.salt_size,
            output,
            output_size);
    }

    UDPChannel channel_;
    const TargetAddress server_;
    const ss::SsCipherInfo cipher_info_;
    const ss::KeyBytes master_key_;
    const std::span<const ss::KeyBytes> psk_chain_;
    std::optional<ss::Ss2022UdpSessionState> ss2022_state_;
};

TargetAddress MakeServerTarget(const SsOutboundConfig& config) {
    if (config.literal_address) {
        return TargetAddress(*config.literal_address, config.port);
    }
    return TargetAddress(std::string_view(config.address.data(), config.address.size()),
                         config.port);
}

net::ip::address SelectUdpBindAddress(const SsOutboundConfig& config) {
    if (config.send_through.GetMode() == OutboundBind::Mode::Explicit) {
        return *config.send_through.ExplicitAddress();
    }
    return net::ip::address_v4::any();
}

}  // namespace

net::awaitable<OutboundProcessResult> proxy::shadowsocks::outbound::Handler::Process(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    transport::Link inbound,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBuffer first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const bool use_uot =
        ctx.content.network == Network::UDP && config_.uot_version.has_value();

    if (ctx.content.network == Network::UDP && !use_uot) {
        if (!udp_session_manager_) {
            LOG_CONN_WARN(ctx, "[SsOutbound] UDP session manager not available");
            co_return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
        }

        auto server = MakeServerTarget(config_);
        if (!server.IsValid()) {
            co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }

        const auto bind_addr = SelectUdpBindAddress(config_);
        char conn_id_buf[std::numeric_limits<decltype(ctx.conn_id)>::digits10 + 1]{};
        const auto [conn_id_end, conn_id_ec] =
            std::to_chars(conn_id_buf, conn_id_buf + sizeof(conn_id_buf), ctx.conn_id);
        if (conn_id_ec != std::errc{}) {
            co_return std::unexpected(ErrorCode::INTERNAL);
        }
        std::string session_id;
        session_id.reserve(
            std::string_view("ssudp--").size() + tag_.size() +
            static_cast<size_t>(conn_id_end - conn_id_buf));
        session_id.append("ssudp-");
        session_id.append(tag_);
        session_id.push_back('-');
        session_id.append(conn_id_buf, conn_id_end);
        auto udp_session_result = udp_session_manager_->AcquireSession(
            session_id, bind_addr);
        if (!udp_session_result) {
            LOG_CONN_WARN(
                ctx,
                "[SsOutbound] UDP session create failed via {}: {}",
                ctx.outbound.tag,
                ErrorCodeToString(udp_session_result.error()));
            co_return std::unexpected(udp_session_result.error());
        }
        std::shared_ptr<UDPSession> udp_session =
            std::move(*udp_session_result);

        ShadowsocksUdpOutboundEndpoint target_endpoint(
            io_context,
            std::move(udp_session),
            std::move(server),
            credentials_.Cipher(),
            credentials_.MasterKey(),
            credentials_.PskChain());
        target_endpoint.SetIdleTimeout(relay_idle_timeout);
        target_endpoint.SetWriteTimeout(relay_write_timeout);
        if (inbound.control) {
            co_return co_await DoRelayLink(
                io_context, *inbound.reader, *inbound.writer, *inbound.control,
                target_endpoint, ctx, stats, relay_config);
        }
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer,
            target_endpoint, ctx, stats, relay_config);
    }

    const TargetAddress protocol_target = use_uot
        ? TargetAddress(
            *config_.uot_version == SsUotVersion::V1
                ? proxy::uot::kV1MagicAddress
                : proxy::uot::kMagicAddress,
            0)
        : ctx.outbound.target;

    auto transport_target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
        .dns_service = &dns_service_,
        .address = config_.address,
        .literal_address = config_.literal_address,
        .port = config_.port,
        .stream_settings = &config_.stream_settings,
        .timeout = config_.timeout,
        .send_through = config_.send_through,
        .inbound_local_addr = inbound_local_addr,
        .tls_server_name = ResolveOutboundTlsServerName(config_.stream_settings, config_.address),
        .ws_host = config_.address,
    });
    if (!transport_target) {
        co_return std::unexpected(transport_target.error());
    }

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_WARN(ctx, "[SsOutbound] dial failed {} -> {} via {}: {}",
                          ctx.inbound.source_ip, ctx.outbound.target,
                          ctx.outbound.tag, dial_result.error_msg);
        co_return std::unexpected(dial_result.error);
    }

    auto stream = std::move(dial_result.stream);
    stream->SetStreamLabel("out");
    if (auto local_ep = stream->LocalEndpoint();
        local_ep && !local_ep->address().is_unspecified()) {
        ctx.outbound.connected_local_addr = local_ep->address();
        ctx.outbound.connected_local_port = local_ep->port();
    }
    LOG_ACCESS(FormatXrayAccessLog(ctx));

    stream->SetIdleTimeout(timeouts.HandshakeTimeout());
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

    auto request_writer_result = co_await ss::WriteTCPRequest(
        protocol_target, credentials_.Cipher(), credentials_.MasterKey(), credentials_.PskChain(), *stream);
    if (!request_writer_result) {
        stream->Cancel();
        co_return std::unexpected(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : request_writer_result.error());
    }
    auto request_session = std::move(request_writer_result.value());
    auto request_writer = std::move(request_session.request_writer);

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    ShadowsocksOutboundEndpoint target_endpoint(
        std::move(request_writer),
        credentials_.Cipher(),
        credentials_.MasterKey(),
        request_session.request_salt,
        *stream);

    if (use_uot &&
        *config_.uot_version != SsUotVersion::V1) {
        auto request = proxy::uot::EncodeRequest(false, ctx.outbound.target);
        if (!request) {
            target_endpoint.Cancel();
            co_return std::unexpected(request.error());
        }
        const std::array<net::const_buffer, 1> request_buffers{
            net::buffer(request->span())};
        co_await target_endpoint.WriteBuffers(request_buffers);
    }

    auto relay_endpoint = [&](auto& endpoint) -> net::awaitable<RelayResult> {
        if (inbound.control) {
            co_return co_await DoRelayLink(
                io_context, *inbound.reader, *inbound.writer, *inbound.control,
                endpoint, ctx, stats, relay_config, std::move(first_payload));
        }
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer,
            endpoint, ctx, stats, relay_config, std::move(first_payload));
    };

    if (use_uot) {
        proxy::uot::FramedEndpoint uot_endpoint(
            target_endpoint, false, ctx.outbound.target);
        co_return co_await relay_endpoint(uot_endpoint);
    }
    co_return co_await relay_endpoint(target_endpoint);
}

proxy::shadowsocks::outbound::Handler::Handler(std::string tag,
                                               const SsOutboundConfig& config,
                                               const Credentials& credentials,
                                               ::acpp::app::dns::DNS& dns_service,
                                               ::acpp::UDPSessionManager* udp_session_manager)
    : tag_(std::move(tag))
    , config_(config)
    , credentials_(credentials)
    , dns_service_(dns_service)
    , udp_session_manager_(udp_session_manager) {}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kSsOutboundRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kShadowsocks,
    [](const acpp::infra::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        auto json_string = [](const acpp::json::object& obj,
                              std::string_view key) -> std::string {
            if (const auto* v = obj.if_contains(key); v && v->is_string()) {
                return std::string(v->as_string());
            }
            return {};
        };
        std::string password;
        std::string method(acpp::constants::protocol::kAes256Gcm);
        auto read_ss_server = [&](const acpp::json::object& obj,
                                  acpp::SsOutboundConfig& config) {
            config.address = json_string(obj, "address");
            const auto port = acpp::ReadJsonPort(obj, {"port"});
            if (port.Invalid()) {
                return false;
            }
            if (port.Valid()) {
                config.port = port.value;
            }
            password = json_string(obj, "password");
            if (password.empty()) {
                password = json_string(obj, "key");
            }
            if (const auto* source_method = obj.if_contains("method")) {
                if (!source_method->is_string() || source_method->as_string().empty()) {
                    return false;
                }
                method = std::string(source_method->as_string());
            }
            auto uot_version =
                acpp::proxy::shadowsocks::outbound::ParseUotVersion(obj);
            if (!uot_version) {
                LOG_ERROR("Shadowsocks outbound '{}': invalid UoT settings: {}",
                          cfg.tag, uot_version.error());
                return false;
            }
            config.uot_version = *uot_version;
            return true;
        };

        acpp::SsOutboundConfig ss_config;

        bool parsed_xray = false;
        if (const auto* servers_p = cfg.settings.if_contains("servers");
                servers_p && servers_p->is_array() && !servers_p->as_array().empty() &&
                servers_p->as_array()[0].is_object()) {
            if (!read_ss_server(servers_p->as_array()[0].as_object(), ss_config)) {
                return std::nullopt;
            }
            parsed_xray = true;
        }
        if (!parsed_xray) {
            if (!read_ss_server(cfg.settings, ss_config)) {
                return std::nullopt;
            }
        }
        ss_config.send_through = cfg.send_through.value_or(acpp::OutboundBind{});
        ss_config.stream_settings = acpp::NormalizeOutboundStreamSettings(
            cfg.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = false,
                .fallback_server_name = ss_config.address,
                .allow_insecure = false,
                .alpn = {},
            });

        if (ss_config.address.empty() || ss_config.port == 0) {
            return std::nullopt;
        }
        auto credentials = acpp::proxy::shadowsocks::outbound::Credentials::Prepare(
            method, password);
        if (!credentials) {
            LOG_ERROR("Shadowsocks outbound '{}': invalid cipher, password or identity chain", cfg.tag);
            return std::nullopt;
        }
        ss_config.literal_address = acpp::iputil::ParseLiteral(ss_config.address);
        if (!ss_config.literal_address && !acpp::domain::IsValidDnsHostname(
                ss_config.address, acpp::domain::TrailingDotPolicy::Allow)) {
            LOG_ERROR("shadowsocks outbound '{}': address must be an IP literal or DNS hostname", cfg.tag);
            return std::nullopt;
        }
        return acpp::proxyman::outbound::PreparedOutboundCreator{
            [ss_config = std::move(ss_config), credentials = std::move(*credentials)](
                std::string_view tag,
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns_service,
                acpp::UDPSessionManager* udp_mgr,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_config = ss_config;
                runtime_config.timeout = timeout;
                return std::make_unique<acpp::proxy::shadowsocks::outbound::Handler>(
                    std::string(tag), runtime_config, credentials, dns_service, udp_mgr);
            }};
    }), true);
}  // namespace
