#include "acppnode/proxy/shadowsocks/outbound/ss_outbound.hpp"
#include "../client.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"

#include <algorithm>
#include <cstring>
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
                                AsyncStream& stream)
        : request_writer_(std::move(request_writer))
        , cipher_info_(cipher_info)
        , master_key_(master_key)
        , stream_(stream) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_reader_) {
            auto reader_result = co_await ss::ReadTCPResponse(
                cipher_info_, master_key_, stream_);
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

    net::awaitable<void> AsyncShutdownWrite() override {
        stream_.ShutdownWrite();
        co_return;
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

    void SetAbortiveClose(bool enable = true) noexcept {
        stream_.SetAbortiveClose(enable);
    }

private:
    std::unique_ptr<transport::MultiBufferWriter> request_writer_;
    ss::SsCipherInfo cipher_info_;
    ss::KeyBytes master_key_;
    AsyncStream& stream_;
    std::unique_ptr<transport::MultiBufferReader> response_reader_;
};

}  // namespace

net::awaitable<OutboundProcessResult> proxy::shadowsocks::outbound::Handler::Process(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    transport::Link inbound,
    StatsShard& stats,
    const RelayConfig& relay_config,
    std::span<const uint8_t> initial_payload,
    buf::MultiBuffer& first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const auto& target = ctx.outbound.target;

    auto transport_target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
        .dns_service = &dns_service_,
        .address = config_.address,
        .literal_address = config_.literal_address,
        .port = config_.port,
        .stream_settings = &stream_settings_,
        .timeout = config_.timeout,
        .send_through = config_.send_through,
        .inbound_local_addr = inbound_local_addr,
        .server_name = ResolveOutboundServerName(stream_settings_, config_.address),
    });
    if (!transport_target) {
        co_return std::unexpected(transport_target.error());
    }

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_FAIL_CTX(ctx, "[SsOutbound] dial failed {} -> {} via {}: {}",
                          ctx.inbound.source_ip, ctx.outbound.target,
                          ctx.outbound.tag, dial_result.error_msg);
        co_return std::unexpected(dial_result.error);
    }

    auto stream = std::move(dial_result.stream);
    stream->SetStreamLabel("out");
    LOG_ACCESS(FormatAccessLog(ctx));

    stream->SetIdleTimeout(timeouts.HandshakeTimeout());
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

    auto request_writer_result = co_await ss::WriteTCPRequest(
        target, cipher_info_, master_key_, *stream);
    if (!request_writer_result) {
        stream->Cancel();
        co_return std::unexpected(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : request_writer_result.error());
    }
    auto request_writer = std::move(request_writer_result.value());

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    ShadowsocksOutboundEndpoint target_endpoint(
        std::move(request_writer),
        cipher_info_,
        master_key_,
        *stream);
    if (buf::TotalLen(first_payload) > 0) {
        if (inbound.control) {
            co_return co_await DoRelayLinkWithFirstPacket(
                io_context, *inbound.reader, *inbound.writer, *inbound.control,
                target_endpoint, ctx, stats, first_payload, relay_config);
        }
        co_return co_await DoRelayLinkWithFirstPacket(
            io_context, *inbound.reader, *inbound.writer, target_endpoint,
            ctx, stats, first_payload, relay_config);
    }
    if (!initial_payload.empty()) {
        if (inbound.control) {
            co_return co_await DoRelayLinkWithFirstPacket(
                io_context, *inbound.reader, *inbound.writer, *inbound.control,
                target_endpoint, ctx, stats, initial_payload, relay_config);
        }
        co_return co_await DoRelayLinkWithFirstPacket(
            io_context, *inbound.reader, *inbound.writer, target_endpoint,
            ctx, stats, initial_payload, relay_config);
    }
    if (inbound.control) {
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer, *inbound.control,
            target_endpoint, ctx, stats, relay_config);
    }
    co_return co_await DoRelayLink(
        io_context, *inbound.reader, *inbound.writer,
        target_endpoint, ctx, stats, relay_config);
}

proxy::shadowsocks::outbound::Handler::Handler(const SsOutboundConfig& config,
                                               ::acpp::app::dns::DNS& dns_service)
    : config_(config)
    , dns_service_(dns_service) {
    config_.literal_address = ParseLiteralAddress(config_.address);

    auto info = ss::ParseCipherMethod(config_.method);
    if (info) {
        cipher_info_ = *info;
    } else {
        LOG_WARN("[SsOutbound] Unknown cipher '{}', fallback to {}",
                 config_.method,
                 acpp::constants::protocol::kAes256Gcm);
        cipher_info_ = ss::SsCipherInfo{ss::SsCipherType::AES_256_GCM, 32, 32};
    }

    master_key_ = ss::DeriveKey(config_.password, cipher_info_.key_size);
    stream_settings_ = config_.stream_settings;
    NormalizeOutboundStreamSettings(
        stream_settings_,
        OutboundStreamDefaults{.fallback_server_name = config_.address});
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kSsOutboundRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kShadowsocks,
    [](const acpp::proxyman::outbound::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundConfig> {
        const auto* servers_p = cfg.settings.if_contains("servers");
        if (!servers_p || !servers_p->is_array() || servers_p->as_array().empty()) {
            return std::nullopt;
        }
        const auto& first_server = servers_p->as_array()[0];
        if (!first_server.is_object()) {
            return std::nullopt;
        }
        const auto& srv = first_server.as_object();

        acpp::SsOutboundConfig ss_config;
        ss_config.tag     = cfg.tag;
        if (const auto* v = srv.if_contains("address"); v && v->is_string()) {
            ss_config.address = std::string(v->as_string());
        }
        if (const auto* v = srv.if_contains("port"); v) {
            if (v->is_uint64()) {
                ss_config.port = static_cast<uint16_t>(v->as_uint64());
            } else if (v->is_int64()) {
                ss_config.port = static_cast<uint16_t>(v->as_int64());
            }
        }
        if (const auto* v = srv.if_contains("password"); v && v->is_string()) {
            ss_config.password = std::string(v->as_string());
        }
        if (const auto* v = srv.if_contains("method"); v && v->is_string()) {
            ss_config.method = std::string(v->as_string());
        }
        ss_config.stream_settings = cfg.stream_settings;
        ss_config.send_through = cfg.send_through;
        acpp::NormalizeOutboundStreamSettings(
            ss_config.stream_settings,
            acpp::OutboundStreamDefaults{.fallback_server_name = ss_config.address});

        if (ss_config.address.empty() || ss_config.password.empty()) {
            return std::nullopt;
        }
        acpp::proxyman::outbound::PreparedOutboundConfig prepared;
        prepared.tag = cfg.tag;
        prepared.protocol = cfg.protocol;
        prepared.create =
            [ss_config = std::move(ss_config)](
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns_service,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_config = ss_config;
                runtime_config.timeout = timeout;
                return std::make_unique<acpp::proxy::shadowsocks::outbound::Handler>(
                    runtime_config, dns_service);
            };
        return prepared;
    }), true);
}  // namespace
