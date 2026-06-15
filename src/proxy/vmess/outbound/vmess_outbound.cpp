#include "acppnode/proxy/vmess/outbound/vmess_outbound.hpp"
#include "../encoding/client.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include <chrono>
#include <cstring>
#include <openssl/rand.h>
#include "acppnode/common/buffer_util.hpp"

namespace acpp {

namespace {

class VMessOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    VMessOutboundEndpoint(vmess::encoding::ClientSession& session,
                          AsyncStream& stream) noexcept
        : session_(session)
        , stream_(stream) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_header_read_) {
            if (!co_await session_.DecodeResponseHeader(stream_)) {
                throw IoSystemError(
                    io_error::connection_reset,
                    "VMess client read response header failed");
            }
            response_header_read_ = true;
        }
        co_return co_await session_.DecodeResponseBody(stream_);
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        co_await session_.EncodeRequestBody(stream_, std::move(mb));
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        co_await session_.EncodeRequestBodyEOF(stream_);
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
    vmess::encoding::ClientSession& session_;
    AsyncStream& stream_;
    bool response_header_read_ = false;
};

}  // namespace

// proxy/vmess/outbound.Handler 实现
// ============================================================================

proxy::vmess::outbound::Handler::Handler(const VMessOutboundConfig& config,
                                         ::acpp::app::dns::DNS& dns_service)
    : config_(config)
    , dns_service_(dns_service) {
    config_.literal_address = ParseLiteralAddress(config_.address);

    user_ = ::acpp::vmess::MemoryAccount::FromUUID(config_.uuid);
    if (!user_) {
        LOG_ERROR("VMess outbound '{}': invalid UUID", config_.tag);
    }

    NormalizeOutboundStreamSettings(
        config_.stream_settings,
        OutboundStreamDefaults{.fallback_server_name = config_.address});
    LOG_DEBUG("VMess outbound '{}' created: {}:{}, network={}, security={}",
              config_.tag, config_.address, config_.port,
              config_.stream_settings.network,
              config_.stream_settings.security);
}

net::awaitable<OutboundProcessResult>
proxy::vmess::outbound::Handler::Process(
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
    if (!user_) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    const auto& target = ctx.outbound.target;

    auto transport_target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
        .dns_service = &dns_service_,
        .address = config_.address,
        .literal_address = config_.literal_address,
        .port = config_.port,
        .stream_settings = &config_.stream_settings,
        .timeout = config_.timeout,
        .send_through = config_.send_through,
        .inbound_local_addr = inbound_local_addr,
        .server_name = ResolveOutboundServerName(config_.stream_settings, config_.address),
    });
    if (!transport_target) {
        if (transport_target.error() == ErrorCode::DNS_RESOLVE_FAILED) {
            LOG_CONN_FAIL_CTX(ctx, "[VMess] DNS resolve failed for {}", config_.address);
        }
        co_return std::unexpected(transport_target.error());
    }

    LOG_CONN_DEBUG(ctx, "[VMess] transport target {}:{} ({}/{})",
                   config_.address, config_.port,
                   config_.stream_settings.security,
                   config_.stream_settings.network);

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_FAIL_CTX(ctx, "[VMess] dial failed {} -> {} via {}: {}",
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

    ::acpp::vmess::encoding::ClientSession vmess_session(
        *user_, target, config_.security);

    auto handshake_result = co_await vmess_session.EncodeRequestHeader(*stream);
    if (!handshake_result) {
        ErrorCode code = handshake_result.error();
        if (code == ErrorCode::OK) {
            code = ErrorCode::PROTOCOL_AUTH_FAILED;
        }
        LOG_CONN_FAIL("[conn={}] VMessOutbound: protocol handshake failed: {}",
                      ctx.conn_id, ErrorCodeToString(code));
        stream->Cancel();
        co_return std::unexpected(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : code);
    }
    LOG_CONN_DEBUG(ctx, "[VMess] Process OK");
    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    VMessOutboundEndpoint target_endpoint(vmess_session, *stream);
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

}  // namespace

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kVMessRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kVmess,
    [](const acpp::proxyman::outbound::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundConfig> {
        const auto& s = cfg.settings;

        // 解析 vnext[0]
        const auto* vnext_p = s.if_contains("vnext");
        if (!vnext_p || !vnext_p->is_array() || vnext_p->as_array().empty()) {
            return std::nullopt;
        }
        const auto& server = vnext_p->as_array()[0].as_object();

        // 解析 users[0]
        const auto* users_p = server.if_contains("users");
        if (!users_p || !users_p->is_array() || users_p->as_array().empty()) {
            return std::nullopt;
        }
        const auto& user = users_p->as_array()[0].as_object();

        acpp::VMessOutboundConfig vmess_config;
        vmess_config.tag      = cfg.tag;
        if (const auto* v = server.if_contains("address"); v && v->is_string()) {
            vmess_config.address = std::string(v->as_string());
        }
        if (const auto* v = server.if_contains("port"); v) {
            if (v->is_uint64()) {
                vmess_config.port = static_cast<uint16_t>(v->as_uint64());
            } else if (v->is_int64()) {
                vmess_config.port = static_cast<uint16_t>(v->as_int64());
            }
        }
        if (const auto* v = user.if_contains("id"); v && v->is_string()) {
            vmess_config.uuid = std::string(v->as_string());
        }
        if (const auto* v = user.if_contains("alterId"); v) {
            if (v->is_uint64()) {
                vmess_config.alter_id = static_cast<int>(v->as_uint64());
            } else if (v->is_int64()) {
                vmess_config.alter_id = static_cast<int>(v->as_int64());
            }
        }

        std::string security = std::string(acpp::constants::binding::kAuto);
        if (const auto* v = user.if_contains("security"); v && v->is_string()) {
            security = std::string(v->as_string());
        }
        if (security == acpp::constants::protocol::kAes128Gcm ||
            security == acpp::constants::binding::kAuto) {
            vmess_config.security = acpp::vmess::Security::AES_128_GCM;
        } else if (security == acpp::constants::protocol::kChacha20IetfPoly1305) {
            vmess_config.security = acpp::vmess::Security::CHACHA20_POLY1305;
        } else if (security == acpp::constants::protocol::kNone) {
            vmess_config.security = acpp::vmess::Security::NONE;
        }

        vmess_config.stream_settings = cfg.stream_settings;
        vmess_config.send_through = cfg.send_through;
        acpp::NormalizeOutboundStreamSettings(
            vmess_config.stream_settings,
            acpp::OutboundStreamDefaults{.fallback_server_name = vmess_config.address});

        if (vmess_config.address.empty() || vmess_config.uuid.empty()) {
            return std::nullopt;  // 配置不完整
        }

        acpp::proxyman::outbound::PreparedOutboundConfig prepared;
        prepared.tag = cfg.tag;
        prepared.protocol = cfg.protocol;
        prepared.create =
            [vmess_config = std::move(vmess_config)](
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_config = vmess_config;
                runtime_config.timeout = timeout;
                return std::make_unique<acpp::proxy::vmess::outbound::Handler>(
                    runtime_config, dns);
            };
        return prepared;
    }), true);
}  // namespace
