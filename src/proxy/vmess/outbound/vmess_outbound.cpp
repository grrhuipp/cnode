#include "vmess_outbound.hpp"
#include "../encoding/client.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/infra/json_port.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <openssl/rand.h>
#include "acppnode/common/buffer_util.hpp"

namespace acpp {

namespace {

[[nodiscard]] bool SameTargetAddress(const TargetAddress& lhs,
                                     const TargetAddress& rhs) {
    if (lhs.port != rhs.port) {
        return false;
    }
    if (lhs.IsDomain() || rhs.IsDomain()) {
        return lhs.IsDomain() && rhs.IsDomain() && lhs.host == rhs.host;
    }
    if (lhs.resolved_addr && rhs.resolved_addr) {
        return *lhs.resolved_addr == *rhs.resolved_addr;
    }
    return false;
}

class VMessOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    VMessOutboundEndpoint(vmess::encoding::ClientSession& session,
                          AsyncStream& stream,
                          bool is_udp,
                          TargetAddress udp_target)
        : session_(session)
        , stream_(stream)
        , is_udp_(is_udp)
        , udp_target_(std::move(udp_target)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_header_read_) {
            if (!co_await session_.DecodeResponseHeader(stream_)) {
                throw IoSystemError(
                    io_error::connection_reset,
                    "VMess client read response header failed");
            }
            response_header_read_ = true;
        }
        auto mb = co_await session_.DecodeResponseBody(stream_);
        if (is_udp_) {
            for (buf::Buffer* buffer : mb) {
                if (buffer && !buffer->IsEmpty()) {
                    buffer->SetUDP(udp_target_);
                }
            }
        }
        co_return mb;
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (is_udp_) {
            buf::MultiBuffer filtered;
            for (buf::Buffer*& buffer : mb) {
                if (!buffer || buffer->IsEmpty()) {
                    mb.FreeSlot(buffer);
                    continue;
                }
                if (buffer->HasUDP() && !SameTargetAddress(buffer->UDP(), udp_target_)) {
                    mb.FreeSlot(buffer);
                    continue;
                }
                filtered.push_back(mb.ReleaseSlot(buffer));
            }
            mb.clear();
            co_await session_.EncodeRequestBody(stream_, std::move(filtered));
            co_return;
        }
        co_await session_.EncodeRequestBody(stream_, std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        co_await session_.EncodeRequestBody(stream_, buffers);
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
    bool is_udp_ = false;
    TargetAddress udp_target_;
};

}  // namespace

// proxy/vmess/outbound.Handler 实现
// ============================================================================

proxy::vmess::outbound::Handler::Handler(std::string tag,
                                         const VMessOutboundConfig& config,
                                         ::acpp::app::dns::DNS& dns_service)
    : tag_(std::move(tag))
    , config_(config)
    , dns_service_(dns_service) {
    config_.literal_address = ParseLiteralAddress(config_.address);

    user_ = ::acpp::vmess::MemoryAccount::FromUUID(config_.uuid);
    if (!user_) {
        LOG_ERROR("VMess outbound '{}': invalid UUID", tag_);
    }

    NormalizeOutboundStreamSettings(
        config_.stream_settings,
        OutboundStreamDefaults{
            .require_tls = false,
            .fallback_server_name = config_.address,
            .allow_insecure = false,
            .alpn = {},
        });
    LOG_DEBUG("VMess outbound '{}' created: {}:{}, network={}, security={}",
              tag_, config_.address, config_.port,
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
        .tls_server_name = ResolveOutboundTlsServerName(
            config_.stream_settings, config_.address),
        .ws_host = config_.address,
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

    const bool is_udp = ctx.content.network == Network::UDP;
    ::acpp::vmess::encoding::ClientSession vmess_session(
        *user_,
        target,
        config_.security,
        is_udp ? ::acpp::vmess::Command::UDP : ::acpp::vmess::Command::TCP);

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

    VMessOutboundEndpoint target_endpoint(vmess_session, *stream, is_udp, target);
    if (buf::HasData(first_payload)) {
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
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        const auto& s = cfg.settings;

        auto json_string = [](const acpp::json::object& obj,
                              std::string_view key) -> std::string {
            if (const auto* v = obj.if_contains(key); v && v->is_string()) {
                return std::string(v->as_string());
            }
            return {};
        };
        auto has_supported_alter_id = [](const acpp::json::object& obj) {
            for (const std::string_view key : {"alterId", "alter_id"}) {
                const auto* value = obj.if_contains(key);
                if (!value) continue;
                if (value->is_int64() && value->as_int64() == 0) continue;
                if (value->is_uint64() && value->as_uint64() == 0) continue;
                return false;
            }
            return true;
        };
        auto lower_ascii = [](std::string text) {
            std::transform(
                text.begin(),
                text.end(),
                text.begin(),
                [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
            return text;
        };
        auto parse_security = [&](std::string security)
            -> std::optional<acpp::vmess::Security> {
            security = lower_ascii(std::move(security));
            if (security.empty() ||
                security == acpp::constants::protocol::kAes128Gcm ||
                security == acpp::constants::binding::kAuto) {
                return acpp::vmess::Security::AES_128_GCM;
            }
            if (security == acpp::constants::protocol::kChacha20IetfPoly1305 ||
                security == "chacha20-poly1305") {
                return acpp::vmess::Security::CHACHA20_POLY1305;
            }
            if (security == acpp::constants::protocol::kNone) {
                return acpp::vmess::Security::NONE;
            }
            if (security == "zero") {
                return acpp::vmess::Security::ZERO;
            }
            return std::nullopt;
        };

        acpp::VMessOutboundConfig vmess_config;

        bool parsed_xray = false;
        if (const auto* vnext_p = s.if_contains("vnext");
                vnext_p && vnext_p->is_array() && !vnext_p->as_array().empty() &&
                vnext_p->as_array()[0].is_object()) {
            const auto& server = vnext_p->as_array()[0].as_object();
            if (const auto* users_p = server.if_contains("users");
                    users_p && users_p->is_array() && !users_p->as_array().empty() &&
                    users_p->as_array()[0].is_object()) {
                const auto& user = users_p->as_array()[0].as_object();
                vmess_config.address = json_string(server, "address");
                if (vmess_config.address.empty()) {
                    vmess_config.address = json_string(server, "server");
                }
                const auto port = acpp::ReadJsonPort(server, {"port"});
                if (port.Invalid()) {
                    return std::nullopt;
                }
                if (port.Valid()) {
                    vmess_config.port = port.value;
                }
                vmess_config.uuid = json_string(user, "id");
                if (vmess_config.uuid.empty()) {
                    vmess_config.uuid = json_string(user, "uuid");
                }
                if (!has_supported_alter_id(user)) {
                    return std::nullopt;
                }
                auto parsed_security = parse_security(json_string(user, "security"));
                if (!parsed_security) {
                    return std::nullopt;
                }
                vmess_config.security = *parsed_security;
                parsed_xray = true;
            }
        }

        if (!parsed_xray) {
            vmess_config.address = json_string(s, "server");
            if (vmess_config.address.empty()) {
                vmess_config.address = json_string(s, "address");
            }
            const auto port = acpp::ReadJsonPort(
                s, {"server_port", "port"});
            if (port.Invalid()) {
                return std::nullopt;
            }
            if (port.Valid()) {
                vmess_config.port = port.value;
            }
            vmess_config.uuid = json_string(s, "uuid");
            if (vmess_config.uuid.empty()) {
                vmess_config.uuid = json_string(s, "id");
            }
            if (!has_supported_alter_id(s)) {
                return std::nullopt;
            }
            auto parsed_security = parse_security(json_string(s, "security"));
            if (!parsed_security) {
                return std::nullopt;
            }
            vmess_config.security = *parsed_security;
        }

        vmess_config.stream_settings = cfg.stream_settings;
        vmess_config.send_through = cfg.send_through.value_or(acpp::OutboundBind{});
        acpp::NormalizeOutboundStreamSettings(
            vmess_config.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = false,
                .fallback_server_name = vmess_config.address,
                .allow_insecure = false,
                .alpn = {},
            });

        if (vmess_config.address.empty() || vmess_config.uuid.empty() ||
            vmess_config.port == 0) {
            return std::nullopt;  // 配置不完整
        }

        return acpp::proxyman::outbound::PreparedOutboundCreator{
            [vmess_config = std::move(vmess_config)](
                std::string_view tag,
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_config = vmess_config;
                runtime_config.timeout = timeout;
                return std::make_unique<acpp::proxy::vmess::outbound::Handler>(
                    std::string(tag), runtime_config, dns);
            }};
    }), true);
}  // namespace
