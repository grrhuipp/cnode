#include "vmess_outbound.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"
#include "../encoding/client.hpp"
#include "../vmess_crypto.hpp"
#include "../udp_datagram.hpp"
#include "../../handshake_timeout.hpp"
#include "../../outbound_stream_endpoint.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "acppnode/infra/json_field.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <openssl/rand.h>
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/buf/length_prefixed_packet_buffer.hpp"

namespace acpp {

namespace {

class VMessOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    VMessOutboundEndpoint(vmess::encoding::ClientSession& session,
                          AsyncStream& stream,
                          bool is_udp,
                          const TargetAddress& udp_target)
        : OutboundStreamEndpointBase(stream)
        , session_(session)
        , is_udp_(is_udp)
        , udp_target_(udp_target) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        auto mb = co_await session_.DecodeResponse(stream_);
        if (is_udp_) {
            buf::SetUdpDatagramTarget(mb, udp_target_);
        }
        co_return mb;
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (is_udp_) {
            ::acpp::vmess::ValidateFixedUdpDatagram(mb, udp_target_);
        }
        co_await session_.EncodeRequestBody(stream_, std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        co_await session_.EncodeRequestBody(stream_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        co_await session_.EncodeRequestBodyEOF(stream_);
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : stream_.ReadEofAction();
    }

private:
    vmess::encoding::ClientSession& session_;
    bool is_udp_ = false;
    const TargetAddress& udp_target_;
};

net::awaitable<tl::expected<void, ErrorCode>>
SendVMessHandshake(
    AsyncStream& stream,
    ::acpp::vmess::encoding::ClientSession& vmess_session,
    std::chrono::seconds handshake_timeout,
    session::Context& ctx) {
    stream.SetIdleTimeout(handshake_timeout);
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream.StartPhaseDeadline(handshake_timeout);

    auto handshake_result = co_await vmess_session.EncodeRequestHeader(stream);
    if (!handshake_result) {
        const bool timed_out = proxy::ConsumeOutboundHandshakeTimeout(
            stream, outbound_protocol_deadline);
        const ErrorCode code = timed_out ? ErrorCode::TIMEOUT : handshake_result.error();
        if (code != ErrorCode::CANCELLED && code != ErrorCode::CONNECTION_CLOSED &&
            code != ErrorCode::SOCKET_EOF) {
            LOG_CONN_WARN(ctx, "protocol handshake failed > {}", ErrorCodeToString(code));
        }
        stream.Cancel();
        co_return tl::unexpected(code);
    }
    LOG_CONN_DEBUG(ctx, "protocol handshake succeeded");
    co_return tl::expected<void, ErrorCode>{};
}

}  // namespace

// proxy/vmess/outbound.Handler 实现
// ============================================================================

proxy::vmess::outbound::Handler::Handler(
    std::string_view tag, std::shared_ptr<const PreparedSettings> prepared,
    ::acpp::app::dns::DNS& dns_service, std::chrono::seconds dial_timeout)
    : tag_(tag), prepared_(std::move(prepared)),
      security_(prepared_->config.stream_settings, StreamEndpointRole::Outbound),
      dial_timeout_(dial_timeout), dns_service_(dns_service) {
    LOG_DEBUG("VMess outbound '{}' created: {}:{}, network={}, security={}",
              tag_, prepared_->config.address, prepared_->config.port,
              prepared_->config.stream_settings.network,
              prepared_->config.stream_settings.security);
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
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    const auto& target = ctx.outbound.target;

    auto dialed = co_await acpp::DialOutboundStream(
        io_context,
        ctx,
        OutboundTargetOptions{
            .dns_service = &dns_service_,
            .address = prepared_->config.address,
            .literal_address = prepared_->config.literal_address,
            .port = prepared_->config.port,
            .stream_settings = &prepared_->config.stream_settings,
            .security = &security_,
            .timeout = dial_timeout_,
            .send_through = &prepared_->config.send_through,
            .inbound_local_addr = inbound_local_addr,
        });
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);

    const bool is_udp = ctx.content.network == Network::UDP;
    ::acpp::vmess::encoding::ClientSession vmess_session(
        prepared_->user,
        prepared_->auth_id_key,
        target,
        prepared_->config.security,
        is_udp ? ::acpp::vmess::Command::UDP : ::acpp::vmess::Command::TCP);

    if (auto ok = co_await SendVMessHandshake(
            *stream, vmess_session, timeouts.HandshakeTimeout(), ctx); !ok) {
        stream->CloseAbortive();
        co_return tl::unexpected(ok.error());
    }
    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    VMessOutboundEndpoint target_endpoint(vmess_session, *stream, is_udp, target);
    co_return co_await DoRelayLink(
        io_context, *inbound.reader, *inbound.writer, inbound.control,
        target_endpoint, ctx, stats, relay_config, std::move(first_payload));
}

}  // namespace

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kVMessRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kVmess,
    [](const acpp::infra::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        const auto& s = cfg.settings;

        // A present field of the wrong type is a configuration error, never
        // an implicit default.
        bool invalid_field = false;
        auto json_string = [&](const acpp::json::object& obj,
                               std::string_view key) -> std::string {
            auto parsed = acpp::ParseJsonString(obj, key);
            if (!parsed) {
                LOG_ERROR("VMess outbound '{}': {}", cfg.tag, parsed.error());
                invalid_field = true;
                return {};
            }
            return std::move(*parsed).value_or(std::string{});
        };
        auto has_supported_alter_id = [](const acpp::json::object& obj) {
            const auto* value = obj.if_contains("alterId");
            if (!value) return true;
            const auto alter_id = acpp::JsonUnsignedInteger(*value);
            return alter_id && *alter_id == 0;
        };
        auto parse_security = [&](std::string security)
            -> std::optional<acpp::vmess::Security> {
            security = acpp::naming::LowerAscii(std::move(security));
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
        std::string uuid;

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
                const auto port = acpp::ReadJsonPort(server, "port");
                if (port.Invalid()) {
                    return std::nullopt;
                }
                if (port.Valid()) {
                    vmess_config.port = port.value;
                }
                uuid = json_string(user, "id");
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
            vmess_config.address = json_string(s, "address");
            const auto port = acpp::ReadJsonPort(s, "port");
            if (port.Invalid()) {
                return std::nullopt;
            }
            if (port.Valid()) {
                vmess_config.port = port.value;
            }
            uuid = json_string(s, "id");
            if (!has_supported_alter_id(s)) {
                return std::nullopt;
            }
            auto parsed_security = parse_security(json_string(s, "security"));
            if (!parsed_security) {
                return std::nullopt;
            }
            vmess_config.security = *parsed_security;
        }
        if (invalid_field) {
            return std::nullopt;
        }

        vmess_config.send_through = cfg.send_through.value_or(acpp::OutboundBind{});
        vmess_config.stream_settings = acpp::NormalizeOutboundStreamSettings(
            cfg.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = false,
                .fallback_server_name = vmess_config.address,
                .allow_insecure = false,
                .alpn = {},
            });

        if (vmess_config.address.empty() || vmess_config.port == 0) {
            return std::nullopt;  // 配置不完整
        }
        auto user = acpp::vmess::MemoryAccount::FromUUID(uuid);
        if (!user) {
            LOG_ERROR("VMess outbound '{}': invalid UUID", cfg.tag);
            return std::nullopt;
        }
        vmess_config.literal_address = acpp::iputil::ParseLiteral(vmess_config.address);
        if (!vmess_config.literal_address && !acpp::domain::IsValidDnsHostname(
                vmess_config.address, acpp::domain::TrailingDotPolicy::Allow)) {
            LOG_ERROR("vmess outbound '{}': address must be an IP literal or DNS hostname", cfg.tag);
            return std::nullopt;
        }
        acpp::TransportSecurity::Prepare(
            vmess_config.stream_settings, acpp::StreamEndpointRole::Outbound);

        using PreparedSettings = acpp::proxy::vmess::outbound::PreparedSettings;
        return acpp::proxyman::outbound::MakePreparedOutboundCreator<
            PreparedSettings,
            +[](std::string_view tag,
                std::shared_ptr<const PreparedSettings> state,
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                std::chrono::seconds timeout,
                acpp::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<acpp::proxy::vmess::outbound::Handler>(
                    tag, std::move(state), dns, timeout);
            }>(PreparedSettings{std::move(vmess_config), *user,
                                acpp::vmess::ExpandAuthIDEncryptKey(user->auth_key)});
    }), true);
}  // namespace
