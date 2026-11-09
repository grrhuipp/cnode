#include "vmess_outbound.hpp"
#include "common/domain_name.hpp"
#include "common/ip_address.hpp"
#include "../encoding/client.hpp"
#include "../vmess_crypto.hpp"
#include "../udp_datagram.hpp"
#include "../../handshake_timeout.hpp"
#include "../../outbound_server.hpp"
#include "../../outbound_stream_endpoint.hpp"
#include "app/relay.hpp"
#include "app/dns/dns.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "infra/json_field.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "core/naming.hpp"
#include "common/error.hpp"
#include "common/session.hpp"
#include "transport/link.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <new>
#include <openssl/rand.h>
#include "common/buffer_util.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"


namespace {

class VMessOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    VMessOutboundEndpoint(vmess::encoding::ClientSession& session,
                          AsyncStream& stream,
                          bool is_udp,
                          const TargetAddress& udp_target) noexcept
        : OutboundStreamEndpointBase(stream)
        , session_(session)
        , is_udp_(is_udp)
        , udp_target_(udp_target) {}
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!is_udp_) {
            return session_.DecodeResponse(stream_);
        }
        return ReadUdpMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (is_udp_) {
            ::vmess::ValidateFixedUdpDatagram(mb, udp_target_);
        }
        return session_.EncodeRequestBody(stream_, std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return session_.EncodeRequestBody(stream_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return session_.EncodeRequestBodyEOF(stream_);
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return false;
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : stream_.ReadEofAction();
    }

private:
    net::awaitable<buf::MultiBuffer> ReadUdpMultiBuffer() {
        auto mb = co_await session_.DecodeResponse(stream_);
        if (mb.byte_size() != 0 && !buf::SetUdpTarget(mb, udp_target_)) {
            throw std::bad_alloc();
        }
        co_return mb;
    }

    vmess::encoding::ClientSession& session_;
    bool is_udp_ = false;
    const TargetAddress& udp_target_;
};

net::awaitable<tl::expected<void, ErrorCode>>
SendVMessHandshake(
    AsyncStream& stream,
    ::vmess::encoding::ClientSession& vmess_session,
    const ::vmess::MemoryAccount& user,
    const AES_KEY& auth_id_key,
    const TargetAddress& target,
    ::vmess::Command command,
    ForwardedMetadataView forwarded,
    std::chrono::seconds handshake_timeout,
    session::Context& ctx) {
    stream.SetIdleTimeout(handshake_timeout);
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream.StartPhaseDeadline(handshake_timeout);

    auto handshake_result = co_await vmess_session.EncodeRequestHeader(
        stream, user, auth_id_key, target, command, forwarded);
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

proxy::vmess::outbound::Handler::Handler(std::shared_ptr<const PreparedSettings> prepared)
    : prepared_(std::move(prepared)) {}

net::awaitable<OutboundProcessResult>
proxy::vmess::outbound::Handler::Process(
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
    const auto& target = ctx.outbound.target;

    auto dialed = co_await dialer.Dial(ctx, prepared_->config.server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);

    const bool is_udp = ctx.content.network == Network::UDP;
    const auto command = is_udp ? ::vmess::Command::UDP : ::vmess::Command::TCP;
    ::vmess::encoding::ClientSession vmess_session(
        prepared_->config.security, command);

    if (auto ok = co_await SendVMessHandshake(
            *stream, vmess_session, prepared_->user, prepared_->auth_id_key,
            target, command, dialer.ForwardedMetadata(ctx),
            timeouts.HandshakeTimeout(), ctx); !ok) {
        stream->CloseAbortive();
        co_return tl::unexpected(ok.error());
    }
    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    VMessOutboundEndpoint target_endpoint(vmess_session, *stream, is_udp, target);
    co_return co_await DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        target_endpoint, ctx, stats, relay_config, std::move(first_payload));
}

  // namespace

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kVMessRegistered = (::proxyman::outbound::RegisterProxy(
    ::constants::protocol::kVmess,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::proxyman::outbound::PreparedOutboundProxy> {
        const auto& s = cfg.settings;

        // A present field of the wrong type is a configuration error, never
        // an implicit default.
        bool invalid_field = false;
        auto json_string = [&](const ::json::object& obj,
                               std::string_view key) -> std::string {
            auto parsed = ::ParseJsonString(obj, key);
            if (!parsed) {
                LOG_ERROR("VMess outbound '{}': {}", cfg.tag, parsed.error());
                invalid_field = true;
                return {};
            }
            return std::move(*parsed).value_or(std::string{});
        };
        auto has_supported_alter_id = [](const ::json::object& obj) {
            const auto* value = obj.if_contains("alterId");
            if (!value) return true;
            const auto alter_id = ::JsonUnsignedInteger(*value);
            return alter_id && *alter_id == 0;
        };
        auto parse_security = [&](std::string security)
            -> std::optional<::vmess::Security> {
            security = ::naming::LowerAscii(std::move(security));
            if (security.empty() ||
                security == ::constants::protocol::kAes128Gcm ||
                security == ::constants::binding::kAuto) {
                return ::vmess::Security::AES_128_GCM;
            }
            if (security == ::constants::protocol::kChacha20IetfPoly1305 ||
                security == "chacha20-poly1305") {
                return ::vmess::Security::CHACHA20_POLY1305;
            }
            if (security == ::constants::protocol::kNone) {
                return ::vmess::Security::NONE;
            }
            if (security == "zero") {
                return ::vmess::Security::ZERO;
            }
            return std::nullopt;
        };

        const auto vnext_server = ::proxy::ParseOptionalSingleObjectArray(
            s, "vnext", "VMess", cfg.tag);
        if (!vnext_server) {
            return std::nullopt;
        }
        const ::json::object& server_obj = *vnext_server ? **vnext_server : s;
        const ::json::object* user_obj = &s;
        if (*vnext_server) {
            user_obj = ::proxy::ParseRequiredSingleObjectArray(
                server_obj, "users", "VMess", cfg.tag);
            if (!user_obj) {
                return std::nullopt;
            }
        } else if (s.if_contains("users")) {
            LOG_ERROR("VMess outbound '{}': users requires vnext", cfg.tag);
            return std::nullopt;
        }
        std::string address = json_string(server_obj, "address");
        uint16_t port = 443;
        const auto source_port = ::ReadJsonPort(server_obj, "port");
        if (source_port.Invalid()) {
            return std::nullopt;
        }
        if (source_port.Valid()) {
            port = source_port.value;
        }
        std::string uuid = json_string(*user_obj, "id");
        if (!has_supported_alter_id(*user_obj)) {
            return std::nullopt;
        }
        auto parsed_security = parse_security(json_string(*user_obj, "security"));
        if (!parsed_security) {
            return std::nullopt;
        }
        const auto security = *parsed_security;
        if (invalid_field) {
            return std::nullopt;
        }

        auto user = ::vmess::MemoryAccount::FromUUID(uuid);
        if (!user) {
            LOG_ERROR("VMess outbound '{}': invalid UUID", cfg.tag);
            return std::nullopt;
        }
        auto next_hop = ::proxy::PrepareNextHop(
            cfg, std::move(address), port, ::OutboundStreamDefaults{});
        if (!next_hop) {
            return std::nullopt;
        }

        using PreparedSettings = ::proxy::vmess::outbound::PreparedSettings;
        return ::proxyman::outbound::PreparedOutboundProxy{
            .create = ::proxyman::outbound::MakePreparedOutboundCreator<
                PreparedSettings,
                +[](std::string_view,
                    std::shared_ptr<const PreparedSettings> state,
                    ::net::io_context& /*io_context*/,
                    ::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::Outbound> {
                    return std::make_unique<::proxy::vmess::outbound::Handler>(
                        std::move(state));
                }>(PreparedSettings{
                    ::VMessOutboundConfig{
                        .server = std::move(next_hop->server),
                        .security = security,
                    },
                    *user,
                    ::vmess::ExpandAuthIDEncryptKey(user->auth_key)}),
            .sender = std::move(next_hop->sender),
        };
    }), true);
}  // namespace
