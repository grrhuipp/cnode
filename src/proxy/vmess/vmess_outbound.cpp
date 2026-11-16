#include "proxy/outbound_endpoint_base.hpp"
#include <openssl/mem.h>
#include "proxy/outbound.hpp"
#include "proxy/vmess/body.hpp"
#include "proxy/vmess/vmess_crypto.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/outbound_stream_endpoint.hpp"
#include "app/outbound_handler.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "common/constants.hpp"
#include "common/error.hpp"
#include "common/session.hpp"
#include "transport/link.hpp"
#include "transport/outbound_target_builder.hpp"
#include <chrono>
#include <openssl/aes.h>
#include <memory>

namespace proxy {

struct VMessOutboundConfig {
    transport::OutboundServer server;
    proxy::VmessSecurity security = proxy::VmessSecurity::AES_128_GCM;
};

struct VmessPreparedSettings {
    VMessOutboundConfig config;
    ::proxy::VmessUserAccount user;
    AES_KEY auth_id_key{};  // Encrypt schedule of user.auth_key, built on prepare.

    ~VmessPreparedSettings() noexcept {
        OPENSSL_cleanse(&auth_id_key, sizeof(auth_id_key));
    }
};

class VmessOutboundHandler final : public ::proxy::Outbound {
public:
    explicit VmessOutboundHandler(std::shared_ptr<const VmessPreparedSettings> prepared);

    struct Session;
    auto SessionArguments() const noexcept { return std::tuple{std::cref(*prepared_)}; }

private:
    std::shared_ptr<const VmessPreparedSettings> prepared_;
};

namespace {

class VMessOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    VMessOutboundEndpoint(proxy::ClientSession& session,
                          transport::AsyncStream& stream,
                          bool is_udp,
                          const common::TargetAddress& udp_target) noexcept
        : OutboundStreamEndpointBase(stream)
        , session_(session)
        , is_udp_(is_udp)
        , udp_target_(udp_target) {}
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        return session_.DecodeResponse(stream_, is_udp_ ? &udp_target_ : nullptr);
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        if (is_udp_) {
            ::proxy::ValidateFixedUdpDatagram(mb, udp_target_);
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
    proxy::ClientSession& session_;
    bool is_udp_ = false;
    const common::TargetAddress& udp_target_;
};

net::awaitable<tl::expected<std::unique_ptr<transport::AsyncStream>, common::ErrorCode>>
DialAndSendVMessHandshake(
    common::Context& ctx,
    transport::OutboundDialer& dialer,
    const VmessPreparedSettings& prepared,
    ::proxy::ClientSession& vmess_session,
    ::proxy::VmessCommand command,
    std::chrono::seconds handshake_timeout) {
    auto dialed = co_await dialer.Dial(ctx, prepared.config.server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    stream->SetIdleTimeout(handshake_timeout);
    transport::PhaseDeadlineToken outbound_protocol_deadline =
        stream->StartPhaseDeadline(handshake_timeout);

    auto handshake_result = co_await vmess_session.EncodeRequestHeader(
        *stream,
        prepared.user,
        prepared.auth_id_key,
        ctx.outbound.target,
        command,
        dialer.ForwardedMetadata(ctx));
    if (!handshake_result) {
        const bool timed_out = proxy::ConsumeOutboundHandshakeTimeout(
            *stream, outbound_protocol_deadline);
        const common::ErrorCode code = timed_out ? common::ErrorCode::TIMEOUT : handshake_result.error();
        if (code != common::ErrorCode::CANCELLED && code != common::ErrorCode::CONNECTION_CLOSED &&
            code != common::ErrorCode::SOCKET_EOF) {
            LOG_CONN_WARN(ctx, "protocol handshake failed > {}", common::ErrorCodeToString(code));
        }
        stream->Cancel();
        stream->CloseAbortive();
        co_return tl::unexpected(code);
    }
    LOG_CONN_DEBUG(ctx, "protocol handshake succeeded");
    co_return std::move(stream);
}
}  // namespace

// proxy/vmess/outbound.Handler 实现
// ============================================================================

struct VmessOutboundHandler::Session final : OutboundSession {
    OutboundPrepareContext& context;
    const VmessPreparedSettings& prepared;
    bool is_udp;
    proxy::VmessCommand command;
    proxy::ClientSession vmess_session;
    std::unique_ptr<transport::AsyncStream> stream;
    std::optional<VMessOutboundEndpoint> endpoint;

    Session(OutboundPrepareContext& context, const VmessPreparedSettings& prepared)
        : context(context), prepared(prepared)
        , is_udp(context.ctx.content.network == common::Network::UDP)
        , command(is_udp ? proxy::VmessCommand::UDP : proxy::VmessCommand::TCP)
        , vmess_session(prepared.config.security, command) {}

    net::awaitable<OutboundPrepareResult<VMessOutboundEndpoint>> Prepare() {
        auto& [ctx, dialer, timeouts] = context;
        auto dialed = co_await DialAndSendVMessHandshake(
            ctx, dialer, prepared, vmess_session, command, timeouts.HandshakeTimeout());
        if (!dialed) co_return tl::unexpected(dialed.error());
        stream = std::move(*dialed);
        endpoint.emplace(vmess_session, *stream, is_udp, ctx.outbound.target);
        co_return std::ref(*endpoint);
    }
};

VmessOutboundHandler::VmessOutboundHandler(std::shared_ptr<const VmessPreparedSettings> prepared)
    : Outbound(std::in_place_type<VmessOutboundHandler>)
    , prepared_(std::move(prepared)) {}

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kVMessRegistered = (::app::RegisterProxy(
    ::common::kVmess,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::app::PreparedOutboundProxy> {
        const auto* settings = std::get_if<::infra::VmessSettings>(&cfg.settings);
        if (!settings) return std::nullopt;
        auto user = ::proxy::VmessUserAccount::FromUuidBytes(settings->id);
        auto next_hop = ::proxy::PrepareNextHop(cfg, settings->server, ::transport::OutboundStreamDefaults{});

        using PreparedSettings = ::proxy::VmessPreparedSettings;
        return ::app::PreparedOutboundProxy{
            .create = ::app::MakePreparedOutboundCreator<
                PreparedSettings,
                +[](std::string_view,
                    std::shared_ptr<const PreparedSettings> state,
                    ::net::io_context& /*io_context*/,
                    ::common::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::proxy::Outbound> {
                    return std::make_unique<::proxy::VmessOutboundHandler>(
                        std::move(state));
                }>(PreparedSettings{
                    ::proxy::VMessOutboundConfig{
                        .server = std::move(next_hop.server),
                        .security = settings->security,
                    },
                    user,
                    ::proxy::ExpandAuthIDEncryptKey(user.auth_key)}),
            .sender = std::move(next_hop.sender),
        };
    }), true);
}  // namespace

}  // namespace proxy
