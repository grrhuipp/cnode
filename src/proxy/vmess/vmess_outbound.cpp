#include "proxy/outbound_endpoint_base.hpp"
#include <openssl/mem.h>
#include "proxy/outbound.hpp"
#include "proxy/vmess/body.hpp"
#include "proxy/vmess/vmess_crypto.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/outbound_stream_endpoint.hpp"
#include "app/relay.hpp"
#include "app/outbound_handler.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "common/constants.hpp"
#include "common/error.hpp"
#include "common/session.hpp"
#include "transport/link.hpp"
#include "transport/outbound_target_builder.hpp"
#include <chrono>
#include <new>
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

    ::net::awaitable<::proxy::OutboundProcessResult> Process(
        ::common::Context& ctx,
        ::transport::Link inbound,
        ::transport::OutboundDialer& dialer,
        const ::infra::TimeoutsConfig& timeouts,
        ::app::StatsShard& stats,
        const ::app::RelayConfig& relay_config,
        ::common::MultiBufferBatch first_payload) override;

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
        if (!is_udp_) {
            return session_.DecodeResponse(stream_);
        }
        return ReadUdpMultiBuffer();
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
    net::awaitable<common::MultiBuffer> ReadUdpMultiBuffer() {
        auto mb = co_await session_.DecodeResponse(stream_);
        if (mb.byte_size() != 0 && !common::SetUdpTarget(mb, udp_target_)) {
            throw std::bad_alloc();
        }
        co_return mb;
    }

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

VmessOutboundHandler::VmessOutboundHandler(std::shared_ptr<const VmessPreparedSettings> prepared)
    : prepared_(std::move(prepared)) {}

net::awaitable<OutboundProcessResult>
VmessOutboundHandler::Process(
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
    const bool is_udp = ctx.content.network == common::Network::UDP;
    const auto command = is_udp ? ::proxy::VmessCommand::UDP : ::proxy::VmessCommand::TCP;
    ::proxy::ClientSession vmess_session(prepared_->config.security, command);
    std::unique_ptr<transport::AsyncStream> stream;
    {
        auto dialed = co_await DialAndSendVMessHandshake(
            ctx, dialer, *prepared_, vmess_session, command, timeouts.HandshakeTimeout());
        if (!dialed) {
            co_return tl::unexpected(dialed.error());
        }
        stream = std::move(*dialed);
    }
    proxy::ApplyOutboundRelayTimeouts(*stream, relay_config);

    VMessOutboundEndpoint target_endpoint(
        vmess_session, *stream, is_udp, ctx.outbound.target);
    co_return co_await app::DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        target_endpoint, ctx, stats, relay_config, std::move(first_payload));
}

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
