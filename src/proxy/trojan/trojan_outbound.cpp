#include "common/scoped_cleanse.hpp"
#include "proxy/outbound.hpp"
#include "proxy/trojan/trojan_codec.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/outbound_stream_endpoint.hpp"
#include "app/relay.hpp"
#include "app/outbound_handler.hpp"
#include "infra/config_types.hpp"
#include "transport/link.hpp"
#include "transport/outbound_target_builder.hpp"
#include <openssl/crypto.h>
#include <array>
#include <cstring>
#include <new>
#include <utility>

#include <chrono>
#include <memory>

namespace proxy {

struct TrojanOutboundConfig {
    transport::OutboundServer server;
    TrojanPasswordHash password_hash{};

    TrojanOutboundConfig() = default;
    TrojanOutboundConfig(transport::OutboundServer srv, TrojanPasswordHash hash) noexcept
        : server(std::move(srv)), password_hash(hash) {}
    TrojanOutboundConfig(const TrojanOutboundConfig&) = default;
    TrojanOutboundConfig& operator=(const TrojanOutboundConfig&) = default;
    TrojanOutboundConfig(TrojanOutboundConfig&&) noexcept = default;
    TrojanOutboundConfig& operator=(TrojanOutboundConfig&&) noexcept = default;
    ~TrojanOutboundConfig() noexcept {
        OPENSSL_cleanse(password_hash.data(), password_hash.size());
    }
};

class TrojanOutboundHandler final : public ::proxy::Outbound {
public:
    explicit TrojanOutboundHandler(std::shared_ptr<const ::proxy::TrojanOutboundConfig> config);

    ::net::awaitable<::proxy::OutboundProcessResult> Process(
        ::common::Context& ctx,
        ::transport::Link inbound,
        ::transport::OutboundDialer& dialer,
        const ::infra::TimeoutsConfig& timeouts,
        ::app::StatsShard& stats,
        const ::app::RelayConfig& relay_config,
        ::common::MultiBufferBatch first_payload) override;

private:
    ::net::awaitable<::proxy::OutboundProcessResult> ProcessUdp(
        ::common::Context& ctx,
        ::transport::Link inbound,
        ::transport::OutboundDialer& dialer,
        const ::infra::TimeoutsConfig& timeouts,
        ::app::StatsShard& stats,
        const ::app::RelayConfig& relay_config,
        ::common::MultiBufferBatch first_payload);
    ::net::awaitable<::proxy::OutboundProcessResult> ProcessTcp(
        ::common::Context& ctx,
        ::transport::Link inbound,
        ::transport::OutboundDialer& dialer,
        const ::infra::TimeoutsConfig& timeouts,
        ::app::StatsShard& stats,
        const ::app::RelayConfig& relay_config,
        ::common::MultiBufferBatch first_payload);

    std::shared_ptr<const ::proxy::TrojanOutboundConfig> config_;
};
namespace {

net::awaitable<tl::expected<std::unique_ptr<transport::AsyncStream>, common::ErrorCode>>
DialAndSendTrojanHandshake(
    common::Context& ctx,
    transport::OutboundDialer& dialer,
    const TrojanOutboundConfig& config,
    bool is_udp,
    std::chrono::seconds handshake_timeout) {
    auto dialed = co_await dialer.Dial(ctx, config.server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    stream->SetIdleTimeout(handshake_timeout);
    transport::PhaseDeadlineToken outbound_protocol_deadline =
        stream->StartPhaseDeadline(handshake_timeout);

    std::array<uint8_t, kRequestPrefixSize + common::kMaxEncodedAddressSize + 2> header_buf{};
    common::ScopedCleanse cleanse_header{header_buf};
    const size_t header_len = EncodeRequestTo(
        config.password_hash,
        is_udp ? TrojanCommand::UDP_ASSOCIATE
               : TrojanCommand::CONNECT,
        ctx.outbound.target,
        header_buf.data(),
        header_buf.size(),
        dialer.ForwardedMetadata(ctx));
    if (header_len == 0) {
        LOG_CONN_WARN(ctx, "handshake encode failed");
        stream->CloseAbortive();
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    try {
        const net::const_buffer header_buffer(header_buf.data(), header_len);
        co_await stream->WriteBuffers({&header_buffer, 1});
        LOG_CONN_DEBUG(ctx, "handshake sent {} bytes", header_len);
        co_return std::move(stream);
    } catch (...) {
        const auto err = proxy::ClassifyOutboundHandshakeException(
            *stream, outbound_protocol_deadline);
        stream->CloseAbortive();
        co_return tl::unexpected(err);
    }
}
}  // namespace

// ============================================================================
// proxy/trojan/outbound.Handler 实现
// ============================================================================

TrojanOutboundHandler::TrojanOutboundHandler(
    std::shared_ptr<const TrojanOutboundConfig> config)
    : config_(std::move(config)) {}

net::awaitable<OutboundProcessResult>
TrojanOutboundHandler::Process(
    common::Context& ctx,
    transport::Link inbound,
    transport::OutboundDialer& dialer,
    const infra::TimeoutsConfig& timeouts,
    app::StatsShard& stats,
    const app::RelayConfig& relay_config,
    common::MultiBufferBatch first_payload) {
    if (ctx.content.network == common::Network::UDP) {
        return ProcessUdp(
            ctx, inbound, dialer, timeouts, stats, relay_config, std::move(first_payload));
    }
    return ProcessTcp(
        ctx, inbound, dialer, timeouts, stats, relay_config, std::move(first_payload));
}

net::awaitable<OutboundProcessResult>
TrojanOutboundHandler::ProcessUdp(
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
    std::unique_ptr<transport::AsyncStream> stream;
    {
        auto dialed = co_await DialAndSendTrojanHandshake(
            ctx, dialer, *config_, true, timeouts.HandshakeTimeout());
        if (!dialed) {
            co_return tl::unexpected(dialed.error());
        }
        stream = std::move(*dialed);
    }
    proxy::ApplyOutboundRelayTimeouts(*stream, relay_config);
    TrojanUdpStreamEndpoint udp_endpoint(
        *stream, ctx.outbound.target, transport::EofAction::WaitForPeer);
    co_return co_await app::DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        udp_endpoint, ctx, stats, relay_config, std::move(first_payload));
}

net::awaitable<OutboundProcessResult>
TrojanOutboundHandler::ProcessTcp(
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
    std::unique_ptr<transport::AsyncStream> stream;
    {
        auto dialed = co_await DialAndSendTrojanHandshake(
            ctx, dialer, *config_, false, timeouts.HandshakeTimeout());
        if (!dialed) {
            co_return tl::unexpected(dialed.error());
        }
        stream = std::move(*dialed);
    }
    proxy::ApplyOutboundRelayTimeouts(*stream, relay_config);
    co_return co_await app::DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        *stream, ctx, stats, relay_config, std::move(first_payload));
}


// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kTrojanRegistered = (::app::RegisterProxy(
    ::common::kTrojan,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::app::PreparedOutboundProxy> {
        const auto* settings = std::get_if<::infra::TrojanSettings>(&cfg.settings);
        if (!settings) return std::nullopt;
        auto next_hop = ::proxy::PrepareNextHop(
            cfg, settings->server,
            ::transport::OutboundStreamDefaults{
                .require_tls = true,
                .fallback_server_name = settings->server_name,
                .allow_insecure = settings->allow_insecure,
                .alpn = settings->alpn,
            });

        return ::app::PreparedOutboundProxy{
            .create = ::app::MakePreparedOutboundCreator<
                ::proxy::TrojanOutboundConfig,
                +[](std::string_view,
                    std::shared_ptr<const ::proxy::TrojanOutboundConfig> cfg_state,
                    ::net::io_context& /*io_context*/,
                    ::common::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::proxy::Outbound> {
                    return std::make_unique<::proxy::TrojanOutboundHandler>(
                        std::move(cfg_state));
                }>(::proxy::TrojanOutboundConfig(
                    std::move(next_hop.server),
                    ::proxy::HashTrojanPassword(settings->password))),
            .sender = std::move(next_hop.sender),
        };
    }), true);
}  // namespace

}  // namespace proxy
