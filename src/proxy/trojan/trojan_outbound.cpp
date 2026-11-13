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

    ~TrojanOutboundHandler() override;

    ::net::awaitable<::proxy::OutboundProcessResult> Process(
        ::common::Context& ctx,
        ::transport::Link inbound,
        ::transport::OutboundDialer& dialer,
        const ::infra::TimeoutsConfig& timeouts,
        ::app::StatsShard& stats,
        const ::app::RelayConfig& relay_config,
        ::common::MultiBufferBatch first_payload) override;

private:
    std::shared_ptr<const ::proxy::TrojanOutboundConfig> config_;
};
namespace {

net::awaitable<tl::expected<void, common::ErrorCode>>
SendTrojanHandshake(
    transport::AsyncStream& stream,
    const TrojanOutboundConfig& config,
    const common::TargetAddress& target,
    bool is_udp,
    std::chrono::seconds handshake_timeout,
    common::Context& ctx,
    const transport::OutboundDialer& dialer) {
    stream.SetIdleTimeout(handshake_timeout);
    transport::PhaseDeadlineToken outbound_protocol_deadline =
        stream.StartPhaseDeadline(handshake_timeout);

    std::array<uint8_t, kRequestPrefixSize + common::kMaxEncodedAddressSize + 2> header_buf{};
    common::ScopedCleanse cleanse_header{header_buf};
    const size_t header_len = EncodeRequestTo(
        config.password_hash,
        is_udp ? TrojanCommand::UDP_ASSOCIATE
               : TrojanCommand::CONNECT,
        target,
        header_buf.data(),
        header_buf.size(),
        dialer.ForwardedMetadata(ctx));
    if (header_len == 0) {
        LOG_CONN_WARN(ctx, "handshake encode failed");
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    try {
        const net::const_buffer header_buffer(header_buf.data(), header_len);
        co_await stream.WriteBuffers({&header_buffer, 1});
        LOG_CONN_DEBUG(ctx, "handshake sent {} bytes", header_len);
        co_return tl::expected<void, common::ErrorCode>{};
    } catch (...) {
        co_return tl::unexpected(
            proxy::ClassifyOutboundHandshakeException(
                stream, outbound_protocol_deadline));
    }
}

}  // namespace

// ============================================================================
// proxy/trojan/outbound.Handler 实现
// ============================================================================

TrojanOutboundHandler::TrojanOutboundHandler(
    std::shared_ptr<const TrojanOutboundConfig> config)
    : config_(std::move(config)) {}

TrojanOutboundHandler::~TrojanOutboundHandler() = default;

net::awaitable<OutboundProcessResult>
TrojanOutboundHandler::Process(
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

    const auto& target = ctx.outbound.target;

    auto dialed = co_await dialer.Dial(ctx, config_->server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    const bool is_udp = ctx.content.network == common::Network::UDP;
    if (auto ok = co_await SendTrojanHandshake(
            *stream, *config_, target, is_udp, timeouts.HandshakeTimeout(),
            ctx, dialer); !ok) {
        stream->CloseAbortive();
        co_return tl::unexpected(ok.error());
    }

    proxy::ApplyOutboundRelayTimeouts(*stream, relay_config);

    if (is_udp) {
        TrojanUdpStreamEndpoint udp_endpoint(
            *stream, target, transport::EofAction::WaitForPeer);
        co_return co_await app::DoRelayLink(
            dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
            udp_endpoint, ctx, stats, relay_config, std::move(first_payload));
    }

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
                }>([] (::transport::OutboundServer srv, const std::string& pwd) {
                    ::proxy::TrojanOutboundConfig cfg_val;
                    cfg_val.server = std::move(srv);
                    cfg_val.password_hash = ::proxy::HashTrojanPassword(pwd);
                    return cfg_val;
                }(std::move(next_hop.server), settings->password)),
            .sender = std::move(next_hop.sender),
        };
    }), true);
}  // namespace

}  // namespace proxy
