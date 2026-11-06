#include "trojan_outbound.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "../trojan_codec.hpp"
#include "../udp_framing.hpp"
#include "../../handshake_timeout.hpp"
#include "../../outbound_server.hpp"
#include "../../outbound_stream_endpoint.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "acppnode/infra/json_field.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/link_error.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <span>
#include <utility>
#include <vector>

namespace acpp {

namespace {

class TrojanUdpOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    TrojanUdpOutboundEndpoint(AsyncStream& stream, TargetAddress fallback_target)
        : OutboundStreamEndpointBase(stream)
        , fallback_target_(std::move(fallback_target)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        return trojan::ReadUdpDatagram(stream_, framer_);
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return trojan::WriteUdpDatagram(stream_, std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return trojan::WriteUdpDatagram(
            stream_, fallback_target_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return stream_.AsyncShutdownWrite();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::WaitForPeer;
    }

private:
    TargetAddress fallback_target_;
    trojan::UdpFramer framer_;
};

net::awaitable<tl::expected<void, ErrorCode>>
SendTrojanHandshake(
    AsyncStream& stream,
    const TrojanOutboundConfig& config,
    const TargetAddress& target,
    bool is_udp,
    std::chrono::seconds handshake_timeout,
    session::Context& ctx) {
    stream.SetIdleTimeout(handshake_timeout);
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream.StartPhaseDeadline(handshake_timeout);

    std::array<uint8_t, 320> header_buf{};
    const size_t header_len = ::acpp::trojan::EncodeRequestTo(
        config.password_hash,
        is_udp ? ::acpp::trojan::TrojanCommand::UDP_ASSOCIATE
               : ::acpp::trojan::TrojanCommand::CONNECT,
        target,
        header_buf.data(),
        header_buf.size());
    if (header_len == 0) {
        LOG_CONN_WARN(ctx, "handshake encode failed");
        co_return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    try {
        ConstBufferSpanBuilder<1> header_buffers;
        header_buffers.Append(net::const_buffer(header_buf.data(), header_len));
        co_await stream.WriteBuffers(header_buffers.Span());
        LOG_CONN_DEBUG(ctx, "handshake sent {} bytes", header_len);
        co_return tl::expected<void, ErrorCode>{};
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

proxy::trojan::outbound::Handler::Handler(
    std::shared_ptr<const TrojanOutboundConfig> config)
    : config_(std::move(config)) {}

proxy::trojan::outbound::Handler::~Handler() = default;

net::awaitable<OutboundProcessResult>
proxy::trojan::outbound::Handler::Process(
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

    auto dialed = co_await dialer.Dial(ctx, config_->server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    auto fail_abortive = [&](ErrorCode error) {
        if (stream) {
            stream->CloseAbortive();
        }
        return tl::unexpected(error);
    };

    const bool is_udp = ctx.content.network == Network::UDP;
    if (auto ok = co_await SendTrojanHandshake(
            *stream, *config_, target, is_udp, timeouts.HandshakeTimeout(), ctx); !ok) {
        co_return fail_abortive(ok.error());
    }

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    try {
        if (is_udp) {
            TrojanUdpOutboundEndpoint target_endpoint(*stream, target);
            co_return co_await DoRelayLink(
                dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
                target_endpoint, ctx, stats, relay_config, std::move(first_payload));
        }

        co_return co_await DoRelayLink(
            dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
            *stream, ctx, stats, relay_config, std::move(first_payload));
    } catch (const IoSystemError& e) {
        co_return fail_abortive(MapAsioError(e.code()));
    } catch (const transport::LinkError& e) {
        co_return fail_abortive(e.code());
    } catch (const std::bad_alloc&) {
        co_return fail_abortive(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (...) {
        co_return fail_abortive(ErrorCode::INTERNAL);
    }
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kTrojanRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kTrojan,
    [](const acpp::infra::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundProxy> {
        const auto& s = cfg.settings;

        std::string address;
        uint16_t port = 443;
        std::string password;
        std::string server_name;
        bool allow_insecure = false;
        std::vector<std::string> alpn;
        // A present field of the wrong type is a configuration error, never
        // an implicit default.
        auto read_trojan_server = [&](const acpp::json::object& obj) {
            const auto fail = [&](std::string_view error) {
                LOG_ERROR("trojan outbound '{}': {}", cfg.tag, error);
                return false;
            };
            auto source_address = acpp::ParseJsonString(obj, "address");
            if (!source_address) return fail(source_address.error());
            const auto source_port = acpp::ReadJsonPort(obj, "port");
            if (source_port.Invalid()) return fail("invalid port");
            auto source_password = acpp::ParseJsonString(obj, "password");
            if (!source_password) return fail(source_password.error());
            auto source_server_name = acpp::ParseJsonString(obj, "serverName");
            if (!source_server_name) return fail(source_server_name.error());
            const auto source_allow_insecure = acpp::ParseJsonBool(obj, "allowInsecure");
            if (!source_allow_insecure) return fail(source_allow_insecure.error());
            auto source_alpn = acpp::ParseJsonStringArray(obj, "alpn");
            if (!source_alpn) return fail(source_alpn.error());

            address = std::move(*source_address).value_or(std::string{});
            if (source_port.Valid()) {
                port = source_port.value;
            }
            password = std::move(*source_password).value_or(std::string{});
            server_name = std::move(*source_server_name).value_or(std::string{});
            allow_insecure = source_allow_insecure->value_or(false);
            alpn = std::move(*source_alpn).value_or(std::vector<std::string>{});
            return true;
        };

        if (const auto* servers_p = s.if_contains("servers")) {
            if (!servers_p->is_array() ||
                servers_p->as_array().size() != 1 ||
                !servers_p->as_array()[0].is_object()) {
                LOG_ERROR("trojan outbound '{}': servers must be a single-element object array", cfg.tag);
                return std::nullopt;
            }
            if (!read_trojan_server(servers_p->as_array()[0].as_object())) {
                return std::nullopt;
            }
        } else if (!read_trojan_server(s)) {
            return std::nullopt;
        }
        if (password.empty()) {
            LOG_ERROR("trojan outbound '{}': password is required", cfg.tag);
            return std::nullopt;
        }
        auto next_hop = acpp::proxy::PrepareNextHop(
            cfg, std::move(address), port,
            acpp::OutboundStreamDefaults{
                .require_tls = true,
                .fallback_server_name = server_name,
                .allow_insecure = allow_insecure,
                .alpn = std::span<const std::string>(alpn.data(), alpn.size()),
            });
        if (!next_hop) {
            return std::nullopt;
        }

        return acpp::proxyman::outbound::PreparedOutboundProxy{
            .create = acpp::proxyman::outbound::MakePreparedOutboundCreator<
                acpp::TrojanOutboundConfig,
                +[](std::string_view,
                    std::shared_ptr<const acpp::TrojanOutboundConfig> cfg_state,
                    acpp::net::io_context& /*io_context*/,
                    acpp::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<acpp::Outbound> {
                    return std::make_unique<acpp::proxy::trojan::outbound::Handler>(
                        std::move(cfg_state));
                }>(acpp::TrojanOutboundConfig{
                    .server = std::move(next_hop->server),
                    .password_hash = acpp::trojan::HashPassword(password),
                }),
            .sender = std::move(next_hop->sender),
        };
    }), true);
}  // namespace
