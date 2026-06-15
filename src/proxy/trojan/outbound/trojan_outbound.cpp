#include "acppnode/proxy/trojan/outbound/trojan_outbound.hpp"
#include "../trojan_codec.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <span>

namespace acpp {

namespace {

net::awaitable<bool> WriteFull(AsyncStream& stream, const uint8_t* buf, size_t len) {
    if (len == 0) {
        co_return true;
    }

    buf::MultiBuffer mb;
    mb.reserve((len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);

    size_t offset = 0;
    while (offset < len) {
        buf::BufferGuard out{buf::Buffer::New()};
        if (!out) {
            co_return false;
        }
        const size_t chunk = std::min(
            len - offset,
            static_cast<size_t>(out->Available()));
        std::memcpy(out->Tail().data(), buf + offset, chunk);
        out->Produce(static_cast<uint32_t>(chunk));
        mb.push_back(out.release());
        offset += chunk;
    }

    try {
        co_await stream.WriteMultiBuffer(std::move(mb));
        mb.clear();
    } catch (...) {
        co_return false;
    }
    co_return true;
}

}  // namespace

// ============================================================================
// proxy/trojan/outbound.Handler 实现
// ============================================================================

proxy::trojan::outbound::Handler::Handler(const TrojanOutboundConfig& config,
                                          ::acpp::app::dns::DNS& dns_service)
    : config_(config)
    , dns_service_(dns_service) {
    config_.literal_address = ParseLiteralAddress(config_.address);
    NormalizeOutboundStreamSettings(
        config_.stream_settings,
        OutboundStreamDefaults{
            .require_tls = true,
            .fallback_server_name = config_.GetServerName(),
            .allow_insecure = config_.allow_insecure,
            .alpn = std::span<const std::string>(config_.alpn.data(), config_.alpn.size()),
        });
}

proxy::trojan::outbound::Handler::~Handler() = default;

net::awaitable<OutboundProcessResult>
proxy::trojan::outbound::Handler::Process(
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
        .stream_settings = &config_.stream_settings,
        .timeout = config_.timeout,
        .send_through = config_.send_through,
        .inbound_local_addr = inbound_local_addr,
        .server_name = ResolveOutboundServerName(config_.stream_settings, config_.GetServerName()),
    });
    if (!transport_target) {
        if (transport_target.error() == ErrorCode::DNS_RESOLVE_FAILED) {
            LOG_CONN_DEBUG(ctx, "[TrojanOutbound] DNS resolve failed for {}", config_.address);
        }
        co_return std::unexpected(transport_target.error());
    }

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_FAIL_CTX(ctx, "[TrojanOutbound] dial failed {} -> {} via {}: {}",
                          ctx.inbound.source_ip, ctx.outbound.target,
                          ctx.outbound.tag, dial_result.error_msg);
        co_return std::unexpected(dial_result.error);
    }

    auto stream = std::move(dial_result.stream);
    stream->SetStreamLabel("out");
    LOG_ACCESS(FormatAccessLog(ctx));
    auto fail_abortive = [&](ErrorCode error) {
        if (stream) {
            stream->CloseAbortive();
        }
        return std::unexpected(error);
    };

    stream->SetIdleTimeout(timeouts.HandshakeTimeout());
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

    std::array<uint8_t, 512> header{};
    size_t header_len = ::acpp::trojan::TrojanCodec::EncodeRequestTo(
        config_.password, ::acpp::trojan::TrojanCommand::CONNECT, target,
        header.data(), header.size());
    if (header_len == 0) {
        LOG_CONN_FAIL_CTX(ctx, "TrojanOutbound: Handshake encode failed");
        co_return fail_abortive(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    try {
        if (!co_await WriteFull(*stream, header.data(), header_len)) {
            LOG_CONN_FAIL_CTX(ctx, "TrojanOutbound: Handshake write failed");
            co_return fail_abortive(outbound_protocol_deadline.Expired()
                ? ErrorCode::TIMEOUT
                : ErrorCode::SOCKET_WRITE_FAILED);
        }

        uint64_t prewritten_bytes = 0;
        if (buf::TotalLen(first_payload) > 0) {
            const size_t first_payload_size = buf::TotalLen(first_payload);
            co_await stream->WriteMultiBuffer(std::move(first_payload));
            first_payload.clear();
            prewritten_bytes += first_payload_size;
            stats.AddBytesOut(first_payload_size);
            ctx.traffic.bytes_up = prewritten_bytes;
        }

        if (!initial_payload.empty()) {
            if (!co_await WriteFull(*stream, initial_payload.data(), initial_payload.size())) {
                LOG_CONN_FAIL_CTX(ctx, "TrojanOutbound: initial payload write failed");
                co_return fail_abortive(outbound_protocol_deadline.Expired()
                    ? ErrorCode::TIMEOUT
                    : ErrorCode::SOCKET_WRITE_FAILED);
            }
            prewritten_bytes += initial_payload.size();
            stats.AddBytesOut(initial_payload.size());
            ctx.traffic.bytes_up = prewritten_bytes;
        }

        LOG_CONN_DEBUG(ctx, "[Trojan] Handshake sent {} bytes", header_len);
        stream->SetIdleTimeout(relay_idle_timeout);
        stream->SetReadTimeout(std::chrono::seconds(0));
        stream->SetWriteTimeout(relay_write_timeout);
        stream->ClearPhaseDeadline();

        RelayResult result;
        if (inbound.control) {
            result = co_await DoRelayLink(
                io_context, *inbound.reader, *inbound.writer, *inbound.control,
                *stream, ctx, stats, relay_config);
        } else {
            result = co_await DoRelayLink(
                io_context, *inbound.reader, *inbound.writer, *stream, ctx, stats, relay_config);
        }
        result.bytes_up += prewritten_bytes;
        ctx.traffic.bytes_up = result.bytes_up;
        co_return result;
    } catch (const IoSystemError& e) {
        co_return fail_abortive(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : MapAsioError(e.code()));
    } catch (...) {
        co_return fail_abortive(ErrorCode::SOCKET_WRITE_FAILED);
    }
}

// ============================================================================
// 工厂函数
// ============================================================================

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kTrojanRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kTrojan,
    [](const acpp::proxyman::outbound::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundConfig> {
        const auto& s = cfg.settings;

        acpp::TrojanOutboundConfig trojan_config;
        trojan_config.tag     = cfg.tag;

        // Xray 格式: servers[0] 包含 address/port/password 等
        const auto* servers_p = s.if_contains("servers");
        if (!servers_p || !servers_p->is_array() || servers_p->as_array().empty()) {
            return std::nullopt;
        }
        const auto& first_server = servers_p->as_array()[0];
        if (!first_server.is_object()) {
            return std::nullopt;
        }
        const auto& srv = first_server.as_object();
        if (const auto* v = srv.if_contains("address"); v && v->is_string()) {
            trojan_config.address = std::string(v->as_string());
        }
        if (const auto* v = srv.if_contains("port"); v) {
            if (v->is_uint64()) {
                trojan_config.port = static_cast<uint16_t>(v->as_uint64());
            } else if (v->is_int64()) {
                trojan_config.port = static_cast<uint16_t>(v->as_int64());
            }
        }
        if (const auto* v = srv.if_contains("password"); v && v->is_string()) {
            trojan_config.password = std::string(v->as_string());
        }
        if (const auto* v = srv.if_contains("serverName"); v && v->is_string()) {
            trojan_config.server_name = std::string(v->as_string());
        }
        if (const auto* v = srv.if_contains("allowInsecure"); v && v->is_bool()) {
            trojan_config.allow_insecure = v->as_bool();
        }
        trojan_config.stream_settings = cfg.stream_settings;
        trojan_config.send_through = cfg.send_through;
        acpp::NormalizeOutboundStreamSettings(
            trojan_config.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = true,
                .fallback_server_name = trojan_config.GetServerName(),
                .allow_insecure = trojan_config.allow_insecure,
                .alpn = std::span<const std::string>(
                    trojan_config.alpn.data(),
                    trojan_config.alpn.size()),
            });

        if (trojan_config.address.empty() || trojan_config.password.empty()) {
            return std::nullopt;  // 配置不完整
        }

        acpp::proxyman::outbound::PreparedOutboundConfig prepared;
        prepared.tag = cfg.tag;
        prepared.protocol = cfg.protocol;
        prepared.create =
            [trojan_config = std::move(trojan_config)](
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_config = trojan_config;
                runtime_config.timeout = timeout;
                return std::make_unique<acpp::proxy::trojan::outbound::Handler>(
                    runtime_config, dns);
            };
        return prepared;
    }), true);
}  // namespace
