#include "acppnode/proxy/trojan/outbound/trojan_outbound.hpp"
#include "../trojan_codec.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"

#include <algorithm>
#include <array>
#include <cstring>

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
    IoErrorCode addr_ec;
    auto literal_addr = net::ip::make_address(config_.address, addr_ec);
    if (!addr_ec) {
        config_.literal_address = literal_addr;
    }

    config_.stream_settings.RecomputeModes();
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
    (void)inbound_local_addr;
    if (!inbound.Valid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const auto& target = ctx.outbound.target;

    OutboundTransportTarget transport_target;
    transport_target.timeout = config_.timeout;
    transport_target.stream_settings = &config_.stream_settings;
    if (config_.literal_address) {
        transport_target.single_candidate = OutboundDialCandidate{
            .endpoint = tcp::endpoint(*config_.literal_address, config_.port),
            .bind_local = std::nullopt
        };
    } else {
        auto dns_result = co_await dns_service_.Resolve(config_.address);
        if (!dns_result.Ok()) {
            LOG_CONN_DEBUG(ctx, "[TrojanOutbound] DNS resolve failed for {}", config_.address);
            co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
        }

        if (dns_result.addresses.size() == 1) {
            transport_target.single_candidate = OutboundDialCandidate{
                .endpoint = tcp::endpoint(dns_result.addresses.front(), config_.port),
                .bind_local = std::nullopt
            };
        } else {
            transport_target.candidates.reserve(dns_result.addresses.size());
            for (const auto& addr : dns_result.addresses) {
                transport_target.candidates.push_back(OutboundDialCandidate{
                    .endpoint = tcp::endpoint(addr, config_.port),
                    .bind_local = std::nullopt
                });
            }
        }
    }
    transport_target.server_name = config_.GetServerName();

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_FAIL_CTX(ctx, "[TrojanOutbound] dial failed {} -> {} via {}: {}",
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

    std::array<uint8_t, 512> header{};
    size_t header_len = ::acpp::trojan::TrojanCodec::EncodeRequestTo(
        config_.password, ::acpp::trojan::TrojanCommand::CONNECT, target,
        header.data(), header.size());
    if (header_len == 0) {
        LOG_CONN_FAIL_CTX(ctx, "TrojanOutbound: Handshake encode failed");
        stream->Cancel();
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    try {
        if (!co_await WriteFull(*stream, header.data(), header_len)) {
            LOG_CONN_FAIL_CTX(ctx, "TrojanOutbound: Handshake write failed");
            stream->Cancel();
            co_return std::unexpected(outbound_protocol_deadline.Expired()
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
                stream->Cancel();
                co_return std::unexpected(outbound_protocol_deadline.Expired()
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
        stream->Cancel();
        co_return std::unexpected(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : MapAsioError(e.code()));
    } catch (...) {
        stream->Cancel();
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
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
        trojan_config.stream_settings.RecomputeModes();
        if (!trojan_config.stream_settings.IsTls()) {
            trojan_config.stream_settings.security = std::string(acpp::constants::protocol::kTls);
            trojan_config.stream_settings.RecomputeModes();
        }
        if (trojan_config.stream_settings.tls.server_name.empty()) {
            trojan_config.stream_settings.tls.server_name = std::string(trojan_config.GetServerName());
        }
        if (trojan_config.allow_insecure) {
            trojan_config.stream_settings.tls.allow_insecure = true;
        }
        if (!trojan_config.alpn.empty() && trojan_config.stream_settings.tls.alpn.empty()) {
            trojan_config.stream_settings.tls.alpn = trojan_config.alpn;
        }

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
