#include "acppnode/proxy/shadowsocks/outbound/ss_outbound.hpp"
#include "../client.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace acpp {

net::awaitable<OutboundProcessResult> proxy::shadowsocks::outbound::Handler::Process(
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
    (void)relay_config;
    if (!inbound.Valid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const auto& target = ctx.outbound.target;

    OutboundTransportTarget transport_target;
    transport_target.timeout = config_.timeout;
    transport_target.stream_settings = &stream_settings_;
    if (config_.literal_address) {
        transport_target.single_candidate = OutboundDialCandidate{
            .endpoint = tcp::endpoint(*config_.literal_address, config_.port),
            .bind_local = std::nullopt
        };
    } else {
        auto dns_result = co_await dns_service_.Resolve(config_.address);
        if (!dns_result.Ok()) {
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

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_FAIL_CTX(ctx, "[SsOutbound] dial failed {} -> {} via {}: {}",
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

    auto request_writer_result = co_await ss::WriteTCPRequest(
        target, cipher_info_, master_key_, *stream);
    if (!request_writer_result) {
        stream->Cancel();
        co_return std::unexpected(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : request_writer_result.error());
    }
    auto request_writer = std::move(request_writer_result.value());

    uint64_t prewritten_bytes = 0;
    try {
        if (buf::TotalLen(first_payload) > 0) {
            const size_t first_payload_size = buf::TotalLen(first_payload);
            co_await request_writer->WriteMultiBuffer(std::move(first_payload));
            first_payload.clear();
            prewritten_bytes += first_payload_size;
            stats.AddBytesOut(first_payload_size);
            ctx.traffic.bytes_up = prewritten_bytes;
        }

        if (!initial_payload.empty()) {
            buf::MultiBuffer initial_mb;
            initial_mb.reserve((initial_payload.size() + buf::Buffer::kSize - 1) /
                               buf::Buffer::kSize);

            size_t offset = 0;
            while (offset < initial_payload.size()) {
                buf::BufferGuard out{buf::Buffer::New()};
                if (!out) {
                    throw std::bad_alloc();
                }
                const size_t chunk = std::min(
                    initial_payload.size() - offset,
                    static_cast<size_t>(out->Available()));
                std::memcpy(
                    out->Tail().data(),
                    initial_payload.data() + offset,
                    chunk);
                out->Produce(static_cast<uint32_t>(chunk));
                initial_mb.push_back(out.release());
                offset += chunk;
            }

            const size_t initial_payload_size = initial_payload.size();
            co_await request_writer->WriteMultiBuffer(std::move(initial_mb));
            prewritten_bytes += initial_payload_size;
            stats.AddBytesOut(initial_payload_size);
            ctx.traffic.bytes_up = prewritten_bytes;
        }
    } catch (const IoSystemError& e) {
        stream->Cancel();
        co_return std::unexpected(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : MapAsioError(e.code()));
    } catch (const std::bad_alloc&) {
        stream->Cancel();
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (...) {
        stream->Cancel();
        co_return std::unexpected(ErrorCode::RELAY_WRITE_FAILED);
    }

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    auto upload = [&]() -> net::awaitable<std::pair<uint64_t, ErrorCode>> {
        uint64_t bytes = prewritten_bytes;
        while (true) {
            try {
                buf::MultiBuffer mb = co_await inbound.reader->ReadMultiBuffer();
                if (mb.empty()) {
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                const size_t n = buf::TotalLen(mb);
                co_await request_writer->WriteMultiBuffer(std::move(mb));
                bytes += n;
                ctx.traffic.bytes_up = bytes;
                stats.AddBytesOut(n);
            } catch (const IoSystemError& e) {
                co_return std::make_pair(bytes, MapAsioError(e.code()));
            } catch (...) {
                co_return std::make_pair(bytes, ErrorCode::RELAY_WRITE_FAILED);
            }
        }
    };

    auto download = [&]() -> net::awaitable<std::pair<uint64_t, ErrorCode>> {
        uint64_t bytes = 0;
        auto response_reader_result = co_await ss::ReadTCPResponse(
            cipher_info_, master_key_, *stream);
        if (!response_reader_result) {
            co_return std::make_pair(
                bytes,
                response_reader_result.error() == ErrorCode::OK
                    ? ErrorCode::SOCKET_READ_FAILED
                    : response_reader_result.error());
        }
        auto response_reader = std::move(response_reader_result.value());

        while (true) {
            try {
                buf::MultiBuffer mb = co_await response_reader->ReadMultiBuffer();
                if (mb.empty()) {
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                const size_t n = buf::TotalLen(mb);
                co_await inbound.writer->WriteMultiBuffer(std::move(mb));
                bytes += n;
                ctx.traffic.bytes_down = bytes;
                stats.AddBytesIn(n);
            } catch (const IoSystemError& e) {
                co_return std::make_pair(bytes, MapAsioError(e.code()));
            } catch (...) {
                co_return std::make_pair(bytes, ErrorCode::RELAY_WRITE_FAILED);
            }
        }
    };

    using namespace net::experimental::awaitable_operators;
    auto [up, down] = co_await (upload() && download());

    RelayResult result;
    result.bytes_up = up.first;
    result.bytes_down = down.first;
    result.client_closed_first = up.second != ErrorCode::OK;
    if (up.second != ErrorCode::OK) {
        result.error = up.second;
    } else if (down.second != ErrorCode::OK) {
        result.error = down.second;
    }
    ctx.traffic.bytes_up = result.bytes_up;
    ctx.traffic.bytes_down = result.bytes_down;

    if (result.error != ErrorCode::OK) {
        stream->Cancel();
    } else {
        try { co_await inbound.writer->AsyncShutdownWrite(); } catch (...) {}
        stream->Cancel();
    }
    co_return result;
}

proxy::shadowsocks::outbound::Handler::Handler(const SsOutboundConfig& config,
                                               ::acpp::app::dns::DNS& dns_service)
    : config_(config)
    , dns_service_(dns_service) {
    IoErrorCode addr_ec;
    auto literal_addr = net::ip::make_address(config_.address, addr_ec);
    if (!addr_ec) {
        config_.literal_address = literal_addr;
    }

    auto info = ss::ParseCipherMethod(config_.method);
    if (info) {
        cipher_info_ = *info;
    } else {
        LOG_WARN("[SsOutbound] Unknown cipher '{}', fallback to {}",
                 config_.method,
                 acpp::constants::protocol::kAes256Gcm);
        cipher_info_ = ss::SsCipherInfo{ss::SsCipherType::AES_256_GCM, 32, 32};
    }

    master_key_ = ss::DeriveKey(config_.password, cipher_info_.key_size);
    stream_settings_ = config_.stream_settings;
    stream_settings_.RecomputeModes();
    if (stream_settings_.network.empty()) {
        stream_settings_.network = std::string(acpp::constants::protocol::kTcp);
        stream_settings_.security = std::string(acpp::constants::protocol::kNone);
        stream_settings_.RecomputeModes();
    }
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kSsOutboundRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kShadowsocks,
    [](const acpp::proxyman::outbound::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundConfig> {
        const auto* servers_p = cfg.settings.if_contains("servers");
        if (!servers_p || !servers_p->is_array() || servers_p->as_array().empty()) {
            return std::nullopt;
        }
        const auto& first_server = servers_p->as_array()[0];
        if (!first_server.is_object()) {
            return std::nullopt;
        }
        const auto& srv = first_server.as_object();

        acpp::SsOutboundConfig ss_config;
        ss_config.tag     = cfg.tag;
        if (const auto* v = srv.if_contains("address"); v && v->is_string()) {
            ss_config.address = std::string(v->as_string());
        }
        if (const auto* v = srv.if_contains("port"); v) {
            if (v->is_uint64()) {
                ss_config.port = static_cast<uint16_t>(v->as_uint64());
            } else if (v->is_int64()) {
                ss_config.port = static_cast<uint16_t>(v->as_int64());
            }
        }
        if (const auto* v = srv.if_contains("password"); v && v->is_string()) {
            ss_config.password = std::string(v->as_string());
        }
        if (const auto* v = srv.if_contains("method"); v && v->is_string()) {
            ss_config.method = std::string(v->as_string());
        }
        ss_config.stream_settings = cfg.stream_settings;
        ss_config.stream_settings.RecomputeModes();
        if (ss_config.stream_settings.network.empty()) {
            ss_config.stream_settings.network = std::string(acpp::constants::protocol::kTcp);
            ss_config.stream_settings.security = std::string(acpp::constants::protocol::kNone);
            ss_config.stream_settings.RecomputeModes();
        }

        if (ss_config.address.empty() || ss_config.password.empty()) {
            return std::nullopt;
        }
        acpp::proxyman::outbound::PreparedOutboundConfig prepared;
        prepared.tag = cfg.tag;
        prepared.protocol = cfg.protocol;
        prepared.create =
            [ss_config = std::move(ss_config)](
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns_service,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_config = ss_config;
                runtime_config.timeout = timeout;
                return std::make_unique<acpp::proxy::shadowsocks::outbound::Handler>(
                    runtime_config, dns_service);
            };
        return prepared;
    }), true);
}  // namespace
