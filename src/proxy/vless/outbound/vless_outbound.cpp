#include "acppnode/proxy/vless/outbound/vless_outbound.hpp"

#include "../vless_codec.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/proxy/vless/validator.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/link.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <utility>

namespace acpp {

namespace {

[[nodiscard]] bool SameTargetAddress(const TargetAddress& lhs,
                                     const TargetAddress& rhs) {
    if (lhs.port != rhs.port) {
        return false;
    }
    if (lhs.IsDomain() || rhs.IsDomain()) {
        return lhs.IsDomain() && rhs.IsDomain() && lhs.host == rhs.host;
    }
    if (lhs.resolved_addr && rhs.resolved_addr) {
        return *lhs.resolved_addr == *rhs.resolved_addr;
    }
    return false;
}

net::awaitable<bool> ReadFull(AsyncStream& stream,
                              uint8_t* data,
                              size_t len) {
    size_t offset = 0;
    while (offset < len) {
        size_t n = 0;
        try {
            n = co_await stream.AsyncRead(net::buffer(data + offset, len - offset));
        } catch (...) {
            co_return false;
        }
        if (n == 0) {
            co_return false;
        }
        offset += n;
    }
    co_return true;
}

net::awaitable<bool> WriteFull(AsyncStream& stream,
                               const uint8_t* data,
                               size_t len) {
    size_t offset = 0;
    while (offset < len) {
        size_t n = 0;
        try {
            n = co_await stream.AsyncWrite(net::buffer(data + offset, len - offset));
        } catch (...) {
            co_return false;
        }
        if (n == 0) {
            co_return false;
        }
        offset += n;
    }
    co_return true;
}

class VlessUdpFramer {
public:
    void Feed(const uint8_t* data, size_t len) {
        while (len > 0) {
            if (!pending_) {
                pending_ = buf::BufferGuard{buf::Buffer::New()};
                if (!pending_) {
                    return;
                }
            }
            if (pending_->Available() == 0 && pending_->start > 0) {
                Compact();
            }
            if (pending_->Available() == 0) {
                ClearBuffer();
                return;
            }

            const size_t n = std::min<size_t>(len, pending_->Available());
            std::memcpy(pending_->Tail().data(), data, n);
            pending_->Produce(static_cast<uint32_t>(n));
            data += n;
            len -= n;
            Parse();
        }
    }

    bool Next(buf::BufferGuard& out) {
        if (queue_.empty()) {
            return false;
        }
        out = std::move(queue_.front());
        queue_.pop_front();
        if (queue_.empty()) {
            TryShrinkSequence(queue_);
        }
        return true;
    }

private:
    buf::BufferGuard pending_;
    memory::ThreadLocalDeque<buf::BufferGuard> queue_;

    void Compact() {
        if (!pending_ || pending_->start == 0) {
            return;
        }
        const uint32_t remaining = pending_->Len();
        if (remaining == 0) {
            ClearBuffer();
            return;
        }
        std::memmove(pending_->data, pending_->Bytes().data(), remaining);
        pending_->start = 0;
        pending_->end = remaining;
    }

    const uint8_t* Data() const {
        return pending_ ? pending_->Bytes().data() : nullptr;
    }

    size_t Size() const {
        return pending_ ? pending_->Len() : 0;
    }

    void ClearBuffer() {
        pending_ = buf::BufferGuard{};
    }

    void Parse() {
        while (Size() > 0) {
            auto parsed = vless::Codec::ParseUdpPacket(Data(), Size());
            if (parsed.result == vless::Codec::UdpParseResult::SUCCESS) {
                buf::BufferGuard payload{buf::Buffer::New()};
                if (payload && parsed.packet) {
                    const auto bytes = parsed.packet->payload;
                    const size_t n = std::min<size_t>(
                        bytes.size(),
                        static_cast<size_t>(payload->Available()));
                    std::memcpy(payload->Tail().data(), bytes.data(), n);
                    payload->Produce(static_cast<uint32_t>(n));
                    queue_.push_back(std::move(payload));
                }
                pending_->Advance(static_cast<uint32_t>(parsed.consumed));
                continue;
            }
            if (parsed.result == vless::Codec::UdpParseResult::INCOMPLETE) {
                break;
            }
            pending_->Advance(1);
            if (Size() < 2) {
                ClearBuffer();
                break;
            }
        }

        if (pending_ && pending_->IsEmpty()) {
            ClearBuffer();
        }
    }
};

class VlessOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    VlessOutboundEndpoint(AsyncStream& stream,
                          bool is_udp,
                          TargetAddress udp_target)
        : stream_(stream)
        , is_udp_(is_udp)
        , udp_target_(std::move(udp_target)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_header_read_) {
            if (!co_await ReadResponseHeader()) {
                throw IoSystemError(
                    io_error::connection_reset,
                    "VLESS response header read failed");
            }
            response_header_read_ = true;
        }

        if (!is_udp_) {
            co_return co_await stream_.ReadMultiBuffer();
        }

        while (true) {
            buf::MultiBuffer out;
            buf::BufferGuard pkt;
            while (framer_.Next(pkt)) {
                if (!pkt || pkt->IsEmpty()) {
                    continue;
                }
                pkt->SetUDP(udp_target_);
                out.push_back(pkt.release());
            }
            if (!out.empty()) {
                co_return out;
            }

            buf::MultiBuffer raw = co_await stream_.ReadMultiBuffer();
            if (raw.empty()) {
                co_return buf::MultiBuffer{};
            }
            for (buf::Buffer* buffer : raw) {
                if (buffer && !buffer->IsEmpty()) {
                    framer_.Feed(buffer->Bytes().data(), buffer->Len());
                }
            }
            raw.clear();
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!is_udp_) {
            co_await stream_.WriteMultiBuffer(std::move(mb));
            co_return;
        }

        buf::MultiBuffer out;
        for (buf::Buffer*& buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            if (buffer->HasUDP() && !SameTargetAddress(buffer->udp, udp_target_)) {
                buf::Buffer::Free(buffer);
                buffer = nullptr;
                continue;
            }
            buf::BufferGuard framed{buf::Buffer::New()};
            if (!framed) {
                break;
            }
            const size_t written = vless::Codec::EncodeUdpPacketTo(
                buffer->Bytes().data(),
                buffer->Len(),
                framed->Tail().data(),
                framed->Available());
            if (written == 0) {
                continue;
            }
            framed->Produce(static_cast<uint32_t>(written));
            out.push_back(framed.release());
        }
        mb.clear();
        if (!out.empty()) {
            co_await stream_.WriteMultiBuffer(std::move(out));
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        stream_.ShutdownWrite();
        co_return;
    }

    void SetIdleTimeout(std::chrono::seconds timeout) {
        stream_.SetIdleTimeout(timeout);
    }

    void SetReadTimeout(std::chrono::seconds timeout) {
        stream_.SetReadTimeout(timeout);
    }

    void SetWriteTimeout(std::chrono::seconds timeout) {
        stream_.SetWriteTimeout(timeout);
    }

    bool ConsumeIdleTimeout() noexcept {
        return stream_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return stream_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return stream_.ConsumeWriteTimeout();
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        return stream_.StartPhaseDeadline(timeout);
    }

    void ClearPhaseDeadline() {
        stream_.ClearPhaseDeadline();
    }

    bool ConsumePhaseDeadline() noexcept {
        return stream_.ConsumePhaseDeadline();
    }

    void Cancel() noexcept {
        stream_.Cancel();
    }

    void SetAbortiveClose(bool enable = true) noexcept {
        stream_.SetAbortiveClose(enable);
    }

private:
    net::awaitable<bool> ReadResponseHeader() {
        uint8_t fixed[2]{};
        if (!co_await ReadFull(stream_, fixed, sizeof(fixed))) {
            co_return false;
        }
        if (fixed[0] != vless::kVersion) {
            co_return false;
        }
        const size_t addons_len = fixed[1];
        if (addons_len > 0) {
            std::array<uint8_t, 255> addons{};
            if (!co_await ReadFull(stream_, addons.data(), addons_len)) {
                co_return false;
            }
        }
        co_return true;
    }

    AsyncStream& stream_;
    bool response_header_read_ = false;
    bool is_udp_ = false;
    TargetAddress udp_target_;
    VlessUdpFramer framer_;
};

}  // namespace

proxy::vless::outbound::Handler::Handler(const VlessOutboundConfig& config,
                                         ::acpp::app::dns::DNS& dns_service)
    : config_(config)
    , dns_service_(dns_service) {
    config_.literal_address = ParseLiteralAddress(config_.address);
    config_.flow = ::acpp::vless::NormalizeFlow(config_.flow);
    if (auto uuid_bytes = ::acpp::vless::ParseUuidBytes(config_.uuid)) {
        config_.uuid_bytes = *uuid_bytes;
        config_valid_ = config_.flow.empty();
    }
    if (!config_valid_) {
        LOG_ERROR("VLESS outbound '{}': invalid UUID or unsupported flow '{}'",
                  config_.tag, config_.flow);
    }

    NormalizeOutboundStreamSettings(
        config_.stream_settings,
        OutboundStreamDefaults{
            .require_tls = false,
            .fallback_server_name = config_.address,
            .allow_insecure = false,
            .alpn = {},
        });
}

proxy::vless::outbound::Handler::~Handler() = default;

net::awaitable<OutboundProcessResult>
proxy::vless::outbound::Handler::Process(
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
    if (!config_valid_) {
        co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
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
        .tls_server_name = ResolveOutboundTlsServerName(
            config_.stream_settings, config_.address),
        .ws_host = config_.address,
    });
    if (!transport_target) {
        if (transport_target.error() == ErrorCode::DNS_RESOLVE_FAILED) {
            LOG_CONN_FAIL_CTX(ctx, "[VLESS] DNS resolve failed for {}", config_.address);
        }
        co_return std::unexpected(transport_target.error());
    }

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_FAIL_CTX(ctx, "[VLESS] dial failed {} -> {} via {}: {}",
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

    const bool is_udp = ctx.content.network == Network::UDP;
    std::array<uint8_t, 512> header{};
    const size_t header_len = ::acpp::vless::Codec::EncodeRequestHeaderTo(
        config_.uuid_bytes,
        is_udp ? ::acpp::vless::Command::UDP : ::acpp::vless::Command::TCP,
        target,
        header.data(),
        header.size());
    if (header_len == 0) {
        co_return fail_abortive(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    if (!co_await WriteFull(*stream, header.data(), header_len)) {
        co_return fail_abortive(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : ErrorCode::SOCKET_WRITE_FAILED);
    }

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    VlessOutboundEndpoint target_endpoint(*stream, is_udp, target);
    if (buf::TotalLen(first_payload) > 0) {
        if (inbound.control) {
            co_return co_await DoRelayLinkWithFirstPacket(
                io_context, *inbound.reader, *inbound.writer, *inbound.control,
                target_endpoint, ctx, stats, first_payload, relay_config);
        }
        co_return co_await DoRelayLinkWithFirstPacket(
            io_context, *inbound.reader, *inbound.writer, target_endpoint,
            ctx, stats, first_payload, relay_config);
    }
    if (!initial_payload.empty()) {
        if (inbound.control) {
            co_return co_await DoRelayLinkWithFirstPacket(
                io_context, *inbound.reader, *inbound.writer, *inbound.control,
                target_endpoint, ctx, stats, initial_payload, relay_config);
        }
        co_return co_await DoRelayLinkWithFirstPacket(
            io_context, *inbound.reader, *inbound.writer, target_endpoint,
            ctx, stats, initial_payload, relay_config);
    }
    if (inbound.control) {
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer, *inbound.control,
            target_endpoint, ctx, stats, relay_config);
    }
    co_return co_await DoRelayLink(
        io_context, *inbound.reader, *inbound.writer,
        target_endpoint, ctx, stats, relay_config);
}

}  // namespace acpp

namespace {
const bool kVlessRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kVless,
    [](const acpp::proxyman::outbound::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundConfig> {
        auto json_string = [](const acpp::json::object& obj,
                              std::string_view key) -> std::string {
            if (const auto* v = obj.if_contains(key); v && v->is_string()) {
                return std::string(v->as_string());
            }
            return {};
        };
        auto json_port = [](const acpp::json::object& obj,
                            std::string_view key,
                            uint16_t fallback = 0) -> uint16_t {
            if (const auto* v = obj.if_contains(key); v) {
                if (v->is_uint64()) {
                    return static_cast<uint16_t>(v->as_uint64());
                }
                if (v->is_int64()) {
                    return static_cast<uint16_t>(v->as_int64());
                }
            }
            return fallback;
        };

        acpp::VlessOutboundConfig vless_config;
        vless_config.tag = cfg.tag;

        const auto& s = cfg.settings;
        if (const auto* vnext_p = s.if_contains("vnext");
                vnext_p && vnext_p->is_array() && !vnext_p->as_array().empty() &&
                vnext_p->as_array()[0].is_object()) {
            const auto& server = vnext_p->as_array()[0].as_object();
            vless_config.address = json_string(server, "address");
            vless_config.port = json_port(server, "port", vless_config.port);

            if (const auto* users_p = server.if_contains("users");
                    users_p && users_p->is_array() && !users_p->as_array().empty() &&
                    users_p->as_array()[0].is_object()) {
                const auto& user = users_p->as_array()[0].as_object();
                vless_config.uuid = json_string(user, "id");
                if (vless_config.uuid.empty()) {
                    vless_config.uuid = json_string(user, "uuid");
                }
                vless_config.flow = json_string(user, "flow");
            }
        } else {
            vless_config.address = json_string(s, "server");
            if (vless_config.address.empty()) {
                vless_config.address = json_string(s, "address");
            }
            vless_config.port = json_port(s, "server_port", json_port(s, "port", vless_config.port));
            vless_config.uuid = json_string(s, "uuid");
            if (vless_config.uuid.empty()) {
                vless_config.uuid = json_string(s, "id");
            }
            vless_config.flow = json_string(s, "flow");
        }

        if (const auto* packet = s.if_contains("packet_encoding");
                packet && packet->is_string() && !packet->as_string().empty()) {
            LOG_WARN("VLESS outbound '{}': packet_encoding '{}' is not supported",
                     cfg.tag, packet->as_string());
            return std::nullopt;
        }
        if (const auto* packet = s.if_contains("packetEncoding");
                packet && packet->is_string() && !packet->as_string().empty()) {
            LOG_WARN("VLESS outbound '{}': packetEncoding '{}' is not supported",
                     cfg.tag, packet->as_string());
            return std::nullopt;
        }

        vless_config.flow = acpp::vless::NormalizeFlow(vless_config.flow);
        if (!vless_config.flow.empty()) {
            LOG_WARN("VLESS outbound '{}': flow '{}' is not supported",
                     cfg.tag, vless_config.flow);
            return std::nullopt;
        }

        vless_config.stream_settings = cfg.stream_settings;
        vless_config.send_through = cfg.send_through;
        acpp::NormalizeOutboundStreamSettings(
            vless_config.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = false,
                .fallback_server_name = vless_config.address,
                .allow_insecure = false,
                .alpn = {},
            });

        if (vless_config.address.empty() ||
            vless_config.uuid.empty() ||
            !acpp::vless::ParseUuidBytes(vless_config.uuid)) {
            return std::nullopt;
        }

        acpp::proxyman::outbound::PreparedOutboundConfig prepared;
        prepared.tag = cfg.tag;
        prepared.protocol = cfg.protocol;
        prepared.create =
            [vless_config = std::move(vless_config)](
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_config = vless_config;
                runtime_config.timeout = timeout;
                return std::make_unique<acpp::proxy::vless::outbound::Handler>(
                    runtime_config, dns);
            };
        return prepared;
    }), true);
}  // namespace
