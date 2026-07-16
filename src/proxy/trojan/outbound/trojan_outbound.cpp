#include "acppnode/proxy/trojan/outbound/trojan_outbound.hpp"
#include "../trojan_codec.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "../../../app/proxyman/outbound/settings_json.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

namespace acpp {

namespace {

constexpr size_t kUdpFrameQueueShrinkItems = 64;

net::awaitable<bool> WriteFull(AsyncStream& stream, const uint8_t* buf, size_t len) {
    if (len == 0) {
        co_return true;
    }
    net::const_buffer buffer{buf, len};
    try {
        co_await stream.WriteBuffers(
            std::span<const net::const_buffer>{&buffer, 1});
    } catch (...) {
        co_return false;
    }
    co_return true;
}

net::awaitable<bool> WriteTrojanTcpInitial(
    AsyncStream& stream,
    std::span<const uint8_t> header,
    buf::MultiBuffer& first_payload,
    std::span<const uint8_t> initial_payload) {
    std::array<net::const_buffer, 2 + buf::MultiBuffer::kInlineCapacity> stack_buffers{};
    memory::ThreadLocalVector<net::const_buffer> spill_buffers;
    const bool use_spill = first_payload.size() > buf::MultiBuffer::kInlineCapacity;
    if (use_spill) {
        spill_buffers.reserve(2 + first_payload.size());
    }
    size_t stack_count = 0;

    auto append = [&](net::const_buffer buffer) {
        if (buffer.size() == 0) {
            return;
        }
        if (use_spill) {
            spill_buffers.push_back(buffer);
            return;
        }
        stack_buffers[stack_count++] = buffer;
    };

    append(net::const_buffer(header.data(), header.size()));
    for (const buf::Buffer* buffer : first_payload) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        append(net::const_buffer(bytes.data(), bytes.size()));
    }
    if (!initial_payload.empty()) {
        append(net::const_buffer(initial_payload.data(), initial_payload.size()));
    }

    const auto buffers = use_spill
        ? std::span<const net::const_buffer>(spill_buffers.data(), spill_buffers.size())
        : std::span<const net::const_buffer>(stack_buffers.data(), stack_count);
    try {
        co_await stream.WriteBuffers(buffers);
    } catch (...) {
        co_return false;
    }
    co_return true;
}

class TrojanUdpFramer {
public:
    struct FramedUdpPacket {
        TargetAddress target;
        buf::BufferGuard payload;
    };

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

    bool Next(FramedUdpPacket& out) {
        if (queue_.empty()) {
            return false;
        }
        out = std::move(queue_.front());
        queue_.pop_front();
        if (queue_.empty() && shrink_queue_on_drain_) {
            TryShrinkSequence(queue_);
            shrink_queue_on_drain_ = false;
        }
        return true;
    }

private:
    buf::BufferGuard pending_;
    memory::ThreadLocalDeque<FramedUdpPacket> queue_;
    bool shrink_queue_on_drain_ = false;

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

    [[nodiscard]] bool TryTakePacket(const TargetAddress& target,
                                     std::span<const uint8_t> payload) {
        buf::BufferGuard taken;
        if (!buf::TakeBufferSuffix(pending_, payload, taken)) {
            return false;
        }

        FramedUdpPacket pkt;
        pkt.target = target;
        pkt.payload = std::move(taken);
        queue_.push_back(std::move(pkt));
        if (queue_.size() >= kUdpFrameQueueShrinkItems) {
            shrink_queue_on_drain_ = true;
        }
        return true;
    }

    void Parse() {
        while (Size() > 0) {
            auto parsed = trojan::TrojanCodec::ParseUdpPacket(Data(), Size());
            if (parsed.result == trojan::TrojanCodec::UdpParseResult::SUCCESS) {
                if (parsed.packet &&
                    TryTakePacket(parsed.packet->target, parsed.packet->payload)) {
                    continue;
                }
                FramedUdpPacket pkt;
                pkt.target = parsed.packet->target;
                pkt.payload = buf::BufferGuard{buf::Buffer::New()};
                if (pkt.payload) {
                    const auto payload = parsed.packet->payload;
                    const size_t n = std::min<size_t>(
                        payload.size(),
                        static_cast<size_t>(pkt.payload->Available()));
                    std::memcpy(pkt.payload->Tail().data(), payload.data(), n);
                    pkt.payload->Produce(static_cast<uint32_t>(n));
                    queue_.push_back(std::move(pkt));
                    if (queue_.size() >= kUdpFrameQueueShrinkItems) {
                        shrink_queue_on_drain_ = true;
                    }
                }
                pending_->Advance(static_cast<uint32_t>(parsed.consumed));
                continue;
            }
            if (parsed.result == trojan::TrojanCodec::UdpParseResult::INCOMPLETE) {
                break;
            }
            pending_->Advance(1);
            if (Size() < 8) {
                ClearBuffer();
                break;
            }
        }

        if (pending_ && pending_->IsEmpty()) {
            ClearBuffer();
        }
    }
};

class TrojanUdpOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    TrojanUdpOutboundEndpoint(AsyncStream& stream, TargetAddress fallback_target)
        : stream_(stream)
        , fallback_target_(std::move(fallback_target)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (true) {
            buf::MultiBuffer out;
            TrojanUdpFramer::FramedUdpPacket pkt;
            while (framer_.Next(pkt)) {
                if (!pkt.payload || pkt.payload->IsEmpty()) {
                    continue;
                }
                pkt.payload->SetUDP(std::move(pkt.target));
                out.push_back(pkt.payload.release());
            }
            if (buf::HasData(out)) {
                co_return out;
            }

            buf::MultiBuffer raw = co_await stream_.ReadMultiBuffer();
            if (!buf::HasData(raw)) {
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
        buf::MultiBuffer out;
        for (buf::Buffer*& buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                mb.FreeSlot(buffer);
                continue;
            }
            const TargetAddress& target =
                buffer->HasUDP() ? buffer->UDP() : fallback_target_;
            buf::BufferGuard header{buf::Buffer::New()};
            if (!header) {
                throw std::bad_alloc();
            }
            const size_t written = trojan::TrojanCodec::EncodeUdpPacketHeaderTo(
                target,
                buffer->Len(),
                header->Tail().data(),
                header->Available());
            if (written == 0) {
                mb.FreeSlot(buffer);
                continue;
            }
            header->Produce(static_cast<uint32_t>(written));
            out.push_back(header.release());
            buffer->ClearUDP();
            out.push_back(mb.ReleaseSlot(buffer));
        }
        mb.clear();
        if (buf::HasData(out)) {
            co_await stream_.WriteMultiBuffer(std::move(out));
        }
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        buf::MultiBuffer header_owner;
        memory::ThreadLocalVector<net::const_buffer> out;
        header_owner.reserve(buffers.size());
        out.reserve(buffers.size() * 2);

        for (const net::const_buffer& buffer : buffers) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            if (!data || buffer.size() == 0) {
                continue;
            }
            buf::BufferGuard header{buf::Buffer::New()};
            if (!header) {
                throw std::bad_alloc();
            }
            const size_t written = trojan::TrojanCodec::EncodeUdpPacketHeaderTo(
                fallback_target_,
                buffer.size(),
                header->Tail().data(),
                header->Available());
            if (written == 0) {
                throw IoSystemError(io_error::fault, "Trojan UDP header allocation failed");
            }
            header->Produce(static_cast<uint32_t>(written));
            const auto header_bytes = header->Bytes();
            out.emplace_back(header_bytes.data(), header_bytes.size());
            header_owner.push_back(header.release());
            out.emplace_back(data, buffer.size());
        }

        if (!out.empty()) {
            co_await stream_.WriteBuffers(out);
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
    AsyncStream& stream_;
    TargetAddress fallback_target_;
    TrojanUdpFramer framer_;
};

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
        .tls_server_name = ResolveOutboundTlsServerName(
            config_.stream_settings, config_.GetServerName()),
        .ws_host = config_.address,
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

    const bool is_udp = ctx.content.network == Network::UDP;

    std::array<uint8_t, 512> header{};
    size_t header_len = ::acpp::trojan::TrojanCodec::EncodeRequestTo(
        config_.password,
        is_udp ? ::acpp::trojan::TrojanCommand::UDP_ASSOCIATE
               : ::acpp::trojan::TrojanCommand::CONNECT,
        target,
        header.data(), header.size());
    if (header_len == 0) {
        LOG_CONN_FAIL_CTX(ctx, "TrojanOutbound: Handshake encode failed");
        co_return fail_abortive(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    try {
        uint64_t prewritten_bytes = 0;
        const size_t first_payload_size = buf::TotalLen(first_payload);
        const size_t initial_payload_size = initial_payload.size();
        const bool handshake_ok = is_udp
            ? co_await WriteFull(*stream, header.data(), header_len)
            : co_await WriteTrojanTcpInitial(
                *stream,
                std::span<const uint8_t>(header.data(), header_len),
                first_payload,
                initial_payload);
        if (!handshake_ok) {
            LOG_CONN_FAIL_CTX(ctx, "TrojanOutbound: Handshake write failed");
            co_return fail_abortive(outbound_protocol_deadline.Expired()
                ? ErrorCode::TIMEOUT
                : ErrorCode::SOCKET_WRITE_FAILED);
        }

        if (!is_udp) {
            first_payload.clear();
            prewritten_bytes += first_payload_size;
            prewritten_bytes += initial_payload_size;
            if (prewritten_bytes > 0) {
                stats.AddBytesOut(prewritten_bytes);
                ctx.traffic.bytes_up = prewritten_bytes;
            }
        }

        LOG_CONN_DEBUG(ctx, "[Trojan] Handshake sent {} bytes", header_len);
        stream->SetIdleTimeout(relay_idle_timeout);
        stream->SetReadTimeout(std::chrono::seconds(0));
        stream->SetWriteTimeout(relay_write_timeout);
        stream->ClearPhaseDeadline();

        if (is_udp) {
            TrojanUdpOutboundEndpoint target_endpoint(*stream, target);
            if (first_payload_size > 0) {
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

        auto json_string = [](const acpp::json::object& obj,
                              std::string_view key) -> std::string {
            if (const auto* v = obj.if_contains(key); v && v->is_string()) {
                return std::string(v->as_string());
            }
            return {};
        };
        auto json_bool = [](const acpp::json::object& obj,
                            std::string_view key,
                            bool fallback = false) -> bool {
            if (const auto* v = obj.if_contains(key); v && v->is_bool()) {
                return v->as_bool();
            }
            return fallback;
        };
        auto json_string_array = [](const acpp::json::object& obj,
                                    std::string_view key) {
            std::vector<std::string> out;
            const auto* v = obj.if_contains(key);
            if (!v || !v->is_array()) {
                return out;
            }
            for (const auto& item : v->as_array()) {
                if (item.is_string()) {
                    out.emplace_back(item.as_string());
                }
            }
            return out;
        };
        auto read_trojan_server = [&](const acpp::json::object& obj,
                                      acpp::TrojanOutboundConfig& config) {
            config.address = json_string(obj, "address");
            if (config.address.empty()) {
                config.address = json_string(obj, "server");
            }
            const auto port = acpp::proxyman::outbound::ParsePort(
                obj, {"server_port", "port"});
            if (!port.valid) {
                return false;
            }
            if (port.present) {
                config.port = port.value;
            }
            config.password = json_string(obj, "password");
            config.server_name = json_string(obj, "serverName");
            if (config.server_name.empty()) {
                config.server_name = json_string(obj, "server_name");
            }
            if (config.server_name.empty()) {
                config.server_name = json_string(obj, "sni");
            }
            config.allow_insecure = json_bool(
                obj,
                "allowInsecure",
                json_bool(obj, "allow_insecure", config.allow_insecure));
            config.alpn = json_string_array(obj, "alpn");
            return true;
        };

        acpp::TrojanOutboundConfig trojan_config;
        trojan_config.tag = cfg.tag;

        bool parsed_xray = false;
        if (const auto* servers_p = s.if_contains("servers");
                servers_p && servers_p->is_array() && !servers_p->as_array().empty() &&
                servers_p->as_array()[0].is_object()) {
            if (!read_trojan_server(
                    servers_p->as_array()[0].as_object(), trojan_config)) {
                return std::nullopt;
            }
            parsed_xray = true;
        }
        if (!parsed_xray) {
            if (!read_trojan_server(s, trojan_config)) {
                return std::nullopt;
            }
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

        if (trojan_config.address.empty() || trojan_config.password.empty() ||
            trojan_config.port == 0) {
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
