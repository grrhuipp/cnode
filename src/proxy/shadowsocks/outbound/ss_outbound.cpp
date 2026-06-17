#include "acppnode/proxy/shadowsocks/outbound/ss_outbound.hpp"
#include "../client.hpp"
#include "../ss_udp.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"

#include <asio/experimental/channel.hpp>

#include <algorithm>
#include <cstring>
#include <deque>
#include <exception>
#include <format>
#include <memory>
#include <span>
#include <utility>

namespace acpp {

namespace {

class ShadowsocksOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    ShadowsocksOutboundEndpoint(std::unique_ptr<transport::MultiBufferWriter> request_writer,
                                const ss::SsCipherInfo& cipher_info,
                                const ss::KeyBytes& master_key,
                                const ss::KeyBytes& request_salt,
                                AsyncStream& stream)
        : request_writer_(std::move(request_writer))
        , cipher_info_(cipher_info)
        , master_key_(master_key)
        , request_salt_(request_salt)
        , stream_(stream) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_reader_) {
            auto reader_result = co_await ss::ReadTCPResponse(
                cipher_info_, master_key_, request_salt_, stream_);
            if (!reader_result) {
                throw IoSystemError(
                    io_error::connection_reset,
                    "Shadowsocks response header failed");
            }
            response_reader_ = std::move(reader_result.value());
        }
        co_return co_await response_reader_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!request_writer_) {
            mb.clear();
            throw IoSystemError(
                io_error::not_connected,
                "Shadowsocks request writer is not initialized");
        }
        co_await request_writer_->WriteMultiBuffer(std::move(mb));
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
    std::unique_ptr<transport::MultiBufferWriter> request_writer_;
    ss::SsCipherInfo cipher_info_;
    ss::KeyBytes master_key_;
    ss::KeyBytes request_salt_;
    AsyncStream& stream_;
    std::unique_ptr<transport::MultiBufferReader> response_reader_;
};

class ShadowsocksUdpOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    ShadowsocksUdpOutboundEndpoint(net::io_context& io_context,
                                   UDPSession& session,
                                   TargetAddress server,
                                   const ss::SsCipherInfo& cipher_info,
                                   const ss::KeyBytes& master_key,
                                   std::span<const ss::KeyBytes> psk_chain)
        : io_context_(io_context)
        , session_(session)
        , server_(std::move(server))
        , cipher_info_(cipher_info)
        , master_key_(master_key)
        , psk_chain_(psk_chain)
        , signal_(io_context, 1)
        , read_timer_(io_context)
        , phase_timer_(io_context) {
        if (ss::Is2022Cipher(cipher_info_)) {
            ss2022_state_.emplace();
            if (!ss::Init2022UdpSessionState(*ss2022_state_, cipher_info_, master_key_)) {
                ss2022_state_.reset();
            }
        }
    }

    void Start() {
        callback_id_ = session_.RegisterCallback(
            PacketCallback{[this](UDPPacketView pkt) { OnPacket(pkt); }});
    }

    ~ShadowsocksUdpOutboundEndpoint() noexcept override {
        Stop();
    }

    void Stop() noexcept {
        try {
            if (callback_id_ != 0) {
                session_.UnregisterCallback(callback_id_);
                callback_id_ = 0;
            }
        } catch (...) {
        }
        Cancel();
    }

    net::awaitable<void> StopAndDrain() {
        Stop();
        co_await net::post(io_context_.get_executor(), net::use_awaitable);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (true) {
            if (!replies_.empty()) {
                buf::MultiBuffer mb = std::move(replies_.front());
                queued_bytes_ -= std::min(queued_bytes_, buf::TotalLen(mb));
                replies_.pop_front();
                co_return mb;
            }
            if (closed_) {
                co_return buf::MultiBuffer{};
            }

            auto [ec] = co_await signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            (void)ec;
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (closed_) {
            mb.clear();
            throw IoSystemError(io_error::operation_aborted, "Shadowsocks UDP endpoint closed");
        }
        memory::ByteVector scratch;
        for (buf::Buffer* buffer : mb) {
            if (!buffer || buffer->IsEmpty() || !buffer->HasUDP()) {
                continue;
            }
            const size_t encoded_len = EncodedPacketSize(*buffer);
            if (encoded_len == 0) {
                continue;
            }

            ErrorCode send_result = ErrorCode::OK;
            if (encoded_len <= buf::Buffer::kSize) {
                buf::BufferGuard encoded{buf::Buffer::New()};
                if (!encoded) {
                    throw std::bad_alloc();
                }
                const size_t written = EncodePacketTo(
                    *buffer, encoded->Tail().data(), encoded->Available());
                if (written != encoded_len) {
                    continue;
                }
                encoded->Produce(static_cast<uint32_t>(written));
                send_result = co_await session_.SendTo(
                    server_, encoded->Bytes().data(), encoded->Len(), callback_id_);
            } else {
                scratch.resize(encoded_len);
                const size_t written = EncodePacketTo(
                    *buffer, scratch.data(), scratch.size());
                if (written != encoded_len) {
                    continue;
                }
                send_result = co_await session_.SendTo(
                    server_, scratch.data(), scratch.size(), callback_id_);
            }
            if (send_result != ErrorCode::OK) {
                mb.clear();
                throw IoSystemError(io_error::fault, std::string(ErrorCodeToString(send_result)));
            }
        }
        mb.clear();
        co_return;
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        Cancel();
        co_return;
    }

    void SetIdleTimeout(std::chrono::seconds) {}

    void SetReadTimeout(std::chrono::seconds timeout) {
        read_timeout_ = false;
        IoErrorCode ignored;
        read_timer_.cancel(ignored);
        if (timeout.count() <= 0 || closed_) {
            return;
        }
        read_timer_.expires_after(timeout);
        read_timer_.async_wait([this](const IoErrorCode& ec) {
            if (!ec && !closed_) {
                read_timeout_ = true;
                Cancel();
            }
        });
    }

    void SetWriteTimeout(std::chrono::seconds) {}

    bool ConsumeIdleTimeout() noexcept { return false; }

    bool ConsumeReadTimeout() noexcept {
        const bool timed_out = read_timeout_;
        read_timeout_ = false;
        return timed_out;
    }

    bool ConsumeWriteTimeout() noexcept { return false; }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        phase_timeout_ = false;
        ++phase_generation_;
        IoErrorCode ignored;
        phase_timer_.cancel(ignored);
        if (timeout.count() <= 0 || closed_) {
            phase_timeout_ = true;
            Cancel();
            return PhaseDeadlineHandle(
                &phase_flags_, kPhaseExpired, &phase_generation_, phase_generation_);
        }

        const uint32_t captured = phase_generation_;
        phase_timer_.expires_after(timeout);
        phase_timer_.async_wait([this, captured](const IoErrorCode& ec) {
            if (!ec && !closed_ && phase_generation_ == captured) {
                phase_timeout_ = true;
                phase_flags_ |= kPhaseExpired;
                Cancel();
            }
        });
        return PhaseDeadlineHandle(
            &phase_flags_, kPhaseExpired, &phase_generation_, captured);
    }

    void ClearPhaseDeadline() {
        ++phase_generation_;
        phase_flags_ = 0;
        phase_timeout_ = false;
        IoErrorCode ignored;
        phase_timer_.cancel(ignored);
    }

    bool ConsumePhaseDeadline() noexcept {
        const bool timed_out = phase_timeout_;
        phase_timeout_ = false;
        phase_flags_ = 0;
        return timed_out;
    }

    void Cancel() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        IoErrorCode ignored;
        read_timer_.cancel(ignored);
        phase_timer_.cancel(ignored);
        (void)signal_.try_send(io_error::operation_aborted);
    }

    void SetAbortiveClose(bool = true) noexcept {
        Cancel();
    }

private:
    [[nodiscard]] size_t EncodedPacketSize(const buf::Buffer& buffer) {
        if (ss2022_state_) {
            return ss::Encode2022UdpRequestPacketTo(
                buffer.UDP(),
                buffer.Bytes().data(),
                buffer.Len(),
                *ss2022_state_,
                psk_chain_,
                nullptr,
                0);
        }
        return ss::EncodeUdpPacketTo(
            buffer.UDP(),
            buffer.Bytes().data(),
            buffer.Len(),
            master_key_.span(),
            cipher_info_.type,
            cipher_info_.key_size,
            cipher_info_.salt_size,
            nullptr,
            0);
    }

    [[nodiscard]] size_t EncodePacketTo(const buf::Buffer& buffer,
                                        uint8_t* output,
                                        size_t output_size) {
        if (ss2022_state_) {
            return ss::Encode2022UdpRequestPacketTo(
                buffer.UDP(),
                buffer.Bytes().data(),
                buffer.Len(),
                *ss2022_state_,
                psk_chain_,
                output,
                output_size);
        }
        return ss::EncodeUdpPacketTo(
            buffer.UDP(),
            buffer.Bytes().data(),
            buffer.Len(),
            master_key_.span(),
            cipher_info_.type,
            cipher_info_.key_size,
            cipher_info_.salt_size,
            output,
            output_size);
    }

    void OnPacket(UDPPacketView pkt) {
        if (closed_) {
            return;
        }

        std::optional<ss::SsUdpDecodeResult> decoded;
        if (ss2022_state_) {
            decoded = ss::Decode2022UdpResponsePacket(
                pkt.data.data(), pkt.data.size(), *ss2022_state_);
        } else {
            decoded = ss::DecodeUdpPacketWithKey(
                pkt.data.data(), pkt.data.size(), master_key_.span(),
                cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size);
        }
        if (!decoded || decoded->payload.empty()) {
            return;
        }

        const size_t payload_size = buf::TotalLen(decoded->payload);
        if (queued_bytes_ + payload_size > 512 * 1024) {
            decoded->payload.clear();
            return;
        }

        for (buf::Buffer* buffer : decoded->payload) {
            if (buffer && !buffer->IsEmpty()) {
                buffer->SetUDP(decoded->target);
            }
        }
        queued_bytes_ += payload_size;
        replies_.push_back(std::move(decoded->payload));
        (void)signal_.try_send(IoErrorCode{});
    }

    net::io_context& io_context_;
    UDPSession& session_;
    TargetAddress server_;
    ss::SsCipherInfo cipher_info_;
    ss::KeyBytes master_key_;
    std::span<const ss::KeyBytes> psk_chain_;
    std::optional<ss::Ss2022UdpSessionState> ss2022_state_;
    uint64_t callback_id_ = 0;
    net::experimental::channel<void(IoErrorCode)> signal_;
    std::deque<buf::MultiBuffer> replies_;
    size_t queued_bytes_ = 0;
    bool closed_ = false;
    bool read_timeout_ = false;
    bool phase_timeout_ = false;
    static constexpr uint8_t kPhaseExpired = 0x01;
    uint8_t phase_flags_ = 0;
    uint32_t phase_generation_ = 0;
    net::steady_timer read_timer_;
    net::steady_timer phase_timer_;
};

std::vector<std::string_view> SplitPasswordChain(std::string_view password) {
    std::vector<std::string_view> parts;
    size_t start = 0;
    while (start <= password.size()) {
        const size_t pos = password.find(':', start);
        const size_t end = pos == std::string_view::npos ? password.size() : pos;
        parts.push_back(password.substr(start, end - start));
        if (pos == std::string_view::npos) {
            break;
        }
        start = pos + 1;
    }
    return parts;
}

TargetAddress MakeServerTarget(const SsOutboundConfig& config) {
    if (config.literal_address) {
        return TargetAddress(*config.literal_address, config.port);
    }
    return TargetAddress(std::string_view(config.address.data(), config.address.size()),
                         config.port);
}

std::string SelectUdpBindAddress(const SsOutboundConfig& config) {
    if (!config.send_through.empty() &&
        config.send_through != constants::binding::kAuto) {
        return config.send_through;
    }
    return std::string(constants::network::kAnyIpv4);
}

}  // namespace

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
    if (!inbound.Valid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (ctx.content.network == Network::UDP) {
        if (!udp_session_manager_) {
            LOG_CONN_FAIL_CTX(ctx, "[SsOutbound] UDP session manager not available");
            co_return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
        }
        if (master_key_.empty()) {
            co_return std::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
        }

        auto server = MakeServerTarget(config_);
        if (!server.IsValid()) {
            co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }

        const auto bind_addr = SelectUdpBindAddress(config_);
        const auto session_id = std::format(
            "ssudp-{}-{}", config_.tag, ctx.conn_id);
        auto* udp_session = udp_session_manager_->GetOrCreateSession(
            session_id, bind_addr);
        if (!udp_session) {
            LOG_CONN_FAIL_CTX(ctx, "[SsOutbound] UDP session create failed via {}",
                              ctx.outbound.tag);
            co_return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
        }

        ShadowsocksUdpOutboundEndpoint target_endpoint(
            io_context,
            *udp_session,
            std::move(server),
            cipher_info_,
            master_key_,
            psk_chain_);
        target_endpoint.Start();

        RelayResult result;
        std::exception_ptr relay_error;
        try {
            if (inbound.control) {
                result = co_await DoRelayLink(
                    io_context, *inbound.reader, *inbound.writer, *inbound.control,
                    target_endpoint, ctx, stats, relay_config);
            } else {
                result = co_await DoRelayLink(
                    io_context, *inbound.reader, *inbound.writer,
                    target_endpoint, ctx, stats, relay_config);
            }
        } catch (...) {
            relay_error = std::current_exception();
        }
        co_await target_endpoint.StopAndDrain();
        if (relay_error) {
            std::rethrow_exception(relay_error);
        }
        co_return result;
    }

    const auto& target = ctx.outbound.target;

    auto transport_target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
        .dns_service = &dns_service_,
        .address = config_.address,
        .literal_address = config_.literal_address,
        .port = config_.port,
        .stream_settings = &stream_settings_,
        .timeout = config_.timeout,
        .send_through = config_.send_through,
        .inbound_local_addr = inbound_local_addr,
        .tls_server_name = ResolveOutboundTlsServerName(stream_settings_, config_.address),
        .ws_host = config_.address,
    });
    if (!transport_target) {
        co_return std::unexpected(transport_target.error());
    }

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
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
        target, cipher_info_, master_key_, psk_chain_, *stream);
    if (!request_writer_result) {
        stream->Cancel();
        co_return std::unexpected(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : request_writer_result.error());
    }
    auto request_session = std::move(request_writer_result.value());
    auto request_writer = std::move(request_session.request_writer);

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    ShadowsocksOutboundEndpoint target_endpoint(
        std::move(request_writer),
        cipher_info_,
        master_key_,
        request_session.request_salt,
        *stream);
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

proxy::shadowsocks::outbound::Handler::Handler(const SsOutboundConfig& config,
                                               ::acpp::app::dns::DNS& dns_service,
                                               ::acpp::UDPSessionManager* udp_session_manager)
    : config_(config)
    , dns_service_(dns_service)
    , udp_session_manager_(udp_session_manager) {
    config_.literal_address = ParseLiteralAddress(config_.address);

    auto info = ss::ParseCipherMethod(config_.method);
    if (info) {
        cipher_info_ = *info;
    } else {
        LOG_WARN("[SsOutbound] Unknown cipher '{}', fallback to {}",
                 config_.method,
                 acpp::constants::protocol::kAes256Gcm);
        cipher_info_ = ss::SsCipherInfo{ss::SsCipherType::AES_256_GCM, 32, 32};
    }

    if (ss::Is2022Cipher(cipher_info_)) {
        const auto parts = SplitPasswordChain(config_.password);
        psk_chain_.reserve(parts.size());
        for (const auto part : parts) {
            auto key = ss::Decode2022Psk(part, cipher_info_.key_size);
            if (!key.empty()) {
                psk_chain_.push_back(key);
            }
        }
        if (!psk_chain_.empty()) {
            master_key_ = psk_chain_.back();
        } else {
            LOG_WARN("[SsOutbound] invalid SS2022 password/key for '{}'", config_.tag);
        }
    } else {
        master_key_ = ss::DeriveKey(config_.password, cipher_info_.key_size);
    }
    stream_settings_ = config_.stream_settings;
    NormalizeOutboundStreamSettings(
        stream_settings_,
        OutboundStreamDefaults{
            .require_tls = false,
            .fallback_server_name = config_.address,
            .allow_insecure = false,
            .alpn = {},
        });
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
        if (ss_config.password.empty()) {
            if (const auto* v = srv.if_contains("key"); v && v->is_string()) {
                ss_config.password = std::string(v->as_string());
            }
        }
        if (const auto* v = srv.if_contains("method"); v && v->is_string()) {
            ss_config.method = std::string(v->as_string());
        }
        ss_config.stream_settings = cfg.stream_settings;
        ss_config.send_through = cfg.send_through;
        acpp::NormalizeOutboundStreamSettings(
            ss_config.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = false,
                .fallback_server_name = ss_config.address,
                .allow_insecure = false,
                .alpn = {},
            });

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
                acpp::UDPSessionManager* udp_mgr,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_config = ss_config;
                runtime_config.timeout = timeout;
                return std::make_unique<acpp::proxy::shadowsocks::outbound::Handler>(
                    runtime_config, dns_service, udp_mgr);
            };
        return prepared;
    }), true);
}  // namespace
