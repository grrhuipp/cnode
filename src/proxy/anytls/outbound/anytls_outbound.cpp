#include "acppnode/proxy/anytls/outbound/anytls_outbound.hpp"

#include "../anytls_codec.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <array>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace {

constexpr size_t kMaxLogicalQueuedPayloadBytes = acpp::buf::Buffer::kSize * 4;

struct PendingWait {
    virtual ~PendingWait() = default;
    virtual void Complete() noexcept = 0;
};

template <typename Handler>
struct PendingWaitOp final : PendingWait {
    template <typename H>
    explicit PendingWaitOp(H&& h) : handler(std::forward<H>(h)) {}

    void Complete() noexcept override {
        try {
            std::move(handler)();
        } catch (...) {}
    }

    Handler handler;
};

template <typename Handler>
std::unique_ptr<PendingWait> MakePendingWait(Handler&& handler) {
    using StoredHandler = std::decay_t<Handler>;
    return std::make_unique<PendingWaitOp<StoredHandler>>(
        std::forward<Handler>(handler));
}

void ResumeWaiter(acpp::net::io_context& io_context,
                  std::unique_ptr<PendingWait>& waiter) noexcept {
    if (auto pending = std::exchange(waiter, {}); pending) {
        try {
            acpp::net::post(io_context, [pending = std::move(pending)]() mutable {
                pending->Complete();
            });
        } catch (...) {
            pending->Complete();
        }
    }
}

std::optional<acpp::anytls::outbound::Settings> ParseSettings(
    const acpp::json::object& settings) {
    acpp::anytls::outbound::Settings result;

    if (const auto* value = settings.if_contains("address"); value && value->is_string()) {
        result.address = std::string(value->as_string());
    }
    if (const auto* value = settings.if_contains("port"); value) {
        const auto raw = value->is_int64()
            ? value->as_int64()
            : (value->is_uint64() ? static_cast<int64_t>(value->as_uint64()) : 0);
        if (raw > 0 && raw <= 65535) {
            result.port = static_cast<uint16_t>(raw);
        }
    }
    if (const auto* value = settings.if_contains("password"); value && value->is_string()) {
        result.password = std::string(value->as_string());
    }
    auto read_seconds = [&](std::string_view key, std::chrono::seconds fallback) {
        if (const auto* value = settings.if_contains(key); value) {
            const auto raw = value->is_int64()
                ? value->as_int64()
                : (value->is_uint64() ? static_cast<int64_t>(value->as_uint64()) : 0);
            if (raw > 0) {
                return std::chrono::seconds(raw);
            }
        }
        return fallback;
    };
    result.idle_session_check_interval =
        read_seconds("idleSessionCheckInterval", result.idle_session_check_interval);
    result.idle_session_timeout =
        read_seconds("idleSessionTimeout", result.idle_session_timeout);
    if (const auto* value = settings.if_contains("minIdleSession"); value) {
        const auto raw = value->is_int64()
            ? value->as_int64()
            : (value->is_uint64() ? static_cast<int64_t>(value->as_uint64()) : -1);
        if (raw >= 0) {
            result.min_idle_sessions = static_cast<size_t>(raw);
        }
    }

    acpp::IoErrorCode addr_ec;
    auto literal_addr = acpp::net::ip::make_address(result.address, addr_ec);
    if (!addr_ec) {
        result.literal_address = literal_addr;
    }

    if (result.address.empty() || result.password.empty() || result.port == 0) {
        return std::nullopt;
    }
    return result;
}

}  // namespace

namespace acpp::anytls::outbound {

struct Handler::ClientSession {
    class LogicalStream final {
    public:
        LogicalStream(net::io_context& io_context, uint32_t stream_id)
            : io_context_(io_context)
            , timeout_scheduler_(TimeoutScheduler::ForIoContext(io_context))
            , syn_signal_(io_context, 1)
            , sid_(stream_id) {}

        ~LogicalStream() noexcept {
            Cancel();
        }

        LogicalStream(const LogicalStream&) = delete;
        LogicalStream& operator=(const LogicalStream&) = delete;

        [[nodiscard]] uint32_t Sid() const noexcept {
            return sid_;
        }

        void PushPayload(buf::MultiBuffer mb) {
            if (closed_) {
                mb.clear();
                return;
            }
            const size_t bytes = buf::TotalLen(mb);
            if (bytes == 0) {
                mb.clear();
                return;
            }
            if (queued_bytes_ + bytes > kMaxLogicalQueuedPayloadBytes) {
                Fail(ErrorCode::RESOURCE_EXHAUSTED);
                mb.clear();
                return;
            }
            queue_.push_back(std::move(mb));
            queued_bytes_ += bytes;
            WakePayloadReader();
        }

        void Close(ErrorCode error = ErrorCode::OK) {
            if (closed_) {
                return;
            }
            closed_ = true;
            error_ = error;
            WakeSynWaiter();
            WakePayloadReader();
        }

        void AckSyn(ErrorCode error = ErrorCode::OK) {
            if (syn_ack_done_) {
                return;
            }
            syn_ack_done_ = true;
            syn_ack_error_ = error;
            WakeSynWaiter();
        }

        net::awaitable<std::expected<void, ErrorCode>> WaitSynAck(std::chrono::seconds timeout) {
            if (syn_ack_done_) {
                if (syn_ack_error_ == ErrorCode::OK) {
                    co_return std::expected<void, ErrorCode>{};
                }
                co_return std::unexpected(syn_ack_error_);
            }
            syn_waiting_ = true;
            syn_timed_out_ = false;
            syn_timeout_token_ = timeout_scheduler_.ScheduleAfter(
                std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
                [this]() {
                    syn_timeout_token_.Reset();
                    syn_timed_out_ = true;
                    if (syn_waiting_) {
                        (void)syn_signal_.try_send(IoErrorCode{});
                    }
                });
            auto [ec] = co_await syn_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            (void)ec;
            syn_waiting_ = false;
            timeout_scheduler_.Cancel(syn_timeout_token_);
            if (syn_ack_done_) {
                if (syn_ack_error_ == ErrorCode::OK) {
                    co_return std::expected<void, ErrorCode>{};
                }
                co_return std::unexpected(syn_ack_error_);
            }
            if (syn_timed_out_) {
                co_return std::unexpected(ErrorCode::TIMEOUT);
            }
            co_return std::expected<void, ErrorCode>{};
        }

        void Cancel() noexcept {
            if (closed_) {
                return;
            }
            closed_ = true;
            error_ = ErrorCode::CANCELLED;
            queue_.clear();
            queued_bytes_ = 0;
            WakeSynWaiter();
            WakePayloadReader();
        }

        template <typename CompletionToken>
        auto AsyncWaitPayload(CompletionToken&& token) {
            return net::async_initiate<CompletionToken, void()>(
                [this](auto&& handler) {
                    payload_waiter_ = MakePendingWait(
                        std::forward<decltype(handler)>(handler));
                },
                token);
        }

        net::awaitable<std::expected<buf::MultiBuffer, ErrorCode>> ReadPayload() {
            while (!closed_) {
                if (!queue_.empty()) {
                    buf::MultiBuffer mb = std::move(queue_.front());
                    queued_bytes_ -= std::min(queued_bytes_, buf::TotalLen(mb));
                    queue_.pop_front();
                    co_return std::move(mb);
                }
                co_await AsyncWaitPayload(net::use_awaitable);
            }
            if (!queue_.empty()) {
                buf::MultiBuffer mb = std::move(queue_.front());
                queued_bytes_ -= std::min(queued_bytes_, buf::TotalLen(mb));
                queue_.pop_front();
                co_return std::move(mb);
            }
            co_return std::unexpected(error_);
        }

    private:
        void Fail(ErrorCode error) noexcept {
            closed_ = true;
            error_ = error;
            queue_.clear();
            queued_bytes_ = 0;
            WakeSynWaiter();
            WakePayloadReader();
        }

        void WakeSynWaiter() noexcept {
            timeout_scheduler_.Cancel(syn_timeout_token_);
            if (syn_waiting_) {
                (void)syn_signal_.try_send(IoErrorCode{});
            }
        }

        void WakePayloadReader() noexcept {
            ResumeWaiter(io_context_, payload_waiter_);
        }

        net::io_context& io_context_;
        TimeoutScheduler& timeout_scheduler_;
        std::unique_ptr<PendingWait> payload_waiter_;
        TimeoutToken syn_timeout_token_;
        net::experimental::channel<void(IoErrorCode)> syn_signal_;
        uint32_t sid_ = 0;
        std::deque<buf::MultiBuffer> queue_;
        size_t queued_bytes_ = 0;
        ErrorCode error_ = ErrorCode::OK;
        ErrorCode syn_ack_error_ = ErrorCode::OK;
        bool closed_ = false;
        bool syn_ack_done_ = false;
        bool syn_waiting_ = false;
        bool syn_timed_out_ = false;
    };

    ClientSession(net::io_context& io_context, std::unique_ptr<AsyncStream> s)
        : stream(std::move(s))
        , write_signal(io_context, 1) {}

    std::unique_ptr<AsyncStream> stream;
    PaddingScheme padding_scheme = DefaultPaddingScheme();
    uint32_t next_sid = 1;
    uint32_t packet_index = 1;
    bool settings_sent = false;
    uint8_t peer_version = 0;
    std::chrono::steady_clock::time_point idle_since{};
    net::experimental::channel<void(IoErrorCode)> write_signal;
    std::mutex streams_mu;
    std::unordered_map<uint32_t, std::weak_ptr<LogicalStream>> logical_streams;
    size_t active_streams = 0;
    bool in_idle_pool = false;
    bool read_loop_started = false;
    bool write_busy = false;
    std::atomic_bool closed = false;

    [[nodiscard]] bool Available() const noexcept {
        return !closed.load() && stream && active_streams == 0;
    }

    std::shared_ptr<LogicalStream> RegisterLogicalStream(
        net::io_context& io_context,
        uint32_t sid) {
        auto logical = std::make_shared<LogicalStream>(io_context, sid);
        std::lock_guard lock(streams_mu);
        logical_streams[sid] = logical;
        return logical;
    }

    void UnregisterLogicalStream(uint32_t sid) {
        std::lock_guard lock(streams_mu);
        logical_streams.erase(sid);
    }

    void CloseAll(ErrorCode error) {
        closed.store(true);
        WakeWriter();
        {
            std::lock_guard lock(streams_mu);
            for (auto& [sid, weak] : logical_streams) {
                (void)sid;
                if (auto logical = weak.lock()) {
                    logical->Close(error);
                }
            }
            logical_streams.clear();
        }
        if (stream) {
            stream->CloseAbortive();
        }
    }

    net::awaitable<std::expected<void, ErrorCode>> WaitWriteTurn() {
        while (write_busy && !closed.load()) {
            auto [ec] = co_await write_signal.async_receive(
                net::as_tuple(net::use_awaitable));
            (void)ec;
        }
        if (closed.load() || !stream) {
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }
        write_busy = true;
        co_return std::expected<void, ErrorCode>{};
    }

    void ReleaseWriteTurn() {
        write_busy = false;
        WakeWriter();
    }

    void WakeWriter() noexcept {
        (void)write_signal.try_send(IoErrorCode{});
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteOpenPacket(uint32_t sid, std::string packet) {
        auto turn = co_await WaitWriteTurn();
        if (!turn) {
            co_return std::unexpected(turn.error());
        }
        auto guard = std::unique_ptr<void, void(*)(void*)>{
            this,
            [](void* p) { static_cast<ClientSession*>(p)->ReleaseWriteTurn(); }};

        if (!settings_sent) {
            const auto settings = DefaultClientSettings();
            auto settings_frame = BuildFrameBytes(
                kCmdSettings,
                0,
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(settings.data()), settings.size()));
            if (!settings_frame) {
                co_return std::unexpected(settings_frame.error());
            }
            packet.insert(0, *settings_frame);
        }

        const uint32_t this_packet = packet_index < padding_scheme.stop ? packet_index++ : 0;
        auto ok = co_await WritePacketWithPadding(
            *stream, padding_scheme, this_packet, std::move(packet));
        if (!ok) {
            closed.store(true);
            co_return std::unexpected(ok.error());
        }
        settings_sent = true;
        co_return std::expected<void, ErrorCode>{};
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WritePayloadFrames(uint32_t sid, buf::MultiBuffer mb) {
        auto turn = co_await WaitWriteTurn();
        if (!turn) {
            mb.clear();
            co_return std::unexpected(turn.error());
        }
        auto guard = std::unique_ptr<void, void(*)(void*)>{
            this,
            [](void* p) { static_cast<ClientSession*>(p)->ReleaseWriteTurn(); }};

        const PaddingScheme scheme_snapshot = padding_scheme;
        const uint32_t this_packet = packet_index < scheme_snapshot.stop ? packet_index++ : 0;
        auto ok = co_await WriteMultiBufferAsFramesWithPadding(
            *stream, scheme_snapshot, this_packet, kCmdPSH, sid, std::move(mb));
        if (!ok) {
            closed.store(true);
            co_return std::unexpected(ok.error());
        }
        co_return std::expected<void, ErrorCode>{};
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteUdpPacket(uint32_t sid, std::string packet) {
        auto turn = co_await WaitWriteTurn();
        if (!turn) {
            co_return std::unexpected(turn.error());
        }
        auto guard = std::unique_ptr<void, void(*)(void*)>{
            this,
            [](void* p) { static_cast<ClientSession*>(p)->ReleaseWriteTurn(); }};

        const PaddingScheme scheme_snapshot = padding_scheme;
        const uint32_t this_packet = packet_index < scheme_snapshot.stop ? packet_index++ : 0;
        auto ok = co_await WritePacketWithPadding(
            *stream, scheme_snapshot, this_packet, std::move(packet));
        if (!ok) {
            closed.store(true);
            co_return std::unexpected(ok.error());
        }
        co_return std::expected<void, ErrorCode>{};
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteFrameSerialized(uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
        auto turn = co_await WaitWriteTurn();
        if (!turn) {
            co_return std::unexpected(turn.error());
        }
        auto guard = std::unique_ptr<void, void(*)(void*)>{
            this,
            [](void* p) { static_cast<ClientSession*>(p)->ReleaseWriteTurn(); }};

        auto ok = co_await WriteFrame(*stream, cmd, sid, payload);
        if (!ok) {
            closed.store(true);
            co_return std::unexpected(ok.error());
        }
        co_return std::expected<void, ErrorCode>{};
    }

    net::awaitable<void> ReadLoop() {
        while (!closed.load() && stream) {
            auto header = co_await ReadFrameHeader(*stream);
            if (!header) {
                CloseAll(header.error());
                co_return;
            }

            auto discard_current = [&]() -> net::awaitable<std::expected<void, ErrorCode>> {
                co_return co_await DiscardFramePayload(*stream, header->length);
            };

            if (header->sid == 0) {
                switch (header->cmd) {
                    case kCmdWaste:
                        if (auto ok = co_await discard_current(); !ok) {
                            CloseAll(ok.error());
                            co_return;
                        }
                        break;
                    case kCmdServerSettings: {
                        if (header->length > 0) {
                            auto text = co_await ReadFrameText(*stream, header->length);
                            if (!text) {
                                CloseAll(text.error());
                                co_return;
                            }
                            if (text->find("v=2") != std::string::npos) {
                                peer_version = 2;
                            }
                        }
                        break;
                    }
                    case kCmdUpdatePaddingScheme: {
                        if (header->length > 0) {
                            auto text = co_await ReadFrameText(*stream, header->length);
                            if (!text) {
                                CloseAll(text.error());
                                co_return;
                            }
                            if (auto parsed = ParsePaddingScheme(*text)) {
                                padding_scheme = std::move(*parsed);
                            }
                        }
                        break;
                    }
                    case kCmdHeartResponse:
                        if (auto ok = co_await discard_current(); !ok) {
                            CloseAll(ok.error());
                            co_return;
                        }
                        break;
                    case kCmdHeartRequest:
                        if (auto ok = co_await discard_current(); !ok) {
                            CloseAll(ok.error());
                            co_return;
                        }
                        if (auto ok = co_await WriteFrameSerialized(kCmdHeartResponse, 0, {}); !ok) {
                            CloseAll(ok.error());
                            co_return;
                        }
                        break;
                    case kCmdAlert: {
                        auto text = co_await ReadFrameText(*stream, header->length);
                        (void)text;
                        CloseAll(ErrorCode::PROTOCOL_DECODE_FAILED);
                        co_return;
                    }
                    default:
                        if (auto ok = co_await discard_current(); !ok) {
                            CloseAll(ok.error());
                            co_return;
                        }
                        break;
                }
                continue;
            }

            std::shared_ptr<LogicalStream> logical;
            {
                std::lock_guard lock(streams_mu);
                auto stream_it = logical_streams.find(header->sid);
                logical = stream_it == logical_streams.end()
                    ? std::shared_ptr<LogicalStream>{}
                    : stream_it->second.lock();
                if (!logical && stream_it != logical_streams.end()) {
                    logical_streams.erase(stream_it);
                }
            }
            if (!logical) {
                if (auto ok = co_await discard_current(); !ok) {
                    CloseAll(ok.error());
                    co_return;
                }
                continue;
            }

            switch (header->cmd) {
                case kCmdSYNACK:
                    if (header->length > 0) {
                        auto text = co_await ReadFrameText(*stream, header->length);
                        (void)text;
                        logical->AckSyn(ErrorCode::PROTOCOL_DECODE_FAILED);
                        logical->Close(ErrorCode::PROTOCOL_DECODE_FAILED);
                    } else {
                        logical->AckSyn(ErrorCode::OK);
                    }
                    break;
                case kCmdWaste:
                    if (auto ok = co_await discard_current(); !ok) {
                        logical->Close(ok.error());
                    }
                    break;
                case kCmdPSH: {
                    auto payload = co_await ReadFramePayload(*stream, header->length);
                    if (!payload) {
                        logical->Close(payload.error());
                        break;
                    }
                    logical->PushPayload(std::move(*payload));
                    break;
                }
                case kCmdFIN:
                    if (auto ok = co_await discard_current(); !ok) {
                        logical->Close(ok.error());
                    } else {
                        logical->Close(ErrorCode::OK);
                    }
                    break;
                case kCmdAlert: {
                    auto text = co_await ReadFrameText(*stream, header->length);
                    (void)text;
                    logical->Close(ErrorCode::PROTOCOL_DECODE_FAILED);
                    break;
                }
                default:
                    if (auto ok = co_await discard_current(); !ok) {
                        logical->Close(ok.error());
                    } else {
                        logical->Close(ErrorCode::PROTOCOL_INVALID_COMMAND);
                    }
                    break;
            }
        }
    }
};

void Handler::CloseSession(std::shared_ptr<ClientSession> session) noexcept {
    if (session && session->stream) {
        session->CloseAll(ErrorCode::CANCELLED);
    }
}

void Handler::PruneSessionsLocked() {
    if (sessions_.empty() && idle_sessions_.empty()) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::shared_ptr<ClientSession>> kept;
    kept.reserve(sessions_.size());
    for (auto& session : sessions_) {
        if (!session || !session->stream) {
            CloseSession(session);
            continue;
        }
        if (session->closed.load()) {
            CloseSession(session);
            continue;
        }
        if (session->active_streams == 0 &&
            session->idle_since != std::chrono::steady_clock::time_point{} &&
            now - session->idle_since > idle_session_timeout_) {
            CloseSession(session);
            continue;
        }
        kept.push_back(std::move(session));
    }
    sessions_ = std::move(kept);

    std::vector<std::shared_ptr<ClientSession>> idle;
    idle.reserve(idle_sessions_.size());
    for (auto& session : idle_sessions_) {
        if (!session || session->closed.load() || !session->in_idle_pool || session->active_streams != 0) {
            continue;
        }
        idle.push_back(session);
    }

    const size_t keep_from = idle.size() > min_idle_sessions_
        ? idle.size() - min_idle_sessions_
        : 0;
    std::vector<std::shared_ptr<ClientSession>> kept_idle;
    kept_idle.reserve(idle.size());
    for (size_t i = 0; i < idle.size(); ++i) {
        auto& session = idle[i];
        if (i >= keep_from ||
            session->idle_since == std::chrono::steady_clock::time_point{} ||
            now - session->idle_since <= idle_session_timeout_) {
            kept_idle.push_back(session);
            continue;
        }
        session->in_idle_pool = false;
        CloseSession(session);
    }
    idle_sessions_ = std::move(kept_idle);
}

Handler::Handler(std::string tag,
                 Settings settings,
                 StreamSettings stream_settings,
                 std::chrono::seconds dial_timeout,
                 app::dns::DNS& dns_service)
    : tag_(std::move(tag))
    , settings_(std::move(settings))
    , stream_settings_(std::move(stream_settings))
    , dial_timeout_(dial_timeout)
    , dns_service_(&dns_service) {
    idle_session_check_interval_ = settings_.idle_session_check_interval;
    idle_session_timeout_ = settings_.idle_session_timeout;
    min_idle_sessions_ = settings_.min_idle_sessions;
    if (!settings_.literal_address) {
        settings_.literal_address = ParseLiteralAddress(settings_.address);
    }
    NormalizeOutboundStreamSettings(
        stream_settings_,
        OutboundStreamDefaults{
            .require_tls = true,
            .fallback_server_name = settings_.address,
        });
}

Handler::~Handler() noexcept {
    std::vector<std::shared_ptr<ClientSession>> sessions;
    {
        std::lock_guard lock(pool_mu_);
        sessions = std::move(sessions_);
        idle_sessions_.clear();
    }
    for (auto& session : sessions) {
        CloseSession(session);
    }
}

net::awaitable<OutboundProcessResult> Handler::Process(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    transport::Link inbound,
    StatsShard& stats,
    const RelayConfig& relay_config,
    std::span<const uint8_t> initial_payload,
    buf::MultiBuffer& first_payload,
    std::chrono::seconds /*relay_idle_timeout*/,
    std::chrono::seconds /*relay_write_timeout*/) {
    if (!inbound.Valid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!dns_service_) {
        co_return std::unexpected(ErrorCode::INTERNAL);
    }
    if (!stream_settings_.IsTls()) {
        LOG_CONN_FAIL_CTX(ctx, "[AnyTLSOutbound] TLS transport is required");
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    std::shared_ptr<ClientSession> session;
    {
        std::lock_guard lock(pool_mu_);
        PruneSessionsLocked();
        while (!idle_sessions_.empty() && !session) {
            auto candidate = idle_sessions_.back();
            idle_sessions_.pop_back();
            if (!candidate || !candidate->Available() || !candidate->in_idle_pool) {
                continue;
            }
            candidate->in_idle_pool = false;
            session = candidate;
        }
    }

    if (!session) {
        auto transport_target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
            .dns_service = dns_service_,
            .address = settings_.address,
            .literal_address = settings_.literal_address,
            .port = settings_.port,
            .stream_settings = &stream_settings_,
            .timeout = dial_timeout_,
            .send_through = settings_.send_through,
            .inbound_local_addr = inbound_local_addr,
            .server_name = ResolveOutboundServerName(stream_settings_, settings_.address),
        });
        if (!transport_target) {
            if (transport_target.error() == ErrorCode::DNS_RESOLVE_FAILED) {
                LOG_CONN_DEBUG(ctx, "[AnyTLSOutbound] DNS resolve failed for {}", settings_.address);
            }
            co_return std::unexpected(transport_target.error());
        }

        auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
        if (!dial_result.Ok()) {
            LOG_CONN_FAIL_CTX(ctx, "[AnyTLSOutbound] dial failed {} -> {} via {}: {}",
                              ctx.inbound.source_ip, ctx.outbound.target,
                              ctx.outbound.tag, dial_result.error_msg);
            co_return std::unexpected(dial_result.error);
        }

        auto new_stream = std::move(dial_result.stream);
        new_stream->SetStreamLabel("out");
        LOG_ACCESS(FormatAccessLog(ctx));

        new_stream->SetIdleTimeout(timeouts.HandshakeTimeout());
        auto deadline = new_stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

        const auto default_scheme = DefaultPaddingScheme();
        const uint16_t auth_padding_size = AuthPaddingSize(default_scheme);
        auto auth_hash = PasswordHash(settings_.password);
        std::vector<uint8_t> auth_packet(34 + auth_padding_size, 0);
        std::copy(auth_hash.begin(), auth_hash.end(), auth_packet.begin());
        auth_packet[32] = static_cast<uint8_t>(auth_padding_size >> 8);
        auth_packet[33] = static_cast<uint8_t>(auth_padding_size);

        if (auto ok = co_await WriteAll(
                *new_stream,
                std::span<const uint8_t>(
                    auth_packet.data(),
                    auth_packet.size())); !ok) {
            new_stream->Cancel();
            co_return std::unexpected(deadline.Expired() ? ErrorCode::TIMEOUT : ok.error());
        }
        session = std::make_shared<ClientSession>(io_context, std::move(new_stream));
        {
            std::lock_guard lock(pool_mu_);
            sessions_.push_back(session);
            PruneSessionsLocked();
        }
    } else if (session->stream) {
        LOG_CONN_DEBUG(ctx, "[AnyTLSOutbound] reuse idle session sid={}", session->next_sid);
    }

    if (!session || !session->stream) {
        co_return std::unexpected(ErrorCode::INTERNAL);
    }

    auto& stream = *session->stream;
    stream.SetIdleTimeout(timeouts.HandshakeTimeout());
    auto deadline = stream.StartPhaseDeadline(timeouts.HandshakeTimeout());

    const uint32_t sid = session->next_sid++;
    auto logical = session->RegisterLogicalStream(io_context, sid);
    auto cleanup_logical_stream = [&]() {
        session->UnregisterLogicalStream(sid);
        logical->Close(ErrorCode::CANCELLED);
        std::lock_guard lock(pool_mu_);
        if (session->active_streams > 0) {
            --session->active_streams;
        }
        if (session->active_streams == 0 && session->stream && !session->closed.load()) {
            session->idle_since = std::chrono::steady_clock::now();
        }
    };
    {
        std::lock_guard lock(pool_mu_);
        ++session->active_streams;
        session->idle_since = {};
    }
    if (!session->read_loop_started) {
        session->read_loop_started = true;
        auto read_session = session;
        net::co_spawn(
            io_context.get_executor(),
            [read_session]() -> net::awaitable<void> {
                co_await read_session->ReadLoop();
            },
            net::detached);
    }
    const bool is_udp = ctx.content.network == Network::UDP;
    const TargetAddress original_target = ctx.outbound.target;
    const TargetAddress stream_target = is_udp
        ? TargetAddress(kUotMagicAddress, 0)
        : ctx.outbound.target;
    auto target = EncodeSocksAddress(stream_target);
    if (!target) {
        stream.Cancel();
        cleanup_logical_stream();
        co_return std::unexpected(target.error());
    }

    std::string open_packet;
    auto syn_frame = BuildFrameBytes(kCmdSYN, sid, {});
    auto target_frame = BuildFrameBytes(
        kCmdPSH,
        sid,
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(target->data()), target->size()));
    if (!syn_frame || !target_frame) {
        stream.Cancel();
        cleanup_logical_stream();
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    open_packet.append(*syn_frame);
    open_packet.append(*target_frame);
    if (is_udp) {
        auto request = EncodeUotRequest(original_target, true);
        if (!request) {
            stream.Cancel();
            cleanup_logical_stream();
            co_return std::unexpected(request.error());
        }
        auto request_frame = BuildFrameBytes(
            kCmdPSH,
            sid,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(request->data()), request->size()));
        if (!request_frame) {
            stream.Cancel();
            cleanup_logical_stream();
            co_return std::unexpected(request_frame.error());
        }
        open_packet.append(*request_frame);
    }
    if (buf::TotalLen(first_payload) > 0) {
        for (auto* buffer : first_payload) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            auto frame = BuildFrameBytes(
                kCmdPSH,
                sid,
                buffer->Bytes());
            if (!frame) {
                stream.Cancel();
                cleanup_logical_stream();
                co_return std::unexpected(frame.error());
            }
            open_packet.append(*frame);
        }
        first_payload.clear();
    }
    if (!initial_payload.empty()) {
        auto frame = BuildFrameBytes(kCmdPSH, sid, initial_payload);
        if (!frame) {
            stream.Cancel();
            cleanup_logical_stream();
            co_return std::unexpected(frame.error());
        }
        open_packet.append(*frame);
    }
    if (auto ok = co_await session->WriteOpenPacket(sid, std::move(open_packet)); !ok) {
        stream.Cancel();
        logical->Close(ok.error());
        cleanup_logical_stream();
        co_return std::unexpected(deadline.Expired() ? ErrorCode::TIMEOUT : ok.error());
    }
    if (sid >= 2 && session->peer_version >= 2) {
        if (auto ok = co_await logical->WaitSynAck(std::chrono::seconds(3)); !ok) {
            session->CloseAll(ok.error());
            cleanup_logical_stream();
            co_return std::unexpected(ok.error());
        }
    }

    stream.SetIdleTimeout(std::chrono::seconds(0));
    stream.SetReadTimeout(std::chrono::seconds(0));
    stream.SetWriteTimeout(std::chrono::seconds(0));
    stream.ClearPhaseDeadline();

    struct LogicalEndpoint final : transport::MultiBufferReader,
                                   transport::MultiBufferWriter {
        std::shared_ptr<ClientSession> session;
        std::shared_ptr<ClientSession::LogicalStream> logical;
        uint32_t sid = 0;
        bool is_udp = false;
        TargetAddress original_target;

        LogicalEndpoint(std::shared_ptr<ClientSession> s,
                        std::shared_ptr<ClientSession::LogicalStream> l,
                        uint32_t stream_id,
                        bool udp,
                        TargetAddress target)
            : session(std::move(s))
            , logical(std::move(l))
            , sid(stream_id)
            , is_udp(udp)
            , original_target(std::move(target)) {}

        net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
            auto payload = co_await logical->ReadPayload();
            if (!payload) {
                if (payload.error() == ErrorCode::OK) {
                    co_return buf::MultiBuffer{};
                }
                throw IoSystemError(io_error::connection_reset, "AnyTLS logical stream closed");
            }
            if (is_udp) {
                for (auto* buffer : *payload) {
                    if (buffer && !buffer->IsEmpty()) {
                        buffer->SetUDP(original_target);
                    }
                }
            }
            co_return std::move(*payload);
        }

        net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
            if (mb.empty()) {
                co_return;
            }

            std::expected<void, ErrorCode> ok;
            if (is_udp) {
                std::string packet;
                for (auto* buffer : mb) {
                    if (!buffer || buffer->IsEmpty()) {
                        continue;
                    }
                    auto frame = BuildFrameBytes(kCmdPSH, sid, buffer->Bytes());
                    if (!frame) {
                        mb.clear();
                        logical->Close(frame.error());
                        throw IoSystemError(io_error::connection_reset, "AnyTLS UDP frame encode failed");
                    }
                    packet.append(*frame);
                }
                mb.clear();
                if (packet.empty()) {
                    co_return;
                }
                ok = co_await session->WriteUdpPacket(sid, std::move(packet));
            } else {
                ok = co_await session->WritePayloadFrames(sid, std::move(mb));
            }

            if (!ok) {
                logical->Close(ok.error());
                throw IoSystemError(io_error::connection_reset, "AnyTLS logical write failed");
            }
        }

        net::awaitable<void> AsyncShutdownWrite() override {
            if (session) {
                (void)co_await session->WriteFrameSerialized(kCmdFIN, sid, {});
            }
        }

        void Cancel() noexcept {
            if (logical) {
                logical->Close(ErrorCode::CANCELLED);
            }
        }

        bool ConsumeIdleTimeout() noexcept { return false; }
        bool ConsumeReadTimeout() noexcept { return false; }
        bool ConsumeWriteTimeout() noexcept { return false; }
    };

    LogicalEndpoint target_endpoint(
        session,
        logical,
        sid,
        is_udp,
        original_target);

    RelayResult result;
    if (buf::TotalLen(first_payload) > 0) {
        result = co_await DoRelayLinkWithFirstPacket(
            io_context,
            *inbound.reader,
            *inbound.writer,
            target_endpoint,
            ctx,
            stats,
            first_payload,
            relay_config);
    } else if (!initial_payload.empty()) {
        result = co_await DoRelayLinkWithFirstPacket(
            io_context,
            *inbound.reader,
            *inbound.writer,
            target_endpoint,
            ctx,
            stats,
            initial_payload,
            relay_config);
    } else {
        result = co_await DoRelayLink(
            io_context,
            *inbound.reader,
            *inbound.writer,
            target_endpoint,
            ctx,
            stats,
            relay_config);
    }

    try { co_await inbound.writer->AsyncShutdownWrite(); } catch (...) {}
    session->UnregisterLogicalStream(sid);
    logical->Close(result.error);
    if (result.error != ErrorCode::OK) {
        session->CloseAll(result.error);
    }
    {
        std::lock_guard lock(pool_mu_);
        if (session->active_streams > 0) {
            --session->active_streams;
        }
        if (result.error == ErrorCode::OK && session->active_streams == 0 && session->stream) {
            session->idle_since = std::chrono::steady_clock::now();
            if (!session->in_idle_pool && !session->closed.load()) {
                session->in_idle_pool = true;
                idle_sessions_.push_back(session);
            }
        }
        PruneSessionsLocked();
    }
    co_return result;
}

}  // namespace acpp::anytls::outbound

namespace {
const bool kOutboundRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kAnyTLS,
    [](const acpp::proxyman::outbound::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundConfig> {
        auto settings = ParseSettings(cfg.settings);
        if (!settings) {
            return std::nullopt;
        }
        settings->send_through = cfg.send_through;
        acpp::proxyman::outbound::PreparedOutboundConfig prepared;
        prepared.tag = cfg.tag;
        prepared.protocol = cfg.protocol;
        prepared.create =
            [tag = cfg.tag,
             settings = std::move(*settings),
             stream_settings = cfg.stream_settings](
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds dial_timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_stream_settings = stream_settings;
                acpp::NormalizeOutboundStreamSettings(
                    runtime_stream_settings,
                    acpp::OutboundStreamDefaults{
                        .require_tls = true,
                        .fallback_server_name = settings.address,
                    });
                return std::make_unique<acpp::anytls::outbound::Handler>(
                    tag,
                    settings,
                    runtime_stream_settings,
                    dial_timeout,
                    dns);
            };
        return prepared;
    }), true);
}  // namespace
