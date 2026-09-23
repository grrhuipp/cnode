#include "anytls_outbound.hpp"
#include "anytls_outbound_settings.hpp"
#include "session_pool.hpp"

#include "../anytls_codec.hpp"
#include "../padding.hpp"
#include "../payload_queue.hpp"
#include "../../uot/uot.hpp"
#include "../../../transport/internet/async_write_gate.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/cancellation_signal.hpp>
#include <asio/experimental/channel.hpp>
#include <algorithm>
#include <memory>
#include <optional>
#include <string>

namespace {

constexpr size_t kMaxLogicalQueuedPayloadBytes = acpp::anytls::kMaxFramePayload;

}  // namespace

namespace acpp::proxy::anytls::outbound {

using namespace ::acpp::anytls;

// One outbound client on its owning Worker. Physical tasks own this state,
// never the Handler; retiring a Handler cannot publish into its replacement.
struct Handler::PaddingState {
    std::shared_ptr<const PaddingScheme> scheme = DefaultPaddingScheme();
};

struct Handler::ClientSession {
    class LogicalStream final {
    public:
        explicit LogicalStream(net::io_context& io_context)
            : io_context_(io_context)
            , timeout_scheduler_(TimeoutScheduler::ForIoContext(io_context))
            , syn_signal_(io_context, 1)
            , payload_signal_(io_context, 1)
            , payload_space_signal_(io_context, 1) {}

        ~LogicalStream() noexcept {
            Close(ErrorCode::CANCELLED);
        }

        LogicalStream(const LogicalStream&) = delete;
        LogicalStream& operator=(const LogicalStream&) = delete;

        net::awaitable<void> PushPayload(buf::MultiBuffer mb) {
            const size_t bytes = mb.byte_size();
            if (bytes == 0 || closed_) co_return;
            // The physical reader owns this payload while capacity is used
            // by the logical queue. Awaiting consumption also stops TLS reads.
            while (!closed_ && queued_payload_.byte_size() + bytes > kMaxLogicalQueuedPayloadBytes) {
                auto [ec] = co_await payload_space_signal_.async_receive(
                    net::as_tuple(net::use_awaitable));
                if (ec) co_return;
            }
            if (closed_) co_return;
            AppendQueuedPayload(queued_payload_, std::move(mb));
            WakePayloadReader();
        }

        transport::CancellationSource& Cancellation() noexcept { return cancellation_; }

        void CheckWrite() const {
            if (error_ != ErrorCode::OK) throw transport::LinkError(error_);
            if (closed_) throw transport::WriteClosed();
        }

        void CloseRemote() noexcept {
            remote_closed_ = true;
            Close();
        }

        bool BeginLocalClose() noexcept {
            if (closed_) return false;
            queued_payload_.clear();
            Close();
            return true;
        }

        bool RemoteClosed() const noexcept { return remote_closed_; }

        void Close(ErrorCode error = ErrorCode::OK) noexcept {
            if (closed_ && (error_ != ErrorCode::OK || error == ErrorCode::OK)) return;
            // Publish the terminal state before cancellation can re-enter us.
            // An error after FIN discards unread bytes; the first error wins.
            closed_ = true;
            error_ = error;
            if (error != ErrorCode::OK) {
                queued_payload_.clear();
                cancellation_.Stop(error);
            }
            WakeOpenWaiter();
            WakePayloadReader();
            WakePayloadWriter();
        }

        void AckSyn() noexcept {
            syn_acked_ = true;
            WakeOpenWaiter();
        }

        net::awaitable<std::expected<void, ErrorCode>> WaitOpenResult(std::chrono::seconds timeout) {
            auto result = OpenResult();
            if (!result) {
                // The finite wait owns its deadline. ACK, FIN and errors are
                // persistent state; a channel notification is only a wakeup.
                const auto timeout_token = timeout_scheduler_.ScheduleAfter(
                    std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
                    [this]() {
                        if (!OpenResult()) Close(ErrorCode::TIMEOUT);
                    });
                do {
                    const auto [ec] = co_await syn_signal_.async_receive(
                        net::as_tuple(net::use_awaitable));
                    if (ec && !OpenResult()) Close(ErrorCode::CANCELLED);
                    result = OpenResult();
                } while (!result);
            }
            if (*result != ErrorCode::OK) co_return std::unexpected(*result);
            co_return std::expected<void, ErrorCode>{};
        }

        net::awaitable<std::expected<buf::MultiBuffer, ErrorCode>> ReadPayload() {
            while (queued_payload_.empty() && !closed_) {
                auto [ec] = co_await payload_signal_.async_receive(
                    net::as_tuple(net::use_awaitable));
                if (ec) {
                    co_return std::unexpected(ErrorCode::CANCELLED);
                }
            }
            if (!queued_payload_.empty()) {
                auto payload = std::move(queued_payload_);
                queued_payload_.ReleaseIfIdle();
                WakePayloadWriter();
                co_return payload;
            }
            queued_payload_.ReleaseIfIdle();
            co_return std::unexpected(error_);
        }

    private:
        void WakePayloadWriter() noexcept {
            if (!io_context_.stopped()) (void)payload_space_signal_.try_send(IoErrorCode{});
        }

        std::optional<ErrorCode> OpenResult() const noexcept {
            if (error_ != ErrorCode::OK) return error_;
            // Clean FIN may precede the ACK. Relay still owns delivery of
            // queued bytes and completion of both application directions.
            if (closed_ || syn_acked_) return ErrorCode::OK;
            return std::nullopt;
        }

        void WakeOpenWaiter() noexcept {
            if (!io_context_.stopped()) (void)syn_signal_.try_send(IoErrorCode{});
        }

        void WakePayloadReader() noexcept {
            if (io_context_.stopped()) {
                return;
            }
            (void)payload_signal_.try_send(IoErrorCode{});
        }

        transport::CancellationSource cancellation_;
        net::io_context& io_context_;
        TimeoutScheduler& timeout_scheduler_;
        net::experimental::channel<void(IoErrorCode)> syn_signal_;
        net::experimental::channel<void(IoErrorCode)> payload_signal_;
        net::experimental::channel<void(IoErrorCode)> payload_space_signal_;
        buf::MultiBuffer queued_payload_;
        ErrorCode error_ = ErrorCode::OK;
        bool closed_ = false;
        bool remote_closed_ = false;
        bool syn_acked_ = false;
    };

    ClientSession(net::io_context& io_context, std::unique_ptr<AsyncStream> s,
                  std::shared_ptr<PaddingState> padding_state,
                  std::shared_ptr<const PaddingScheme> opening_scheme)
        : io_context_(io_context)
        , stream(std::move(s))
        , padding_state_(std::move(padding_state))
        , opening_scheme_(std::move(opening_scheme))
        , write_gate(io_context) {}

    net::io_context& io_context_;
    std::unique_ptr<AsyncStream> stream;
    std::shared_ptr<PaddingState> padding_state_;
    // Authentication, first settings, and first framed write use one snapshot.
    // Releasing it also records that settings have been sent successfully.
    std::shared_ptr<const PaddingScheme> opening_scheme_;
    uint32_t next_sid = 1;
    uint32_t packet_index = 1;
    std::optional<SessionVersion> session_version;
    transport::internet::AsyncWriteGate write_gate;
    acpp::memory::ThreadLocalUnorderedMap<
        uint32_t,
        std::weak_ptr<LogicalStream>>
        logical_streams;
    size_t active_streams = 0;
    net::cancellation_signal task_cancellation;
    bool closed = false;

    net::cancellation_slot CancellationSlot() noexcept { return task_cancellation.slot(); }

    [[nodiscard]] bool IsClosed() const noexcept { return closed || !stream; }

    uint32_t NextPacketIndex() noexcept {
        const auto index = packet_index;
        // Index zero belongs to authentication. Saturate before wrapping into it.
        if (packet_index != UINT32_MAX) ++packet_index;
        return index;
    }

    [[nodiscard]] bool Available() const noexcept {
        return !closed && stream && active_streams == 0;
    }

    std::shared_ptr<LogicalStream> RegisterLogicalStream(uint32_t sid) {
        auto logical = memory::AllocateShared<LogicalStream>(io_context_);
        logical_streams[sid] = logical;
        return logical;
    }

    void UnregisterLogicalStream(uint32_t sid) {
        logical_streams.erase(sid);
    }

    void CloseAll(ErrorCode error) noexcept {
        if (closed) return;
        closed = true;
        write_gate.Cancel();
        task_cancellation.emit(net::cancellation_type::all);
        for (auto& [sid, weak] : logical_streams) {
            (void)sid;
            if (auto logical = weak.lock()) {
                logical->Close(error);
            }
        }
        logical_streams.clear();
        if (stream) {
            stream->CloseAbortive();
        }
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteOpenPacket(memory::ByteVector packet) {
        auto write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }

        try {
            auto scheme_snapshot = opening_scheme_ ? opening_scheme_ : padding_state_->scheme;
            if (opening_scheme_) {
                const auto settings = ClientSettings(*scheme_snapshot);
                memory::ByteVector with_settings;
                with_settings.reserve(packet.size() + kFrameHeaderSize + settings.size());
                auto settings_frame = AppendFrameBytesTo(
                    with_settings,
                    kCmdSettings,
                    0,
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(settings.data()), settings.size()));
                if (!settings_frame) {
                    co_return std::unexpected(settings_frame.error());
                }
                with_settings.insert(with_settings.end(), packet.begin(), packet.end());
                packet = std::move(with_settings);
            }

            const uint32_t this_packet = NextPacketIndex();
            auto ok = co_await WritePacketWithPadding(
                *stream, *scheme_snapshot, this_packet, std::move(packet));
            if (!ok) {
                CloseAll(ok.error());
                co_return std::unexpected(ok.error());
            }
            opening_scheme_.reset();
            co_return std::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception()));
            throw;
        }
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WritePayloadFrames(uint32_t sid, LogicalStream& logical, buf::MultiBuffer mb) {
        auto write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            mb.clear();
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }

        logical.CheckWrite();

        try {
            auto scheme_snapshot = padding_state_->scheme;
            const uint32_t this_packet = NextPacketIndex();
            auto ok = co_await WriteMultiBufferAsFramesWithPadding(
                *stream, *scheme_snapshot, this_packet, kCmdPSH, sid, std::move(mb));
            if (!ok) {
                CloseAll(ok.error());
                co_return std::unexpected(ok.error());
            }
            co_return std::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception()));
            throw;
        }
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WritePayloadBuffers(uint32_t sid, LogicalStream& logical, std::span<const net::const_buffer> buffers) {
        bool has_data = false;
        for (const net::const_buffer& buffer : buffers) {
            if (buffer.data() && buffer.size() > 0) {
                has_data = true;
                break;
            }
        }
        if (!has_data) {
            co_return std::expected<void, ErrorCode>{};
        }

        auto write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }

        logical.CheckWrite();

        try {
            auto scheme_snapshot = padding_state_->scheme;
            const uint32_t this_packet = NextPacketIndex();
            auto ok = co_await WriteBuffersAsFramesWithPadding(
                *stream, *scheme_snapshot, this_packet, kCmdPSH, sid, buffers);
            if (!ok) {
                CloseAll(ok.error());
                co_return std::unexpected(ok.error());
            }
            co_return std::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception()));
            throw;
        }
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteFrameSerialized(uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
        auto write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }
        if (cmd == kCmdFIN) {
            const auto found = logical_streams.find(sid);
            if (found != logical_streams.end()) {
                if (auto logical = found->second.lock(); logical && logical->RemoteClosed())
                    co_return std::expected<void, ErrorCode>{};
            }
        }

        try {
            auto ok = co_await WriteFrame(*stream, cmd, sid, payload);
            if (!ok) {
                CloseAll(ok.error());
                co_return std::unexpected(ok.error());
            }
            co_return std::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception()));
            throw;
        }
    }

    net::awaitable<void> Run() {
        while (!closed && stream) {
            auto header = co_await ReadFrameHeader(*stream);
            if (!header) {
                CloseAll(header.error());
                co_return;
            }

            const bool supports_v2 = session_version == SessionVersion::V2;
            if (header->cmd == kCmdSettings || header->cmd == kCmdSYN ||
                ((header->cmd == kCmdServerSettings || header->cmd == kCmdUpdatePaddingScheme) && header->sid != 0) ||
                ((header->cmd == kCmdHeartRequest || header->cmd == kCmdHeartResponse) &&
                    (!supports_v2 || header->sid != 0 || header->length != 0)) ||
                (header->cmd == kCmdSYNACK && (!supports_v2 || header->sid == 0))) {
                CloseAll(ErrorCode::PROTOCOL_INVALID_COMMAND);
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
                        if (session_version) {
                            CloseAll(ErrorCode::PROTOCOL_INVALID_COMMAND);
                            co_return;
                        }
                        auto text = co_await ReadFrameText(*stream, header->length);
                        if (!text) { CloseAll(text.error()); co_return; }
                        auto parsed = ParsePeerSettings(*text);
                        if (!parsed) { CloseAll(parsed.error()); co_return; }
                        session_version = parsed->version;
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
                                padding_state_->scheme =
                                    memory::AllocateShared<const PaddingScheme>(std::move(*parsed));
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
            auto stream_it = logical_streams.find(header->sid);
            logical = stream_it == logical_streams.end()
                ? std::shared_ptr<LogicalStream>{}
                : stream_it->second.lock();
            if (!logical && stream_it != logical_streams.end()) {
                logical_streams.erase(stream_it);
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
                        if (!text) {
                            CloseAll(text.error());
                            co_return;
                        }
                        logical->Close(ErrorCode::PROTOCOL_DECODE_FAILED);
                    } else {
                        logical->AckSyn();
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
                    co_await logical->PushPayload(std::move(*payload));
                    break;
                }
                case kCmdFIN:
                    if (auto ok = co_await discard_current(); !ok) {
                        logical->Close(ok.error());
                    } else {
                        logical->CloseRemote();
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

struct Handler::LogicalStreamLease {
    SessionPool<ClientSession>::Lease& transport_lease;
    std::shared_ptr<ClientSession> session;
    std::shared_ptr<ClientSession::LogicalStream> logical;
    uint32_t sid = 0;
    bool cleaned = false;

    LogicalStreamLease(
        SessionPool<ClientSession>::Lease& transport_lease,
        std::shared_ptr<ClientSession> session,
        std::shared_ptr<ClientSession::LogicalStream> logical,
        uint32_t sid) noexcept
        : transport_lease(transport_lease)
        , session(std::move(session))
        , logical(std::move(logical))
        , sid(sid) {
        ++this->session->active_streams;
    }

    ~LogicalStreamLease() noexcept { Cleanup(ErrorCode::CANCELLED); }

    LogicalStreamLease(const LogicalStreamLease&) = delete;
    LogicalStreamLease& operator=(const LogicalStreamLease&) = delete;

    void Finish(ErrorCode error) noexcept {
        Cleanup(error);
        if (error == ErrorCode::OK) transport_lease.Reuse();
    }

private:
    void Cleanup(ErrorCode error) noexcept {
        if (cleaned) return;
        cleaned = true;
        session->UnregisterLogicalStream(sid);
        logical->Close(error);
        if (session->active_streams > 0) --session->active_streams;
    }
};

Handler::Handler(std::string tag,
                 net::io_context& io_context,
                 Settings settings,
                 StreamSettings stream_settings,
                 std::chrono::seconds dial_timeout,
                 app::dns::DNS& dns_service)
    : tag_(std::move(tag))
    , settings_(std::move(settings))
    , stream_settings_(std::move(stream_settings))
    , dial_timeout_(dial_timeout)
    , dns_service_(dns_service)
    , padding_(memory::AllocateShared<PaddingState>())
    , pool_(std::make_unique<SessionPool<ClientSession>>(
          io_context, settings_.idle_session_check_interval,
          settings_.idle_session_timeout, settings_.min_idle_sessions, tag_)) {}

Handler::~Handler() noexcept = default;

net::awaitable<OutboundProcessResult> Handler::Process(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    transport::Link inbound,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBuffer first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const bool ordered_bind = settings_.send_through.GetMode() == OutboundBind::Mode::Ordered;
    const auto selected_v4 = ordered_bind
        ? settings_.send_through.Select(net::ip::address_v4::any(),
            ctx.inbound.source_ip, ctx.inbound.source_port)
        : OutboundBind::Selection{};
    const auto selected_v6 = ordered_bind
        ? settings_.send_through.Select(net::ip::address_v6::any(),
            ctx.inbound.source_ip, ctx.inbound.source_port)
        : OutboundBind::Selection{};
    auto transport_lease = ordered_bind
        ? pool_->AcquireIf([&](const ClientSession& physical) {
            if (!physical.stream) return false;
            const auto remote = physical.stream->RemoteEndpoint();
            const auto local = physical.stream->LocalEndpoint();
            if (!remote || !local) return false;
            const auto& selected = remote->address().is_v6() ? selected_v6 : selected_v4;
            return !selected.address ||
                iputil::NormalizeAddress(local->address()) == *selected.address;
        })
        : pool_->Acquire();
    std::shared_ptr<ClientSession> session = transport_lease.Get();

    if (!session) {
        auto transport_target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
            .dns_service = &dns_service_,
            .address = settings_.address,
            .literal_address = settings_.literal_address,
            .port = settings_.port,
            .stream_settings = &stream_settings_,
            .timeout = dial_timeout_,
            .send_through = &settings_.send_through,
            .inbound_local_addr = inbound_local_addr,
            .inbound_source_ip = ctx.inbound.source_ip,
            .inbound_source_port = ctx.inbound.source_port,
            .ordered_bind_v4 = ordered_bind
                ? std::optional{selected_v4} : std::nullopt,
            .ordered_bind_v6 = ordered_bind
                ? std::optional{selected_v6} : std::nullopt,
            .tls_server_name = ResolveOutboundTlsServerName(
                stream_settings_, settings_.address),
            .ws_host = settings_.address,
        });
        if (!transport_target) {
            if (transport_target.error() == ErrorCode::DNS_RESOLVE_FAILED) {
                LOG_CONN_DEBUG(ctx, "[AnyTLSOutbound] DNS resolve failed for {}", settings_.address);
            }
            co_return std::unexpected(transport_target.error());
        }

        auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
        if (!dial_result.Ok()) {
            LOG_CONN_WARN(ctx, "[AnyTLSOutbound] dial failed {} -> {} via {}: {}",
                              ctx.inbound.source_ip, ctx.outbound.target,
                              ctx.outbound.tag, dial_result.error_msg);
            co_return std::unexpected(dial_result.error);
        }

        auto new_stream = std::move(dial_result.stream);
        new_stream->SetStreamLabel("out");
        if (auto local_ep = new_stream->LocalEndpoint();
            local_ep && !local_ep->address().is_unspecified()) {
            ctx.outbound.connected_local_addr = local_ep->address();
            ctx.outbound.connected_local_port = local_ep->port();
        }
        LOG_ACCESS(FormatAccessLog(ctx));

        new_stream->SetIdleTimeout(timeouts.HandshakeTimeout());
        auto deadline = new_stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

        auto opening_scheme = padding_->scheme;
        const uint16_t auth_padding_size = opening_scheme->SampleAuthPaddingSize();
        memory::ByteVector auth_packet(34 + auth_padding_size, uint8_t{0});
        std::copy(settings_.password_hash.begin(), settings_.password_hash.end(), auth_packet.begin());
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
        session = memory::AllocateShared<ClientSession>(io_context, std::move(new_stream),
            padding_, std::move(opening_scheme));
        transport_lease = pool_->Adopt(session);
    } else if (session->stream) {
        LOG_CONN_DEBUG(ctx, "[AnyTLSOutbound] reuse idle session sid={}", session->next_sid);
    }

    if (!session || !session->stream) {
        co_return std::unexpected(ErrorCode::INTERNAL);
    }

    auto& stream = *session->stream;
    if (auto local_ep = stream.LocalEndpoint();
        local_ep && !local_ep->address().is_unspecified()) {
        ctx.outbound.connected_local_addr = local_ep->address();
        ctx.outbound.connected_local_port = local_ep->port();
    }
    stream.SetIdleTimeout(timeouts.HandshakeTimeout());
    auto deadline = stream.StartPhaseDeadline(timeouts.HandshakeTimeout());

    const uint32_t sid = session->next_sid++;
    auto logical = session->RegisterLogicalStream(sid);
    LogicalStreamLease logical_lease(transport_lease, session, logical, sid);
    const bool is_udp = ctx.content.network == Network::UDP;
    const TargetAddress original_target = ctx.outbound.target;
    const TargetAddress stream_target = is_udp
        ? TargetAddress(proxy::uot::kMagicAddress, 0)
        : ctx.outbound.target;
    auto target = EncodeSocksAddress(stream_target);
    if (!target) {
        stream.Cancel();
        co_return std::unexpected(target.error());
    }

    memory::ByteVector open_packet;
    open_packet.reserve((kFrameHeaderSize * 3) + target->size() + 128);
    auto syn_frame = AppendFrameBytesTo(open_packet, kCmdSYN, sid, {});
    auto target_frame = AppendFrameBytesTo(
        open_packet,
        kCmdPSH,
        sid,
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(target->data()), target->size()));
    if (!syn_frame || !target_frame) {
        stream.Cancel();
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    if (is_udp) {
        auto request = proxy::uot::EncodeRequest(true, original_target);
        if (!request) {
            stream.Cancel();
            co_return std::unexpected(request.error());
        }
        auto request_frame = AppendFrameBytesTo(
            open_packet,
            kCmdPSH,
            sid,
            request->span());
        if (!request_frame) {
            stream.Cancel();
            co_return std::unexpected(request_frame.error());
        }
    }
    if (auto ok = co_await session->WriteOpenPacket(std::move(open_packet)); !ok) {
        stream.Cancel();
        logical->Close(ok.error());
        co_return std::unexpected(deadline.Expired() ? ErrorCode::TIMEOUT : ok.error());
    }
    if (sid >= 2 && session->session_version == SessionVersion::V2) {
        if (auto ok = co_await logical->WaitOpenResult(std::chrono::seconds(3)); !ok) {
            session->CloseAll(ok.error());
            co_return std::unexpected(ok.error());
        }
    }

    // A pool lease exclusively owns this physical session for the request.
    // Its background reader must observe the same deadlines as relay writes.
    stream.SetIdleTimeout(relay_idle_timeout);
    stream.SetReadTimeout(std::chrono::seconds(0));
    stream.SetWriteTimeout(relay_write_timeout);
    stream.ClearPhaseDeadline();

    struct LogicalEndpoint final : transport::MultiBufferReader,
                                   transport::MultiBufferWriter {
        std::shared_ptr<ClientSession> session;
        std::shared_ptr<ClientSession::LogicalStream> logical;
        uint32_t sid = 0;
        bool is_udp = false;
        TargetAddress original_target;
        bool cancelled = false;
        size_t pending_writes = 0;

        struct PendingWrite {
            size_t& count;
            explicit PendingWrite(size_t& count) noexcept : count(count) { ++count; }
            ~PendingWrite() noexcept { --count; }
            PendingWrite(const PendingWrite&) = delete;
            PendingWrite& operator=(const PendingWrite&) = delete;
        };

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
                throw transport::LinkError(payload.error());
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

        transport::EofAction ReadEofAction() const noexcept override { return transport::EofAction::CloseLink; }
        bool WriteShutdownClosesLink() const noexcept override { return true; }

        net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
            if (!buf::HasData(mb)) {
                co_return;
            }
            if (cancelled) {
                throw transport::LinkError(ErrorCode::CANCELLED);
            }
            logical->CheckWrite();

            PendingWrite pending(pending_writes);
            auto ok = co_await session->WritePayloadFrames(sid, *logical, std::move(mb));
            if (!ok) {
                logical->Close(ok.error());
                throw transport::LinkError(ok.error());
            }
        }

        net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
            if (cancelled) {
                throw transport::LinkError(ErrorCode::CANCELLED);
            }
            logical->CheckWrite();
            PendingWrite pending(pending_writes);
            auto ok = co_await session->WritePayloadBuffers(sid, *logical, buffers);
            if (!ok) {
                logical->Close(ok.error());
                throw transport::LinkError(ok.error());
            }
        }

        net::awaitable<void> AsyncShutdownWrite() override {
            if (!cancelled && logical->BeginLocalClose()) {
                PendingWrite pending(pending_writes);
                if (auto ok = co_await session->WriteFrameSerialized(kCmdFIN, sid, {}); !ok) {
                    throw transport::LinkError(ok.error());
                }
            }
        }

        transport::CancellationSource& Cancellation() noexcept override { return logical->Cancellation(); }

        void Cancel() noexcept {
            cancelled = true;
            logical->Close(ErrorCode::CANCELLED);
            // Relay also calls Cancel after a successful join. Preserve that
            // idle transport, but abort a pending gate/write: a partial frame
            // cannot safely be handed to the next request.
            if (pending_writes != 0) session->CloseAll(ErrorCode::CANCELLED);
        }

        void SetIdleTimeout(std::chrono::seconds timeout) {
            session->stream->SetIdleTimeout(timeout);
        }
        void SetReadTimeout(std::chrono::seconds timeout) {
            session->stream->SetReadTimeout(timeout);
        }
        void SetWriteTimeout(std::chrono::seconds timeout) {
            session->stream->SetWriteTimeout(timeout);
        }
        PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
            return session->stream->StartPhaseDeadline(timeout);
        }
        void ClearPhaseDeadline() { session->stream->ClearPhaseDeadline(); }
        bool ConsumeIdleTimeout() noexcept { return session->stream->ConsumeIdleTimeout(); }
        bool ConsumeReadTimeout() noexcept { return session->stream->ConsumeReadTimeout(); }
        bool ConsumeWriteTimeout() noexcept { return session->stream->ConsumeWriteTimeout(); }
        bool ConsumePhaseDeadline() noexcept { return session->stream->ConsumePhaseDeadline(); }
    };

    LogicalEndpoint target_endpoint(
        session,
        logical,
        sid,
        is_udp,
        original_target);

    RelayResult result;
    auto* inbound_control = inbound.control;
    auto relay_endpoint = [&](auto& endpoint) -> net::awaitable<RelayResult> {
        if (inbound_control) {
            co_return co_await DoRelayLink(
                io_context, *inbound.reader, *inbound.writer, *inbound_control,
                endpoint, ctx, stats, relay_config, std::move(first_payload));
        }
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer,
            endpoint, ctx, stats, relay_config, std::move(first_payload));
    };

    if (is_udp) {
        proxy::uot::FramedEndpoint uot_endpoint(
            target_endpoint, true, original_target);
        result = co_await relay_endpoint(uot_endpoint);
    } else {
        result = co_await relay_endpoint(target_endpoint);
    }

    if (result.error == ErrorCode::OK) {
        // Request and half-close deadlines must not escape into the idle pool.
        stream.SetIdleTimeout(std::chrono::seconds(0));
        stream.SetReadTimeout(std::chrono::seconds(0));
        stream.SetWriteTimeout(std::chrono::seconds(0));
        stream.ClearPhaseDeadline();
    }
    logical_lease.Finish(result.error);
    co_return result;
}

}  // namespace acpp::proxy::anytls::outbound

namespace {
const bool kOutboundRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kAnyTLS,
    [](const acpp::infra::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        auto settings = acpp::proxy::anytls::outbound::ParseSettings(cfg.settings);
        if (!settings) {
            LOG_ERROR("AnyTLS outbound '{}': invalid settings: {}",
                      cfg.tag, settings.error());
            return std::nullopt;
        }
        settings->send_through = cfg.send_through.value_or(acpp::OutboundBind{});
        auto prepared_stream_settings = acpp::NormalizeOutboundStreamSettings(
            cfg.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = true,
                .fallback_server_name = settings->address,
                .allow_insecure = false,
                .alpn = {},
            });
        return acpp::proxyman::outbound::PreparedOutboundCreator{
            [settings = std::move(*settings),
             stream_settings = std::move(prepared_stream_settings)](
                std::string_view tag,
                acpp::net::io_context& io_context,
                acpp::app::dns::DNS& dns,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds dial_timeout) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<acpp::proxy::anytls::outbound::Handler>(
                    std::string(tag),
                    io_context,
                    settings,
                    stream_settings,
                    dial_timeout,
                    dns);
            }};
    }), true);
}  // namespace
