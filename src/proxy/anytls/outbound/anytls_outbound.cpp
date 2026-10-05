#include "anytls_outbound.hpp"
#include "anytls_outbound_settings.hpp"
#include "acppnode/runtime/channel.hpp"
#include "../../../transport/internet/connection_timeouts.hpp"
#include <asio/strand.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>

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
namespace { ErrorCode SessionExceptionError(const std::exception_ptr& failure) noexcept; }

struct PhysicalSessionState {
    class LogicalStream final {
    public:
        explicit LogicalStream(net::any_io_executor executor)
            : executor_(executor)
            , timeout_scheduler_(TimeoutScheduler::ForExecutor(executor))
            , syn_signal_(executor, 1)
            , payload_signal_(executor, 1)
            , payload_space_signal_(executor, 1) {}

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

        net::awaitable<tl::expected<void, ErrorCode>> WaitOpenResult(std::chrono::seconds timeout) {
            auto result = OpenResult();
            if (!result) {
                // The finite wait owns its deadline. ACK, FIN and errors are
                // persistent state; a channel notification is only a wakeup.
                const auto timeout_token = timeout_scheduler_.ScheduleAfter(
                    std::chrono::duration_cast<std::chrono::milliseconds>(timeout), executor_,
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
            if (*result != ErrorCode::OK) co_return tl::unexpected(*result);
            co_return tl::expected<void, ErrorCode>{};
        }

        net::awaitable<tl::expected<buf::MultiBuffer, ErrorCode>> ReadPayload() {
            while (queued_payload_.empty() && !closed_) {
                auto [ec] = co_await payload_signal_.async_receive(
                    net::as_tuple(net::use_awaitable));
                if (ec) {
                    co_return tl::unexpected(ErrorCode::CANCELLED);
                }
            }
            if (!queued_payload_.empty()) {
                auto payload = std::move(queued_payload_);
                queued_payload_.ReleaseIfIdle();
                WakePayloadWriter();
                co_return payload;
            }
            queued_payload_.ReleaseIfIdle();
            co_return tl::unexpected(error_);
        }

    private:
        void WakePayloadWriter() noexcept {
            (void)payload_space_signal_.try_send(IoErrorCode{});
        }

        std::optional<ErrorCode> OpenResult() const noexcept {
            if (error_ != ErrorCode::OK) return error_;
            // Clean FIN may precede the ACK. Relay still owns delivery of
            // queued bytes and completion of both application directions.
            if (closed_ || syn_acked_) return ErrorCode::OK;
            return std::nullopt;
        }

        void WakeOpenWaiter() noexcept {
            (void)syn_signal_.try_send(IoErrorCode{});
        }

        void WakePayloadReader() noexcept {
            (void)payload_signal_.try_send(IoErrorCode{});
        }

        transport::CancellationSource cancellation_;
        net::any_io_executor executor_;
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

    PhysicalSessionState(net::any_io_executor executor, std::unique_ptr<AsyncStream> s,
                  std::shared_ptr<const PaddingScheme> padding_scheme,
                  std::shared_ptr<const PaddingScheme> opening_scheme)
        : executor_(executor)
        , stream(std::move(s))
        , padding_scheme_(std::move(padding_scheme))
        , opening_scheme_(std::move(opening_scheme))
        , write_gate(executor) {}

    net::any_io_executor executor_;
    std::unique_ptr<AsyncStream> stream;
    std::shared_ptr<const PaddingScheme> padding_scheme_;
    // Authentication, first settings, and first framed write use one snapshot.
    // Releasing it also records that settings have been sent successfully.
    std::shared_ptr<const PaddingScheme> opening_scheme_;
    uint32_t next_sid = 1;
    uint32_t packet_index = 1;
    std::optional<SessionVersion> session_version;
    transport::internet::AsyncWriteGate write_gate;
    acpp::memory::DataUnorderedMap<
        uint32_t,
        std::shared_ptr<LogicalStream>>
        logical_streams;
    size_t active_streams = 0;
    net::cancellation_signal task_cancellation;
    bool closed = false;
    ErrorCode terminal_error = ErrorCode::CONNECTION_CLOSED;

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
        auto logical = memory::AllocateShared<LogicalStream>(executor_);
        logical_streams[sid] = logical;
        return logical;
    }

    void UnregisterLogicalStream(uint32_t sid) {
        logical_streams.erase(sid);
    }

    void CloseAll(ErrorCode error) noexcept {
        if (closed) return;
        terminal_error = error;
        closed = true;
        write_gate.Cancel();
        task_cancellation.emit(net::cancellation_type::all);
        for (auto& [sid, weak] : logical_streams) {
            (void)sid;
            if (auto logical = weak) {
                logical->Close(error);
            }
        }
        logical_streams.clear();
        if (stream) {
            stream->CloseAbortive();
        }
    }

    net::awaitable<tl::expected<void, ErrorCode>>
    WriteOpenPacket(memory::ByteVector packet) {
        auto write_lease = write_gate.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            co_return tl::unexpected(terminal_error);
        }

        try {
            auto scheme_snapshot = opening_scheme_ ? opening_scheme_ : padding_scheme_;
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
                    co_return tl::unexpected(settings_frame.error());
                }
                with_settings.insert(with_settings.end(), packet.begin(), packet.end());
                packet = std::move(with_settings);
            }

            const uint32_t this_packet = NextPacketIndex();
            auto ok = co_await WritePacketWithPadding(
                *stream, *scheme_snapshot, this_packet, std::move(packet));
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            opening_scheme_.reset();
            co_return tl::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception()));
            throw;
        }
    }

    net::awaitable<tl::expected<void, ErrorCode>>
    WritePayloadFrames(uint32_t sid, LogicalStream& logical, buf::MultiBuffer mb) {
        auto write_lease = write_gate.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            mb.clear();
            co_return tl::unexpected(terminal_error);
        }

        logical.CheckWrite();

        try {
            auto scheme_snapshot = padding_scheme_;
            const uint32_t this_packet = NextPacketIndex();
            auto ok = co_await WriteMultiBufferAsFramesWithPadding(
                *stream, *scheme_snapshot, this_packet, kCmdPSH, sid, std::move(mb));
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            co_return tl::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception()));
            throw;
        }
    }

    net::awaitable<tl::expected<void, ErrorCode>>
    WriteFrameSerialized(uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
        auto write_lease = write_gate.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            co_return tl::unexpected(terminal_error);
        }
        if (cmd == kCmdFIN) {
            const auto found = logical_streams.find(sid);
            if (found != logical_streams.end()) {
                if (auto logical = found->second; logical && logical->RemoteClosed())
                    co_return tl::expected<void, ErrorCode>{};
            }
        }

        try {
            auto ok = co_await WriteFrame(*stream, cmd, sid, payload);
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            co_return tl::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception()));
            throw;
        }
    }

    template <typename PublishPadding>
    net::awaitable<void> Run(PublishPadding publish_padding) {
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

            auto discard_current = [&]() -> net::awaitable<tl::expected<void, ErrorCode>> {
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
                                padding_scheme_ =
                                    memory::AllocateShared<const PaddingScheme>(std::move(*parsed));
                                co_await publish_padding(padding_scheme_);
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
                : stream_it->second;
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

namespace {
ErrorCode SessionExceptionError(const std::exception_ptr& failure) noexcept {
    try { std::rethrow_exception(failure); }
    catch (const transport::LinkError& error) { return error.code(); }
    catch (const std::bad_alloc&) { return ErrorCode::RESOURCE_EXHAUSTED; }
    catch (const IoSystemError& error) { return MapAsioError(error.code()); }
    catch (...) { return ErrorCode::INTERNAL; }
}

struct ClientConfig {
    Settings settings;
    StreamSettings stream;
    std::chrono::seconds dial_timeout;
    app::dns::DNS& dns;
};

// Dialing receives owned metadata. It never borrows the caller's live Context.
struct OpenMessage {
    session::Inbound inbound;
    session::Outbound outbound;
    session::Content content;
    std::string transport;
    std::string outbound_tag;
    session::ID id = 0;
    std::chrono::seconds handshake_timeout;

    OpenMessage(const session::Context& context, std::chrono::seconds timeout)
        : inbound(context.inbound), outbound(context.outbound), content(context.content),
          transport(context.inbound.transport), outbound_tag(context.outbound.tag),
          id(context.conn_id), handshake_timeout(timeout) {}
};
struct OpenReply {
    ErrorCode error = ErrorCode::OK;
    uint32_t sid = 0;
    session::Outbound outbound;
    std::optional<tcp::endpoint> local;
    std::optional<tcp::endpoint> remote;
};
struct ReturnReply {
    bool reusable = false;
};
} // namespace

// Only this bounded actor can enter a physical protocol session. Callers retain
// its entry capability and logical ID; socket, codec and queues remain private.
struct Handler::ClientSession : std::enable_shared_from_this<ClientSession> {
    ClientSession(net::any_io_executor executor, std::shared_ptr<const ClientConfig> config,
                  std::shared_ptr<const PaddingScheme> padding, std::weak_ptr<Pool> pool)
        : channel_(std::move(executor), 8), config_(std::move(config)),
          initial_padding_(std::move(padding)), pool_(std::move(pool)) {}

    static net::awaitable<void> PublishPadding(
        std::weak_ptr<Pool> weak_pool, std::shared_ptr<const PaddingScheme> padding);
    static net::awaitable<void> NotifyRetired(std::weak_ptr<Pool> weak_pool,
                                              std::shared_ptr<ClientSession> client);

    [[nodiscard]] ServiceChannel::Reservation Reserve() noexcept { return channel_.TryReserve(); }
    net::awaitable<bool> Available() {
        co_return co_await channel_.Call([self = shared_from_this()] {
            return !self->stopping_ && (!self->state_ || self->state_->Available());
        });
    }
    net::awaitable<OpenReply> Open(OpenMessage message) {
        co_return co_await channel_.Post(OpenOwned(shared_from_this(), std::move(message)));
    }
    net::awaitable<buf::MultiBuffer> Read(uint32_t sid) {
        co_return co_await channel_.Post(ReadOwned(shared_from_this(), sid));
    }
    net::awaitable<void> Write(uint32_t sid, buf::MultiBuffer payload) {
        co_await channel_.Post(WriteOwned(shared_from_this(), sid, std::move(payload)));
    }
    net::awaitable<void> ShutdownWrite(uint32_t sid) {
        co_await channel_.Post(ShutdownOwned(shared_from_this(), sid));
    }
    net::awaitable<ReturnReply> Finish(uint32_t sid, ErrorCode error) {
        co_return co_await channel_.PostCommitted(FinishOwned(shared_from_this(), sid, error));
    }
    bool Cancel(ServiceChannel::Reservation ticket, uint32_t sid, bool abort_physical,
                ErrorCode error) noexcept {
        try {
            return channel_.SendReserved(std::move(ticket),
                [self = shared_from_this(), sid, abort_physical, error] {
                    if (!self->state_) return;
                    if (abort_physical) self->state_->CloseAll(error);
                    else if (const auto it = self->state_->logical_streams.find(sid);
                             it != self->state_->logical_streams.end()) it->second->Close(error);
                });
        } catch (...) { return false; }
    }
    net::awaitable<void> Stop(ServiceChannel::Reservation& ticket) {
        co_await channel_.PostReserved(ticket, StopOwned(shared_from_this()));
    }

private:
    static net::awaitable<OpenReply> OpenOwned(std::shared_ptr<ClientSession> self,
                                               OpenMessage message) {
        OpenReply reply;
        const auto executor = self->channel_.Executor();
        session::Context context(executor);
        context.inbound = std::move(message.inbound);
        context.outbound = std::move(message.outbound);
        context.content = std::move(message.content);
        context.inbound.transport = message.transport;
        context.outbound.tag = message.outbound_tag;
        context.conn_id = message.id;
        try {
            if (self->stopping_) throw transport::LinkError(ErrorCode::CANCELLED);
            if (!self->state_) {
                self->state_ = std::make_unique<PhysicalSessionState>(executor, nullptr,
                    self->initial_padding_, self->initial_padding_);
                auto& state = *self->state_;
                const auto& config = *self->config_;
                auto target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
                    .dns_service = &config.dns,
                    .address = config.settings.address,
                    .literal_address = config.settings.literal_address,
                    .port = config.settings.port,
                    .stream_settings = &config.stream,
                    .timeout = config.dial_timeout,
                    .send_through = &config.settings.send_through,
                    .inbound_local_addr = context.inbound.local_endpoint
                        ? &*context.inbound.local_endpoint : nullptr,
                    .inbound_source_ip = context.inbound.source_ip,
                    .inbound_source_port = context.inbound.source_port,
                    .tls_server_name = ResolveOutboundTlsServerName(config.stream, config.settings.address),
                    .ws_host = config.settings.address,
                });
                if (!target) throw transport::LinkError(target.error());
                auto dial = co_await DialOutboundTransport(executor, context, *target);
                if (!dial.Ok()) throw transport::LinkError(dial.error);
                state.stream = std::move(dial.stream);
                state.stream->SetStreamLabel("out");
                state.stream->SetIdleTimeout(message.handshake_timeout);
                auto deadline = state.stream->StartPhaseDeadline(message.handshake_timeout);
                const auto padding_bytes = state.opening_scheme_->SampleAuthPaddingSize();
                memory::ByteVector auth(34 + padding_bytes, uint8_t{0});
                std::copy(config.settings.password_hash.begin(), config.settings.password_hash.end(), auth.begin());
                auth[32] = static_cast<uint8_t>(padding_bytes >> 8);
                auth[33] = static_cast<uint8_t>(padding_bytes);
                const auto authenticated = co_await WriteAll(*state.stream, auth);
                if (!authenticated)
                    throw transport::LinkError(deadline.Expired() ? ErrorCode::TIMEOUT : authenticated.error());
                auto reader_ticket = self->channel_.TryReserve();
                if (!reader_ticket) throw ServiceChannelFull();
                self->reader_running_ = true;
                try {
                    net::co_spawn(executor, state.Run(
                        [weak_pool = self->pool_](std::shared_ptr<const PaddingScheme> padding) {
                            return ClientSession::PublishPadding(weak_pool, std::move(padding));
                        }),
                        net::bind_cancellation_slot(state.CancellationSlot(),
                            [self, ticket = std::move(reader_ticket)](std::exception_ptr failure) mutable {
                                self->reader_running_ = false;
                                if (self->state_) self->state_->CloseAll(failure
                                    ? SessionExceptionError(failure) : ErrorCode::CONNECTION_CLOSED);
                                net::co_spawn(self->channel_.Executor(),
                                    NotifyRetired(self->pool_, self), [](std::exception_ptr) {});
                                ticket = {};
                            }));
                } catch (...) { self->reader_running_ = false; throw; }
            }
            auto& state = *self->state_;
            if (!state.Available()) throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
            state.stream->SetIdleTimeout(message.handshake_timeout);
            auto deadline = state.stream->StartPhaseDeadline(message.handshake_timeout);
            const auto sid = state.next_sid++;
            auto logical = state.RegisterLogicalStream(sid);
            ++state.active_streams;
            const bool udp = context.content.network == Network::UDP;
            const auto original_target = context.outbound.target;
            const auto stream_target = udp ? TargetAddress(proxy::uot::kMagicAddress, 0) : original_target;
            const auto target = EncodeSocksAddress(stream_target);
            if (!target) throw transport::LinkError(target.error());
            memory::ByteVector packet;
            packet.reserve(kFrameHeaderSize * 3 + target->size() + 128);
            if (!AppendFrameBytesTo(packet, kCmdSYN, sid, {}) ||
                !AppendFrameBytesTo(packet, kCmdPSH, sid,
                    std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(target->data()), target->size())))
                throw transport::LinkError(ErrorCode::PROTOCOL_ENCODE_FAILED);
            if (udp) {
                const auto request = proxy::uot::EncodeRequest(true, original_target);
                if (!request) throw transport::LinkError(request.error());
                if (!AppendFrameBytesTo(packet, kCmdPSH, sid, request->span()))
                    throw transport::LinkError(ErrorCode::PROTOCOL_ENCODE_FAILED);
            }
            const auto opened = co_await state.WriteOpenPacket(std::move(packet));
            if (!opened) throw transport::LinkError(deadline.Expired() ? ErrorCode::TIMEOUT : opened.error());
            if (sid >= 2 && state.session_version == SessionVersion::V2) {
                const auto acknowledged = co_await logical->WaitOpenResult(std::chrono::seconds(3));
                if (!acknowledged) throw transport::LinkError(acknowledged.error());
            }
            // The caller's aggregate request deadline owns relay timeouts. Idle
            // physical sessions retain no request deadline in their transport.
            state.stream->SetIdleTimeout(std::chrono::seconds(0));
            state.stream->SetReadTimeout(std::chrono::seconds(0));
            state.stream->SetWriteTimeout(std::chrono::seconds(0));
            state.stream->ClearPhaseDeadline();
            reply.sid = sid;
            reply.local = state.stream->LocalEndpoint();
            reply.remote = state.stream->RemoteEndpoint();
        } catch (...) {
            reply.error = SessionExceptionError(std::current_exception());
            if (self->state_) self->state_->CloseAll(reply.error);
        }
        reply.outbound = std::move(context.outbound);
        reply.outbound.tag = {}; // The caller retains its immutable handler tag.
        co_return reply;
    }

    static std::shared_ptr<PhysicalSessionState::LogicalStream> Logical(ClientSession& self, uint32_t sid) {
        if (!self.state_) throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
        const auto found = self.state_->logical_streams.find(sid);
        if (found == self.state_->logical_streams.end())
            throw transport::LinkError(self.state_->terminal_error);
        return found->second;
    }
    static net::awaitable<buf::MultiBuffer> ReadOwned(std::shared_ptr<ClientSession> self, uint32_t sid) {
        auto logical = Logical(*self, sid);
        auto payload = co_await logical->ReadPayload();
        if (!payload) {
            if (payload.error() == ErrorCode::OK) co_return buf::MultiBuffer{};
            throw transport::LinkError(payload.error());
        }
        co_return std::move(*payload);
    }
    static net::awaitable<void> WriteOwned(std::shared_ptr<ClientSession> self,
                                          uint32_t sid, buf::MultiBuffer payload) {
        auto logical = Logical(*self, sid);
        logical->CheckWrite();
        const auto result = co_await self->state_->WritePayloadFrames(sid, *logical, std::move(payload));
        if (!result) throw transport::LinkError(result.error());
    }
    static net::awaitable<void> ShutdownOwned(std::shared_ptr<ClientSession> self, uint32_t sid) {
        auto logical = Logical(*self, sid);
        if (logical->BeginLocalClose()) {
            const auto result = co_await self->state_->WriteFrameSerialized(kCmdFIN, sid, {});
            if (!result) throw transport::LinkError(result.error());
        }
    }
    static net::awaitable<ReturnReply> FinishOwned(std::shared_ptr<ClientSession> self,
                                                  uint32_t sid, ErrorCode error) {
        ReturnReply result;
        if (!self->state_) co_return result;
        auto& state = *self->state_;
        if (const auto found = state.logical_streams.find(sid); found != state.logical_streams.end()) {
            found->second->Close(error);
            state.UnregisterLogicalStream(sid);
            if (state.active_streams) --state.active_streams;
        }
        if (error != ErrorCode::OK) state.CloseAll(error);
        result.reusable = error == ErrorCode::OK && state.Available();
        co_return result;
    }
    static net::awaitable<void> StopOwned(std::shared_ptr<ClientSession> self) {
        self->stopping_ = true;
        if (self->state_) self->state_->CloseAll(ErrorCode::CANCELLED);
        // The terminal reservation remains held; every ordinary entry and the
        // tracked reader must finish before the private protocol state is freed.
        net::steady_timer wake(self->channel_.Executor());
        while (self->reader_running_ || self->channel_.Outstanding() > 1) {
            wake.expires_after(std::chrono::milliseconds(1));
            co_await wake.async_wait(net::use_awaitable);
        }
        self->state_.reset();
    }

    ServiceChannel channel_;
    const std::shared_ptr<const ClientConfig> config_;
    const std::shared_ptr<const PaddingScheme> initial_padding_;
    const std::weak_ptr<Pool> pool_;
    std::unique_ptr<PhysicalSessionState> state_;
    bool reader_running_ = false;
    bool stopping_ = false;
};

struct Handler::Pool : std::enable_shared_from_this<Pool> {
    using Clock = std::chrono::steady_clock;
    static constexpr size_t kMaxSessions = 512;
    struct Entry {
        uint64_t id;
        std::shared_ptr<ClientSession> client;
        ServiceChannel::Reservation stop_ticket;
        std::optional<Clock::time_point> idle_since;
        std::optional<tcp::endpoint> local;
        std::optional<tcp::endpoint> remote;
        bool retiring = false;
    };
    class Lease {
    public:
        Lease() = default;
        Lease(std::shared_ptr<Pool> owner, uint64_t id, std::shared_ptr<ClientSession> client,
              ServiceChannel::Reservation ticket)
            : owner_(std::move(owner)), id_(id), client_(std::move(client)), ticket_(std::move(ticket)) {}
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&&) noexcept = default;
        Lease& operator=(Lease&&) = delete;
        ~Lease() {
            if (!owner_ || !ticket_) return;
            owner_->channel.SendReserved(std::move(ticket_), [owner = owner_, id = id_] {
                owner->Retire(id);
            });
        }
        [[nodiscard]] const std::shared_ptr<ClientSession>& Client() const noexcept { return client_; }
        net::awaitable<void> Return(ReturnReply result, const OpenReply& opened) {
            co_await owner_->channel.CallReserved(ticket_,
                [owner = owner_, id = id_, result = std::move(result), local = opened.local,
                 remote = opened.remote]() mutable {
                    if (const auto found = owner->Find(id); found != owner->entries.end()) {
                        found->local = local;
                        found->remote = remote;
                        if (!owner->stopping && result.reusable) {
                            found->idle_since = Clock::now();
                            owner->Schedule();
                        } else owner->Retire(id);
                    }
                });
            ticket_ = {};
            owner_.reset();
            client_.reset();
        }
    private:
        std::shared_ptr<Pool> owner_;
        uint64_t id_ = 0;
        std::shared_ptr<ClientSession> client_;
        ServiceChannel::Reservation ticket_;
    };

    static net::awaitable<void> FinishRequest(Lease lease,
                                              std::shared_ptr<ClientSession> client,
                                              OpenReply opened, ErrorCode error) {
        ReturnReply returned;
        std::exception_ptr failure;
        try {
            returned = co_await client->Finish(opened.sid, error);
        } catch (...) {
            failure = std::current_exception();
        }
        // Return the reservation even when finishing the logical stream fails.
        co_await lease.Return(returned, opened);
        if (failure) std::rethrow_exception(failure);
    }

    Pool(net::any_io_executor shared_executor, std::shared_ptr<const ClientConfig> config)
        : channel(net::make_strand(shared_executor), kMaxSessions + 8),
          shutdown_ticket(channel.TryReserve()),
          base_executor(std::move(shared_executor)),
          config(std::move(config)),
          scheduler(TimeoutScheduler::ForExecutor(channel.Executor())) {}

    net::awaitable<Lease> Acquire(OutboundBind::Selection selected_v4,
                                  OutboundBind::Selection selected_v6) {
        co_return co_await channel.PostCommitted(
            AcquireOwned(shared_from_this(), selected_v4, selected_v6));
    }
    net::awaitable<void> Stop() {
        co_await channel.PostReserved(shutdown_ticket, StopOwned(shared_from_this()));
    }
    net::awaitable<void> UpdatePadding(std::shared_ptr<const PaddingScheme> padding) {
        co_await channel.Call([self = shared_from_this(), padding = std::move(padding)]() mutable {
            if (!self->stopping) self->padding = std::move(padding);
        });
    }
    net::awaitable<void> RetireClient(const std::shared_ptr<ClientSession>& client) {
        co_await channel.Call([self = shared_from_this(), client] {
            const auto found = std::find_if(self->entries.begin(), self->entries.end(),
                [&client](const Entry& entry) { return entry.client == client; });
            if (found != self->entries.end()) self->Retire(found->id);
        });
    }

private:
    static net::awaitable<Lease> AcquireOwned(std::shared_ptr<Pool> self,
                                               OutboundBind::Selection selected_v4,
                                               OutboundBind::Selection selected_v6) {
        if (self->stopping) throw transport::LinkError(ErrorCode::CANCELLED);
        auto ticket = self->channel.TryReserve();
        if (!ticket) throw ServiceChannelFull();
        // Reserve an idle entry before consulting its physical owner. No
        // pointer into the registry survives that cross-strand suspension.
        for (;;) {
            uint64_t id = 0;
            std::shared_ptr<ClientSession> client;
            for (auto& entry : self->entries) {
                if (entry.retiring || !entry.idle_since) continue;
                if (entry.remote && entry.local) {
                    const auto& selected = entry.remote->address().is_v6() ? selected_v6 : selected_v4;
                    if (selected.address && iputil::NormalizeAddress(entry.local->address()) != *selected.address)
                        continue;
                }
                entry.idle_since.reset();
                id = entry.id;
                client = entry.client;
                break;
            }
            if (!client) break;
            const bool available = co_await client->Available();
            if (self->stopping) throw transport::LinkError(ErrorCode::CANCELLED);
            if (available) co_return Lease(self, id, std::move(client), std::move(ticket));
            self->Retire(id);
        }
        if (self->entries.size() == kMaxSessions) throw ServiceChannelFull();
        auto client = memory::AllocateShared<ClientSession>(net::make_strand(self->base_executor),
            self->config, self->padding, self);
        auto stop_ticket = client->Reserve();
        if (!stop_ticket) throw ServiceChannelFull();
        const auto id = ++self->next_id;
        self->entries.push_back(Entry{id, client, std::move(stop_ticket), {}, {}, {}, false});
        co_return Lease(self, id, std::move(client), std::move(ticket));
    }
    memory::DataVector<Entry>::iterator Find(uint64_t id) {
        return std::find_if(entries.begin(), entries.end(), [id](const Entry& entry) { return entry.id == id; });
    }
    static net::awaitable<void> RetireOwned(std::shared_ptr<ClientSession> client,
                                           ServiceChannel::Reservation ticket) {
        co_await client->Stop(ticket);
    }
    void Retire(uint64_t id) {
        const auto found = Find(id);
        if (found == entries.end() || found->retiring) return;
        found->retiring = true;
        auto client = found->client;
        net::co_spawn(channel.Executor(), RetireOwned(client, std::move(found->stop_ticket)),
            [self = shared_from_this(), id](std::exception_ptr failure) {
                const auto found = self->Find(id);
                if (found != self->entries.end()) self->entries.erase(found);
                if (failure && !self->failure) self->failure = failure;
            });
    }
    void Schedule() {
        if (stopping || timer.Valid()) return;
        timer = scheduler.ScheduleAfter(
            std::chrono::duration_cast<std::chrono::milliseconds>(config->settings.idle_session_check_interval),
            channel.Executor(), [weak = weak_from_this()] {
                const auto self = weak.lock();
                if (!self) return;
                self->timer.Reset();
                const auto now = Clock::now();
                size_t kept = 0;
                for (size_t i = self->entries.size(); i-- > 0;) {
                    auto& entry = self->entries[i];
                    if (!entry.idle_since || entry.retiring) continue;
                    if (kept >= self->config->settings.min_idle_sessions &&
                        now - *entry.idle_since >= self->config->settings.idle_session_timeout)
                        self->Retire(entry.id);
                    else ++kept;
                }
                if (!self->entries.empty()) self->Schedule();
            });
    }
    static net::awaitable<void> StopOwned(std::shared_ptr<Pool> self) {
        self->stopping = true;
        self->scheduler.Cancel(self->timer);
        for (auto& entry : self->entries) self->Retire(entry.id);
        net::steady_timer wake(self->channel.Executor());
        while (!self->entries.empty() || self->channel.Outstanding() > 1) {
            wake.expires_after(std::chrono::milliseconds(1));
            co_await wake.async_wait(net::use_awaitable);
        }
        memory::DataVector<Entry>{}.swap(self->entries);
        if (self->failure) std::rethrow_exception(self->failure);
    }

public:
    ServiceChannel channel;
    ServiceChannel::Reservation shutdown_ticket;
private:
    const net::any_io_executor base_executor;
    const std::shared_ptr<const ClientConfig> config;
    TimeoutScheduler& scheduler;
    TimeoutToken timer;
    memory::DataVector<Entry> entries;
    std::shared_ptr<const PaddingScheme> padding = DefaultPaddingScheme();
    uint64_t next_id = 0;
    bool stopping = false;
    std::exception_ptr failure;
};

net::awaitable<void> Handler::ClientSession::PublishPadding(
    std::weak_ptr<Pool> weak_pool, std::shared_ptr<const PaddingScheme> padding) {
    if (auto pool = weak_pool.lock()) co_await pool->UpdatePadding(std::move(padding));
}
net::awaitable<void> Handler::ClientSession::NotifyRetired(
    std::weak_ptr<Pool> weak_pool, std::shared_ptr<ClientSession> client) {
    if (auto pool = weak_pool.lock()) co_await pool->RetireClient(client);
}

Handler::Handler(std::string tag, net::any_io_executor executor, Settings settings,
                 StreamSettings stream_settings, std::chrono::seconds dial_timeout,
                 app::dns::DNS& dns)
    : tag_(std::move(tag)), settings_(std::move(settings)),
      stream_settings_(std::move(stream_settings)), dial_timeout_(dial_timeout), dns_service_(dns),
      pool_(memory::AllocateShared<Pool>(executor,
          memory::AllocateShared<const ClientConfig>(ClientConfig{
              settings_, stream_settings_, dial_timeout_, dns_service_}))) {
    if (settings_.idle_session_check_interval <= std::chrono::seconds::zero() ||
        settings_.idle_session_timeout <= std::chrono::seconds::zero())
        throw std::invalid_argument("AnyTLS session intervals must be positive");
}
Handler::~Handler() noexcept = default;
net::awaitable<void> Handler::Stop() const { co_await pool_->Stop(); }

net::awaitable<OutboundProcessResult> Handler::Process(
    net::any_io_executor executor, const tcp::endpoint* inbound_local_addr,
    session::Context& ctx, const TimeoutsConfig& timeouts, transport::Link inbound,
    StatsShard& stats, const RelayConfig& relay_config, buf::MultiBuffer first_payload,
    std::chrono::seconds relay_idle_timeout, std::chrono::seconds relay_write_timeout) const {
    if (!inbound.Valid()) co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    (void)inbound_local_addr; // Owned local endpoint is already present in session metadata.
    const bool ordered = settings_.send_through.GetMode() == OutboundBind::Mode::Ordered;
    auto lease = co_await pool_->Acquire(
        ordered ? settings_.send_through.Select(net::ip::address_v4::any(),
            ctx.inbound.source_ip, ctx.inbound.source_port) : OutboundBind::Selection{},
        ordered ? settings_.send_through.Select(net::ip::address_v6::any(),
            ctx.inbound.source_ip, ctx.inbound.source_port) : OutboundBind::Selection{});
    const auto client = lease.Client();
    auto opened = co_await client->Open(OpenMessage(ctx, timeouts.HandshakeTimeout()));
    const auto tag = ctx.outbound.tag;
    ctx.outbound = opened.outbound;
    ctx.outbound.tag = tag;
    if (opened.local && !opened.local->address().is_unspecified()) {
        ctx.outbound.connected_local_addr = opened.local->address();
        ctx.outbound.connected_local_port = opened.local->port();
    }
    if (opened.error != ErrorCode::OK) co_return tl::unexpected(opened.error);
    LOG_ACCESS(FormatAccessLog(ctx));

    // Request control and relay remain on their caller strand. Only the shared
    // physical protocol's narrow read/write messages cross its owner boundary.
    struct LogicalEndpoint final : transport::MultiBufferReader, transport::MultiBufferWriter {
        std::shared_ptr<ClientSession> client;
        ServiceChannel::Reservation cancel_ticket;
        uint32_t sid;
        const bool udp;
        const TargetAddress target;
        transport::CancellationSource cancellation;
        transport::internet::detail::ConnectionTimeouts<LogicalEndpoint> deadlines;
        size_t pending_writes = 0;
        bool cancelled = false;
        ErrorCode cancellation_error = ErrorCode::CANCELLED;

        LogicalEndpoint(net::any_io_executor executor, std::shared_ptr<ClientSession> client,
                        uint32_t sid, bool udp, TargetAddress target)
            : client(std::move(client)), cancel_ticket(this->client->Reserve()), sid(sid),
              udp(udp), target(std::move(target)), deadlines(std::move(executor), *this) {
            if (!cancel_ticket) throw ServiceChannelFull();
        }
        ~LogicalEndpoint() { deadlines.Stop(); Cancel(); }
        struct ReadScope {
            LogicalEndpoint& owner;
            explicit ReadScope(LogicalEndpoint& owner) : owner(owner) { owner.deadlines.BeginRead(); }
            ~ReadScope() { owner.deadlines.EndRead(); }
        };
        struct WriteScope {
            LogicalEndpoint& owner;
            explicit WriteScope(LogicalEndpoint& owner) : owner(owner) {
                owner.deadlines.BeginWrite();
                ++owner.pending_writes;
            }
            ~WriteScope() { --owner.pending_writes; owner.deadlines.EndWrite(); }
        };
        net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
            if (cancelled) throw transport::LinkError(cancellation_error);
            ReadScope scope(*this);
            auto payload = co_await client->Read(sid);
            if (udp) for (auto* buffer : payload) if (buffer && !buffer->IsEmpty()) buffer->SetUDP(target);
            if (buf::HasData(payload)) deadlines.TouchActivity();
            co_return payload;
        }
        net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
            if (!buf::HasData(payload)) co_return;
            if (cancelled) throw transport::LinkError(cancellation_error);
            WriteScope scope(*this);
            co_await client->Write(sid, std::move(payload));
            deadlines.TouchActivity();
        }
        // The inherited WriteBuffers owns borrowed bytes before the first await.
        net::awaitable<void> AsyncShutdownWrite() override {
            if (cancelled) co_return;
            WriteScope scope(*this);
            co_await client->ShutdownWrite(sid);
        }
        transport::EofAction ReadEofAction() const noexcept override { return transport::EofAction::CloseLink; }
        bool WriteShutdownClosesLink() const noexcept override { return true; }
        transport::CancellationSource& Cancellation() noexcept override { return cancellation; }
        void Cancel() noexcept {
            if (cancelled) return;
            cancelled = true;
            deadlines.Stop();
            cancellation.Stop(cancellation_error);
            if (cancel_ticket)
                (void)client->Cancel(std::move(cancel_ticket), sid,
                    pending_writes != 0 || cancellation_error != ErrorCode::CANCELLED, cancellation_error);
        }
        void OnTimeout(ErrorCode error) noexcept { cancellation_error = error; Cancel(); }
        void SetIdleTimeout(std::chrono::seconds value) { deadlines.SetIdleTimeout(value); }
        void SetReadTimeout(std::chrono::seconds value) { deadlines.SetReadTimeout(value); }
        void SetWriteTimeout(std::chrono::seconds value) { deadlines.SetWriteTimeout(value); }
        PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds value) { return deadlines.StartPhaseDeadline(value); }
        void ClearPhaseDeadline() { deadlines.ClearPhaseDeadline(); }
        bool ConsumeIdleTimeout() noexcept { return deadlines.ConsumeIdleTimeout(); }
        bool ConsumeReadTimeout() noexcept { return deadlines.ConsumeReadTimeout(); }
        bool ConsumeWriteTimeout() noexcept { return deadlines.ConsumeWriteTimeout(); }
        bool ConsumePhaseDeadline() noexcept { return deadlines.ConsumePhaseDeadline(); }
    } endpoint(executor, client, opened.sid, ctx.content.network == Network::UDP, ctx.outbound.target);
    endpoint.SetIdleTimeout(relay_idle_timeout);
    endpoint.SetWriteTimeout(relay_write_timeout);
    RelayResult result;
    std::exception_ptr failure;
    try {
        auto relay = [&](auto& target) {
            if (inbound.control) return DoRelayLink(executor, *inbound.reader, *inbound.writer,
                *inbound.control, target, ctx, stats, relay_config, std::move(first_payload));
            return DoRelayLink(executor, *inbound.reader, *inbound.writer,
                target, ctx, stats, relay_config, std::move(first_payload));
        };
        if (ctx.content.network == Network::UDP) {
            proxy::uot::FramedEndpoint framed(endpoint, true, ctx.outbound.target);
            result = co_await relay(framed);
        } else result = co_await relay(endpoint);
    } catch (...) {
        failure = std::current_exception();
        result.error = SessionExceptionError(failure);
    }
    endpoint.Cancel();
    const bool previous = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    try {
        co_await net::co_spawn(executor,
            Pool::FinishRequest(std::move(lease), client, std::move(opened), result.error),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    } catch (...) {
        if (!failure) failure = std::current_exception();
        result.error = SessionExceptionError(failure);
    }
    const auto cancellation = co_await net::this_coro::cancellation_state;
    co_await net::this_coro::throw_if_cancelled(previous);
    if (result.error == ErrorCode::OK &&
        cancellation.cancelled() != net::cancellation_type::none)
        result.error = ErrorCode::CANCELLED;
    if (failure && result.error != ErrorCode::CANCELLED) std::rethrow_exception(failure);
    co_return result;
}

} // namespace acpp::proxy::anytls::outbound
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
                acpp::net::any_io_executor executor,
                acpp::app::dns::DNS& dns,
                std::chrono::seconds dial_timeout) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<acpp::proxy::anytls::outbound::Handler>(
                    std::string(tag),
                    executor,
                    settings,
                    stream_settings,
                    dial_timeout,
                    dns);
            }};
    }), true);
}  // namespace
