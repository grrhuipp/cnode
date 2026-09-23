#include "anytls_inbound.hpp"
#include "../../../common/awaitable_task_group.hpp"

#include "../anytls_codec.hpp"
#include "../padding.hpp"
#include "../payload_queue.hpp"
#include "../credentials.hpp"
#include "../../uot/uot.hpp"
#include "../../../transport/internet/async_write_gate.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link_error.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "../validator.hpp"

#include <asio/experimental/channel.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

namespace acpp::proxy::anytls::inbound {

namespace anytls = ::acpp::anytls;
using namespace ::acpp::anytls;

namespace {

constexpr size_t kMaxSubStreamQueuedPayloadBytes = anytls::kMaxFramePayload;
// Includes both pending headers and dispatched requests. At the per-stream
// queue limit this bounds queued application data to less than 8 MiB/session.
constexpr size_t kMaxConcurrentSubstreams = 128;

class AnyTLSOnlineSession {
public:
    AnyTLSOnlineSession(Validator& validator,
                        std::string_view tag,
                        uint64_t user_id,
                        std::string_view client_ip)
        : validator_(&validator)
        , tag_(tag)
        , user_id_(user_id)
        , client_ip_(client_ip) {}

    ~AnyTLSOnlineSession() noexcept {
        if (!validator_ || user_id_ == 0) {
            return;
        }
        try {
            validator_->OnUserDisconnected(tag_, user_id_, client_ip_);
        } catch (...) {}
    }

    AnyTLSOnlineSession(const AnyTLSOnlineSession&) = delete;
    AnyTLSOnlineSession& operator=(const AnyTLSOnlineSession&) = delete;
    AnyTLSOnlineSession(AnyTLSOnlineSession&&) = delete;
    AnyTLSOnlineSession& operator=(AnyTLSOnlineSession&&) = delete;

private:
    Validator* validator_;
    std::string tag_;
    uint64_t user_id_;
    std::string client_ip_;
};

void CopySessionContext(const session::Context& source, session::Context& target) {
    target.conn_id = session::NewID(source.worker_id);
    target.inbound = source.inbound;
    target.outbound = source.outbound;
    target.outbounds = source.outbounds;
    target.content = source.content;
    target.traffic = {};
    target.sockopt = source.sockopt;
    target.worker_id = source.worker_id;
    target.parent_conn_id = source.conn_id;
    target.runtime_generation = source.runtime_generation;
    target.config_generation = source.config_generation;
}

}  // namespace

Handler::Handler(Validator& validator,
                 StatsShard& stats,
                 ConnectionLimiterPtr limiter,
                 std::shared_ptr<const ::acpp::anytls::PaddingScheme> padding_scheme)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(limiter)
    , padding_scheme_(std::move(padding_scheme)) {}

namespace {

// A SOCKS target belongs to the logical byte stream, not to a PSH frame.
// Keep only the bounded address prefix on the coroutine frame; pending owns
// every byte already read after it and is transferred to TCP relay or UoT.
net::awaitable<std::expected<TargetAddress, ErrorCode>> ReadSocksTarget(
    transport::MultiBufferReader& reader, buf::MultiBuffer& pending) {
    auto ensure = [&](size_t required) -> net::awaitable<bool> {
        while (pending.byte_size() < required) {
            auto next = co_await reader.ReadMultiBuffer();
            if (!buf::HasData(next)) co_return false;
            next.MoveTo(pending, true);
        }
        co_return true;
    };
    std::array<uint8_t, 1 + 1 + 255 + 2> address{};
    if (!co_await ensure(1)) co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    (void)pending.CopyPrefixTo(std::span(address).first(1));
    const uint8_t type = address[0];
    size_t size = 0;
    if (type == 1) size = 1 + 4 + 2;
    else if (type == 4) size = 1 + 16 + 2;
    else if (type == 3) {
        if (!co_await ensure(2)) co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        (void)pending.CopyPrefixTo(std::span(address).first(2));
        if (address[1] == 0) co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        size = 1 + 1 + address[1] + 2;
    } else co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    if (!co_await ensure(size)) co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    (void)pending.CopyPrefixTo(std::span(address).first(size));
    const uint16_t port = static_cast<uint16_t>((uint16_t(address[size - 2]) << 8) | address[size - 1]);
    TargetAddress target;
    if (type == 1) {
        net::ip::address_v4::bytes_type bytes{};
        std::copy_n(address.begin() + 1, bytes.size(), bytes.begin());
        target = TargetAddress(net::ip::make_address_v4(bytes), port);
    } else if (type == 4) {
        net::ip::address_v6::bytes_type bytes{};
        std::copy_n(address.begin() + 1, bytes.size(), bytes.begin());
        target = TargetAddress(net::ip::make_address_v6(bytes), port);
    } else {
        target = TargetAddress(std::string_view(
            reinterpret_cast<const char*>(address.data() + 2), address[1]), port);
    }
    if (!target.IsValid() && !proxy::uot::VersionFromMagicAddress(target))
        co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    pending.DropPrefixBytes(size);
    co_return target;
}

class AnyTLSDemuxSession;

class AnyTLSSubStream final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }
    transport::EofAction ReadEofAction() const noexcept override { return transport::EofAction::CloseLink; }
    bool WriteShutdownClosesLink() const noexcept override { return true; }

    bool RemoteClosed() const noexcept { return remote_closed_; }
    bool IsClosed() const noexcept { return write_closed_; }

    void CheckWrite() const {
        if (cancelled_) throw transport::LinkError(ErrorCode::CANCELLED);
        if (write_closed_) throw transport::WriteClosed();
    }

    AnyTLSSubStream(net::io_context& io_context,
                    AnyTLSDemuxSession& session,
                    uint32_t sid)
        : io_context_(io_context)
        , input_signal_(io_context, 1)
        , input_space_signal_(io_context, 1)
        , session_(session)
        , sid_(sid) {}

    ~AnyTLSSubStream() noexcept override {
        Cancel();
    }

    AnyTLSSubStream(const AnyTLSSubStream&) = delete;
    AnyTLSSubStream& operator=(const AnyTLSSubStream&) = delete;

    [[nodiscard]] uint32_t Sid() const noexcept {
        return sid_;
    }

    session::Context ctx;

    net::awaitable<bool> PushInput(buf::MultiBuffer mb) {
        const size_t bytes = mb.byte_size();
        if (cancelled_ || input_done_) {
            mb.clear();
            co_return false;
        }
        if (bytes == 0) {
            mb.clear();
            co_return true;
        }
        if (bytes > kMaxSubStreamQueuedPayloadBytes) {
            mb.clear();
            co_return false;
        }
        while (!cancelled_ &&
               !input_done_ &&
               queued_input_.byte_size() + bytes > kMaxSubStreamQueuedPayloadBytes) {
            auto [ec] = co_await input_space_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                mb.clear();
                co_return false;
            }
        }
        if (cancelled_ || input_done_) {
            mb.clear();
            co_return false;
        }
        AppendQueuedPayload(queued_input_, std::move(mb));
        WakeInputReader();
        co_return true;
    }

    void CloseRemote() {
        remote_closed_ = true;
        write_closed_ = true;
        input_done_ = true;
        WakeInputReader();
        WakeInputWriter();
    }

    void Cancel() noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        cancellation_.Stop();
        input_done_ = true;
        queued_input_.clear();
        WakeInputReader();
        WakeInputWriter();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (!cancelled_) {
            if (!queued_input_.empty()) {
                auto input = std::move(queued_input_);
                WakeInputWriter();
                co_return input;
            }
            if (input_done_) {
                co_return buf::MultiBuffer{};
            }
            auto [ec] = co_await input_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                throw IoSystemError(
                    io_error::operation_aborted,
                    "AnyTLS substream input cancelled");
            }
        }
        throw IoSystemError(
            io_error::operation_aborted,
            "AnyTLS substream cancelled");
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;

private:
    transport::CancellationSource cancellation_;

    void WakeInputReader() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)input_signal_.try_send(IoErrorCode{});
    }

    void WakeInputWriter() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)input_space_signal_.try_send(IoErrorCode{});
    }

    net::io_context& io_context_;
    net::experimental::channel<void(IoErrorCode)> input_signal_;
    net::experimental::channel<void(IoErrorCode)> input_space_signal_;
    AnyTLSDemuxSession& session_; // Run joins all users before destroying the session.
    uint32_t sid_ = 0;
    buf::MultiBuffer queued_input_;
    bool input_done_ = false;
    bool cancelled_ = false;
    bool write_closed_ = false;
    bool remote_closed_ = false;
};

class AnyTLSDemuxSession final {
public:
    AnyTLSDemuxSession(std::unique_ptr<AsyncStream> stream,
                       routing::Dispatcher& dispatcher,
                       const routing::DispatchPolicy& policy,
                       net::io_context& io_context,
                       const session::Context& base_ctx,
                       StatsShard& stats,
                       const TimeoutsConfig& timeouts,
                       std::shared_ptr<const PaddingScheme> padding_scheme)
        : stream_(std::move(stream))
        , dispatcher_(dispatcher)
        , policy_(policy)
        , io_context_(io_context)
        , stats_(stats)
        , timeouts_(timeouts)
        , padding_scheme_(std::move(padding_scheme))
        , write_gate_(io_context) {
        CopySessionContext(base_ctx, base_ctx_);
    }

    ~AnyTLSDemuxSession() noexcept {
        CancelAll();
    }

    AnyTLSDemuxSession(const AnyTLSDemuxSession&) = delete;
    AnyTLSDemuxSession& operator=(const AnyTLSDemuxSession&) = delete;

    net::awaitable<RelayResult> Run();

    net::awaitable<std::expected<void, ErrorCode>>
    WriteFrameSerialized(uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
        auto write_lease = co_await write_gate_.Acquire();
        if (!write_lease || cancelled_ || !stream_) {
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }
        if (auto sub = FindStream(sid)) {
            if (cmd == anytls::kCmdFIN && sub->RemoteClosed())
                co_return std::expected<void, ErrorCode>{};
            if (cmd == anytls::kCmdSYNACK && sub->IsClosed())
                co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }

        try {
            auto result = co_await anytls::WriteFrame(*stream_, cmd, sid, payload);
            if (!result) CancelAll();
            co_return result;
        } catch (...) {
            CancelAll();
            throw;
        }
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteMultiBufferSerialized(uint8_t cmd, uint32_t sid, buf::MultiBuffer mb) {
        auto write_lease = co_await write_gate_.Acquire();
        if (!write_lease || cancelled_ || !stream_) {
            mb.clear();
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }
        if (auto sub = FindStream(sid)) sub->CheckWrite();
        else throw transport::WriteClosed();

        try {
            auto result = co_await anytls::WriteMultiBufferAsFrameBatch(
                *stream_, cmd, sid, std::move(mb));
            if (!result) CancelAll();
            co_return result;
        } catch (...) {
            CancelAll();
            throw;
        }
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteBuffersSerialized(uint8_t cmd,
                           uint32_t sid,
                           std::span<const net::const_buffer> buffers) {
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

        auto write_lease = co_await write_gate_.Acquire();
        if (!write_lease || cancelled_ || !stream_) {
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }

        if (auto sub = FindStream(sid)) sub->CheckWrite();
        else throw transport::WriteClosed();
        const PaddingScheme no_padding;
        try {
            auto result = co_await anytls::WriteBuffersAsFramesWithPadding(
                *stream_, no_padding, 0, cmd, sid, buffers);
            if (!result) CancelAll();
            co_return result;
        } catch (...) {
            CancelAll();
            throw;
        }
    }

    void RemoveStream(uint32_t sid) {
        auto it = streams_.find(sid);
        if (it == streams_.end()) {
            return;
        }
        it->second->Cancel();
        streams_.erase(it);
    }

private:
    std::shared_ptr<AnyTLSSubStream> FindStream(uint32_t sid) const {
        const auto it = streams_.find(sid);
        return it == streams_.end() ? nullptr : it->second;
    }

    void CancelAll() noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        write_gate_.Cancel();
        for (auto& [sid, sub] : streams_) {
            (void)sid;
            if (sub) {
                sub->Cancel();
            }
        }
        streams_.clear();
        if (stream_) {
            stream_->CloseAbortive();
        }
    }

    net::awaitable<RelayResult> RejectSession(std::string_view message, ErrorCode error) {
        (void)co_await WriteFrameSerialized(anytls::kCmdAlert, 0,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(message.data()), message.size()));
        RelayResult result;
        result.error = error;
        co_return result;
    }

    net::awaitable<ErrorCode> ProcessStream(
        AnyTLSSubStream& sub, std::chrono::steady_clock::time_point opened_at);
    net::awaitable<void> RunStream(
        std::shared_ptr<AnyTLSSubStream> sub, std::chrono::steady_clock::time_point opened_at);
    net::awaitable<RelayResult> ReadFrames(AwaitableTaskGroup& tasks);

    std::unique_ptr<AsyncStream> stream_;
    routing::Dispatcher& dispatcher_;
    const routing::DispatchPolicy& policy_;
    net::io_context& io_context_;
    session::Context base_ctx_;
    StatsShard& stats_;
    TimeoutsConfig timeouts_;
    std::shared_ptr<const PaddingScheme> padding_scheme_;
    transport::internet::AsyncWriteGate write_gate_;
    memory::ThreadLocalUnorderedMap<uint32_t, std::shared_ptr<AnyTLSSubStream>> streams_;
    uint32_t last_stream_id_ = 0;
    bool cancelled_ = false;
    std::optional<anytls::SessionVersion> session_version_;
};

net::awaitable<void> AnyTLSSubStream::WriteMultiBuffer(buf::MultiBuffer mb) {
    CheckWrite();
    auto ok = co_await session_.WriteMultiBufferSerialized(anytls::kCmdPSH, sid_, std::move(mb));
    if (!ok) throw transport::LinkError(ok.error());
}

net::awaitable<void> AnyTLSSubStream::WriteBuffers(std::span<const net::const_buffer> buffers) {
    CheckWrite();
    auto ok = co_await session_.WriteBuffersSerialized(anytls::kCmdPSH, sid_, buffers);
    if (!ok) throw transport::LinkError(ok.error());
}

net::awaitable<void> AnyTLSSubStream::AsyncShutdownWrite() {
    if (write_closed_) co_return;
    write_closed_ = true;
    input_done_ = true;
    queued_input_.clear();
    WakeInputReader();
    WakeInputWriter();
    if (auto result = co_await session_.WriteFrameSerialized(anytls::kCmdFIN, sid_, {}); !result)
        throw transport::LinkError(result.error());
}

net::awaitable<ErrorCode> AnyTLSDemuxSession::ProcessStream(
    AnyTLSSubStream& sub, std::chrono::steady_clock::time_point opened_at) {
    buf::MultiBuffer pending;
    TargetAddress target;
    session::Context& ctx = sub.ctx;
    bool is_connect = false;
    std::optional<proxy::uot::PacketReader> uot_reader;
    std::optional<proxy::uot::PacketWriter> uot_writer;
    auto prepare = [&]() -> net::awaitable<ErrorCode> {
        auto parsed = co_await ReadSocksTarget(sub, pending);
        if (!parsed) co_return parsed.error();
        target = std::move(*parsed);
        const auto uot_version = proxy::uot::VersionFromMagicAddress(target);
        ctx.outbound.original_target = uot_version ? TargetAddress{} : target;
        ctx.outbound.target = ctx.outbound.original_target;
        ctx.outbound.route_target = ctx.outbound.original_target;
        ctx.content.network = uot_version ? Network::UDP : Network::TCP;
        if (session_version_ == anytls::SessionVersion::V2) {
            if (auto ok = co_await WriteFrameSerialized(anytls::kCmdSYNACK, sub.Sid(), {}); !ok)
                co_return ok.error();
        }

        if (uot_version) {
            target = {};
            if (*uot_version == proxy::uot::Version::V2) {
                auto request = co_await proxy::uot::ReadRequest(sub, pending);
                if (!request) co_return request.error();
                if (!request->destination.IsValid()) co_return ErrorCode::PROTOCOL_INVALID_ADDRESS;
                is_connect = request->is_connect;
                target = std::move(request->destination);
            }
            uot_reader.emplace(sub, is_connect, target, std::move(pending));
            if (*uot_version == proxy::uot::Version::V1) {
                auto first_packet = co_await uot_reader->ReadMultiBuffer();
                if (!buf::HasData(first_packet)) co_return ErrorCode::CONNECTION_CLOSED;
                for (const buf::Buffer* buffer : first_packet) {
                    if (buffer && buffer->HasUDP()) {
                        target = buffer->UDP();
                        break;
                    }
                }
                if (!target.IsValid()) co_return ErrorCode::PROTOCOL_INVALID_ADDRESS;
                uot_reader->SetInitialDecoded(std::move(first_packet));
            }
            uot_writer.emplace(sub, is_connect, target);
        }
        ctx.outbound.original_target = target;
        ctx.outbound.target = target;
        ctx.outbound.route_target = target;
        ctx.content.network = uot_version ? Network::UDP : Network::TCP;
        co_return ErrorCode::OK;
    };

    bool timed_out = false;
    ErrorCode prepare_error = ErrorCode::INTERNAL;
    auto handshake = [&](AwaitableTaskGroup& tasks) -> net::awaitable<void> {
        const auto elapsed = std::chrono::ceil<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - opened_at);
        const auto remaining = std::max(std::chrono::milliseconds::zero(),
            std::chrono::duration_cast<std::chrono::milliseconds>(timeouts_.HandshakeTimeout()) - elapsed);
        if (remaining == std::chrono::milliseconds::zero()) {
            timed_out = true;
            sub.Cancel();
            co_return;
        }
        // The token lives inside this child: its callback cannot outlive the
        // task group it borrows. Cancellation covers both reads and SYNACK I/O.
        auto deadline = TimeoutScheduler::ForIoContext(io_context_).ScheduleAfter(remaining, [&] {
            timed_out = true;
            sub.Cancel();
            tasks.Cancel();
        });
        prepare_error = co_await prepare();
        // Ready continuations can run before an already-due timer callback.
        // Do not dispatch a header that completed beyond its absolute budget.
        if (std::chrono::steady_clock::now() >= opened_at + timeouts_.HandshakeTimeout()) {
            timed_out = true;
            sub.Cancel();
        }
    };
    try {
        co_await RunAwaitableTaskGroup(io_context_.get_executor(),
            [&](AwaitableTaskGroup& tasks) { tasks.Spawn(handshake(tasks)); });
    } catch (const IoSystemError&) {
        if (!timed_out) throw;
    }
    if (timed_out) co_return ErrorCode::TIMEOUT;
    if (prepare_error != ErrorCode::OK) co_return prepare_error;
    if (sub.IsClosed()) co_return ErrorCode::CONNECTION_CLOSED;
    // Header preparation is joined and its timer removed before Dispatcher.
    if (uot_reader) {
        (void)co_await dispatcher_.Dispatch(io_context_, policy_, nullptr,
            transport::Link{std::addressof(*uot_reader), std::addressof(*uot_writer)},
            InitialPayload{}, ctx, stats_, timeouts_);
    } else {
        (void)co_await dispatcher_.Dispatch(io_context_, policy_, nullptr,
            transport::Link{&sub, &sub}, InitialPayload{std::move(pending)},
            ctx, stats_, timeouts_);
    }
    co_return ErrorCode::OK;
}

net::awaitable<void> AnyTLSDemuxSession::RunStream(
    std::shared_ptr<AnyTLSSubStream> sub, std::chrono::steady_clock::time_point opened_at) {
    ErrorCode error = ErrorCode::OK;
    try {
        error = co_await ProcessStream(*sub, opened_at);
    } catch (const transport::LinkError& failure) {
        error = failure.code();
    } catch (const IoSystemError& failure) {
        error = MapAsioError(failure.code());
    } catch (const std::bad_alloc&) {
        error = ErrorCode::RESOURCE_EXHAUSTED;
    } catch (...) {
        error = ErrorCode::INTERNAL;
    }
    if (error == ErrorCode::CONNECTION_CLOSED && sub->RemoteClosed()) error = ErrorCode::OK;
    // The request owner closes exactly once on every completion path. A remote
    // close is already terminal and produces no FIN reply.
    try { co_await sub->AsyncShutdownWrite(); } catch (...) {}
    RemoveStream(sub->Sid());
}

net::awaitable<RelayResult> AnyTLSDemuxSession::Run() {
    RelayResult result;
    auto read_frames = [&](AwaitableTaskGroup& tasks) -> net::awaitable<void> {
        try {
            result = co_await ReadFrames(tasks);
        } catch (...) {
            CancelAll();
            throw; // The group records this failure before cancelling siblings.
        }
        CancelAll();
        // Join every logical task, including header preparation and async
        // cleanup, even when the frame loop returns normally.
        tasks.Cancel();
    };
    co_await RunAwaitableTaskGroup(io_context_.get_executor(),
        [&](AwaitableTaskGroup& tasks) { tasks.Spawn(read_frames(tasks)); });
    if (result.error == ErrorCode::CONNECTION_CLOSED) result.error = ErrorCode::OK;
    co_return result;
}

net::awaitable<RelayResult> AnyTLSDemuxSession::ReadFrames(AwaitableTaskGroup& tasks) {
    RelayResult result;
    while (!cancelled_) {
        auto header = co_await anytls::ReadFrameHeader(*stream_);
        if (!header) {
            result.error = header.error();
            break;
        }

        if (header->cmd == anytls::kCmdSettings) {
            if (header->sid != 0 || session_version_)
                co_return co_await RejectSession("invalid or repeated client settings", ErrorCode::PROTOCOL_INVALID_COMMAND);
            auto text = co_await anytls::ReadFrameText(*stream_, header->length);
            if (!text) { result.error = text.error(); break; }
            auto parsed = anytls::ParsePeerSettings(*text);
            if (!parsed)
                co_return co_await RejectSession("invalid client settings", parsed.error());
            session_version_ = parsed->version; // Publish once before accepting any SYN.
            if (session_version_ == anytls::SessionVersion::V2) {
                const std::string settings = "v=" + std::to_string(anytls::kProtocolVersion);
                if (auto ok = co_await WriteFrameSerialized(anytls::kCmdServerSettings, 0,
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(settings.data()), settings.size())); !ok) {
                    result.error = ok.error();
                    break;
                }
            }
            if (padding_scheme_ && !parsed->padding_md5.empty() &&
                parsed->padding_md5 != padding_scheme_->Digest()) {
                if (auto ok = co_await WriteFrameSerialized(anytls::kCmdUpdatePaddingScheme, 0,
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(padding_scheme_->Raw().data()),
                            padding_scheme_->Raw().size())); !ok) {
                    result.error = ok.error();
                    break;
                }
            }
            continue;
        }
        if (header->cmd == anytls::kCmdServerSettings || header->cmd == anytls::kCmdUpdatePaddingScheme ||
            header->cmd == anytls::kCmdSYNACK)
            co_return co_await RejectSession("server command received from client", ErrorCode::PROTOCOL_INVALID_COMMAND);
        if (header->cmd == anytls::kCmdHeartRequest || header->cmd == anytls::kCmdHeartResponse) {
            if (session_version_ != anytls::SessionVersion::V2 || header->sid != 0 || header->length != 0)
                co_return co_await RejectSession("heartbeat requires negotiated v2", ErrorCode::PROTOCOL_INVALID_COMMAND);
            if (header->cmd == anytls::kCmdHeartRequest) {
                if (auto ok = co_await WriteFrameSerialized(anytls::kCmdHeartResponse, 0, {}); !ok) {
                    result.error = ok.error();
                    break;
                }
            }
            continue;
        }
        if (header->cmd == anytls::kCmdWaste) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            continue;
        }

        const uint32_t sid = header->sid;
        if (header->cmd == anytls::kCmdSYN) {
            std::string_view rejection;
            if (!session_version_) rejection = "client did not send its settings";
            else if (sid <= last_stream_id_) rejection = "stream IDs must increase";
            else if (header->length != 0) rejection = "SYN must not carry data";
            if (!rejection.empty())
                co_return co_await RejectSession(rejection, ErrorCode::PROTOCOL_INVALID_COMMAND);
            if (streams_.size() >= kMaxConcurrentSubstreams) {
                last_stream_id_ = sid; // A refused ID is retired, never reusable.
                stats_.OnError();
                if (session_version_ == anytls::SessionVersion::V2) {
                    constexpr std::string_view message = "concurrent stream limit";
                    auto ok = co_await WriteFrameSerialized(anytls::kCmdSYNACK, sid,
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(message.data()), message.size()));
                    if (!ok) { result.error = ok.error(); co_return result; }
                }
                if (auto ok = co_await WriteFrameSerialized(anytls::kCmdFIN, sid, {}); !ok) {
                    result.error = ok.error();
                    co_return result;
                }
                continue;
            }
            const auto opened_at = std::chrono::steady_clock::now();
            auto sub = memory::AllocateShared<AnyTLSSubStream>(io_context_, *this, sid);
            CopySessionContext(base_ctx_, sub->ctx);
            sub->ctx.stream_id = sid;
            sub->ctx.content.network = Network::TCP;
            streams_.emplace(sid, sub);
            last_stream_id_ = sid; // Commit after the complete stream was inserted.
            tasks.Spawn(RunStream(std::move(sub), opened_at));
            continue;
        }
        if (sid == 0) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            result.error = ErrorCode::PROTOCOL_INVALID_COMMAND;
            break;
        }

        // The dispatcher can retire this stream during any following await.
        // Retain the stream itself, never an iterator into the live index.
        const auto sub = FindStream(sid);
        if (!sub) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            continue;
        }

        if (header->cmd == anytls::kCmdFIN) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            sub->CloseRemote();
            continue;
        }

        if (sub->IsClosed()) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            continue;
        }

        if (header->cmd != anytls::kCmdPSH) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            result.error = ErrorCode::PROTOCOL_INVALID_COMMAND;
            break;
        }

        auto payload = co_await anytls::ReadFramePayload(*stream_, header->length);
        if (!payload) {
            result.error = payload.error();
            break;
        }

        if (!co_await sub->PushInput(std::move(*payload)))
            RemoveStream(sid);
    }

    co_return result;
}

net::awaitable<std::expected<void, ErrorCode>> ReadAuth(
    AsyncStream& stream,
    std::array<uint8_t, 32>& hash) {
    std::array<uint8_t, 34> auth{};
    size_t offset = 0;
    while (offset < auth.size()) {
        try {
            const auto n = co_await stream.AsyncRead(
                net::buffer(auth.data() + offset, auth.size() - offset));
            if (n == 0) {
                co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
            }
            offset += n;
        } catch (const IoSystemError& e) {
            co_return std::unexpected(MapAsioError(e.code()));
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }
    }
    std::copy_n(auth.begin(), hash.size(), hash.begin());
    const uint16_t padding = static_cast<uint16_t>(
        (static_cast<uint16_t>(auth[32]) << 8) | auth[33]);
    if (auto ok = co_await anytls::DiscardFramePayload(stream, padding); !ok) {
        co_return std::unexpected(ok.error());
    }
    co_return std::expected<void, ErrorCode>{};
}

}  // namespace

net::awaitable<RelayResult>
Handler::Process(
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {
    if (!stream) {
        RelayResult result;
        result.error = ErrorCode::PROTOCOL_DECODE_FAILED;
        co_return result;
    }

    std::array<uint8_t, 32> auth_hash{};
    if (auto ok = co_await ReadAuth(*stream, auth_hash); !ok) {
        stats_->OnError();
        RelayResult result;
        result.error = ok.error();
        co_return result;
    }
    auto user = validator_.Validate(ctx.inbound.tag, auth_hash);
    if (!user) {
        if (limiter_) {
            limiter_->OnAuthFailTracked(ctx.inbound.tag, ctx.inbound.source_ip);
        }
        stats_->OnError();
        RelayResult result;
        result.error = ErrorCode::PROTOCOL_AUTH_FAILED;
        co_return result;
    }

    auto control_idle_timeout = timeouts.StreamIdleTimeout();
    if (pressure_idle_timeout > 0) {
        control_idle_timeout = std::min(
            control_idle_timeout,
            std::chrono::seconds(pressure_idle_timeout));
    }
    stream->SetIdleTimeout(control_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(
        std::min(timeouts.WriteTimeout(), control_idle_timeout));
    stream->ClearPhaseDeadline();

    std::optional<AnyTLSOnlineSession> user_session;
    if (user->profile) {
        const auto& profile = *user->profile;
        ctx.inbound.user_email = profile.email;
        ctx.inbound.user_id = profile.user_id;
        ctx.content.speed_limit = profile.speed_limit;

        const uint64_t uid = static_cast<uint64_t>(profile.user_id);
        if (uid != 0) {
            if (!validator_.CanAcceptDevice(
                    ctx.inbound.tag, uid, ctx.inbound.source_ip, profile.device_limit)) {
                LOG_NET_DEBUG("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
                    FormatTimestamp(ctx.accept_time_us),
                    ctx.inbound.source_ip,
                    ctx.inbound.source_port,
                    ctx.inbound.tag,
                    ctx.inbound.user_email,
                    profile.device_limit,
                    validator_.OnlineDeviceCount(ctx.inbound.tag, uid));
                stats_->OnError();
                RelayResult result;
                result.error = ErrorCode::PERMISSION_DENIED;
                co_return result;
            }
            validator_.OnUserConnected(ctx.inbound.tag, uid, ctx.inbound.source_ip);
            user_session.emplace(validator_, ctx.inbound.tag, uid, ctx.inbound.source_ip);
        }
    }

    // The authenticated socket is an AnyTLS control transport. The shared
    // access-session boundary suppresses MUX containers while each logical
    // child below replaces this with TCP/UDP and reports independently.
    ctx.content.network = Network::MUX;

    AnyTLSDemuxSession demux(
        std::move(stream),
        dispatcher,
        receiver.dispatch_policy,
        io_context,
        ctx,
        *stats_,
        timeouts,
        padding_scheme_);
    co_return co_await demux.Run();
}

}  // namespace acpp::proxy::anytls::inbound

namespace {
class AnyTlsRuntime final : public acpp::proxyman::inbound::ProtocolRuntime {
public:
    [[nodiscard]] std::vector<acpp::OnlineDevice>
    GetOnlineDevices(std::string_view tag) const override {
        return validator.GetOnlineDevices(tag);
    }

    acpp::anytls::Validator validator;
};

class AnyTlsSettings final
    : public acpp::proxyman::inbound::ProtocolSettings {
public:
    std::shared_ptr<const acpp::anytls::PaddingScheme> padding_scheme;
};

[[nodiscard]] const AnyTlsSettings* GetAnyTlsSettings(
    const acpp::proxyman::inbound::BuildRequest& req) noexcept {
    return dynamic_cast<const AnyTlsSettings*>(req.settings.get());
}

const bool kInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = acpp::proxyman::inbound::UserProtocol::AnyTls;

    reg.create_runtime = []() -> std::unique_ptr<
        acpp::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<AnyTlsRuntime>();
    };

    reg.create_tcp_handler =
        [](acpp::proxyman::inbound::ProtocolRuntime& runtime,
           acpp::StatsShard& stats,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<acpp::Inbound> {
            auto* anytls_runtime = dynamic_cast<AnyTlsRuntime*>(&runtime);
            const auto* settings = GetAnyTlsSettings(req);
            if (!anytls_runtime || !settings) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::anytls::inbound::Handler>(
                anytls_runtime->validator,
                stats,
                limiter,
                settings->padding_scheme);
        };

    reg.prepare_settings =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<std::shared_ptr<
                const acpp::proxyman::inbound::ProtocolSettings>> {
            // The advertised raw scheme must fit in one UpdatePaddingScheme frame.
            if (config.padding_scheme.size() > acpp::anytls::kMaxFramePayload) {
                LOG_WARN("AnyTLS inbound '{}': padding scheme exceeds {} bytes",
                    tag, acpp::anytls::kMaxFramePayload);
                return std::nullopt;
            }
            auto settings = acpp::memory::AllocateShared<AnyTlsSettings>();
            if (!config.padding_scheme.empty()) {
                auto parsed =
                    acpp::anytls::ParsePaddingScheme(config.padding_scheme);
                if (!parsed) {
                    LOG_WARN(
                        "AnyTLS inbound '{}': invalid padding scheme", tag);
                    return std::nullopt;
                }
                settings->padding_scheme =
                    acpp::memory::AllocateShared<const acpp::anytls::PaddingScheme>(std::move(*parsed));
            }
            return settings;
        };

    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedAnyTlsUser> users;
            users.reserve(config.clients.size());
            for (const auto& client : config.clients) {
                const std::string& password =
                    client.password.empty() ? client.id : client.password;
                if (password.empty()) {
                    LOG_WARN("AnyTLS inbound '{}': static user password is empty", tag);
                    return std::nullopt;
                }
                acpp::proxyman::inbound::PreparedAnyTlsUser info;
                info.password_hash = acpp::anytls::PasswordHash(password);
                info.profile.email = client.email.empty() ? std::string(tag) : client.email;
                users.push_back(std::move(info));
            }
            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& /*req*/,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedAnyTlsUser> users;
            users.reserve(runtime_users.size());
            for (const auto& runtime_user : runtime_users) {
                if (runtime_user.password.empty()) {
                    continue;
                }
                acpp::proxyman::inbound::PreparedAnyTlsUser info;
                info.password_hash = acpp::anytls::PasswordHash(runtime_user.password);
                info.profile.email = runtime_user.email;
                info.profile.user_id = runtime_user.user_id;
                info.profile.speed_limit = runtime_user.speed_limit;
                info.profile.device_limit = runtime_user.device_limit;
                users.push_back(std::move(info));
            }
            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kAnyTLS, std::move(reg));
    return true;
}();
}  // namespace
