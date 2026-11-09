#include "mux_inbound.hpp"
#include "../../inbound_admission.hpp"
#include "../../../common/awaitable_task_group.hpp"
#include "features/routing/dispatcher.hpp"
#include "common/mux/mux_codec.hpp"
#include "common/session.hpp"
#include "infra/config_types.hpp"
#include "app/stats.hpp"
#include "common/allocator.hpp"
#include "transport/async_stream.hpp"
#include "transport/link_error.hpp"
#include "common/buffer_util.hpp"
#include "common/container_util.hpp"
#include "infra/log.hpp"

#include <asio/as_tuple.hpp>

#include <algorithm>
#include <exception>
#include <unordered_map>
#include <limits>
#include <memory>
#include <new>
#include <array>
#include <chrono>
#include <cstring>
#include <utility>
#include <vector>

namespace mux {

// ============================================================================
// 内部类型
// ============================================================================
namespace {

constexpr size_t kMuxQueueHighWaterBytes = 4 * 1024 * 1024;
constexpr size_t kMuxQueueLowWaterBytes  = 2 * 1024 * 1024;
constexpr size_t kMuxQueueEmergencyBytes = 8 * 1024 * 1024;
constexpr size_t kMuxReplyOverhead       = 128;
// Above what one Xray client connection can carry (its MaxConnection is 128),
// so compliant clients never hit it; every accepted sub-session owns a
// dispatch task and outbound resources.
constexpr size_t kMaxConcurrentSubSessions = 1024;

[[nodiscard]] constexpr bool QueueBytesWouldExceed(
    size_t queued,
    size_t incoming,
    size_t limit) noexcept {
    return queued > limit || incoming > limit - queued;
}

struct QueuedInput {
    QueuedInput(buf::MultiBuffer p, size_t n) noexcept
        : payload(std::move(p))
        , bytes(n) {}

    buf::MultiBuffer payload;
    size_t bytes = 0;
};

// 回包元素（出站 → 客户端）
struct MuxReply {
    uint16_t session_id = 0;
    bool is_end = false;
    bool is_error = false;   // END carries OptionError (child refused)
    bool dispatch_done = false;
    bool is_udp = false;     // true → EncodeKeepUDP（带源地址）
    TargetAddress udp_src;   // UDP 源地址（is_udp == true 时有效）
    buf::MultiBuffer payload;
    size_t payload_size = 0;

    [[nodiscard]] size_t PayloadSize() const noexcept {
        return payload_size;
    }
};

class TcpSubState;

struct ReplyQueueState {
    explicit ReplyQueueState(SignalChannel& main_signal)
        : main_signal_(main_signal) {}
    memory::ThreadLocalDeque<MuxReply> queue;
    size_t tcp_queued_bytes = 0;   // TCP 子会话回包字节（含 overhead）
    size_t udp_queued_bytes = 0;   // UDP 子会话回包字节（含 overhead）
    uint32_t active_sub_loops = 0;
    SignalChannel& main_signal_;
    TcpSubState* waiting_writers_head = nullptr;
    bool running = true;
    bool tcp_overflowed = false;
    bool tcp_backpressured = false;
    bool client_frames_backpressured = false;
    uint64_t udp_dropped = 0;
    // Client input queued in all sub-sessions and not yet taken by their
    // dispatchers. The frame loop stops parsing client frames at the high
    // watermark, so the aggregate never grows with the sub-session count.
    size_t sub_input_bytes = 0;

    void AddWaitingWriter(TcpSubState* writer) noexcept;
    void RemoveWaitingWriter(TcpSubState* writer) noexcept;
    void WakeWaitingWriters() noexcept;

    bool CanPushUdp(size_t payload_bytes) const noexcept {
        if (payload_bytes > kMuxQueueHighWaterBytes - kMuxReplyOverhead) {
            return false;
        }
        return !QueueBytesWouldExceed(
            udp_queued_bytes,
            payload_bytes + kMuxReplyOverhead,
            kMuxQueueHighWaterBytes);
    }

    bool CanPushTcp(size_t payload_bytes, size_t reply_count) const noexcept {
        if (reply_count > kMuxQueueEmergencyBytes / kMuxReplyOverhead) {
            return false;
        }
        const size_t overhead = reply_count * kMuxReplyOverhead;
        if (payload_bytes > kMuxQueueEmergencyBytes - overhead) {
            return false;
        }
        return !QueueBytesWouldExceed(
            tcp_queued_bytes,
            payload_bytes + overhead,
            kMuxQueueEmergencyBytes);
    }

    bool PushTcp(MuxReply&& reply) {
        if (reply.PayloadSize() > kMuxQueueEmergencyBytes - kMuxReplyOverhead) {
            return false;
        }
        const size_t reply_bytes = reply.PayloadSize() + kMuxReplyOverhead;
        if (QueueBytesWouldExceed(
                tcp_queued_bytes, reply_bytes, kMuxQueueEmergencyBytes)) {
            return false;
        }
        queue.push_back(std::move(reply));
        tcp_queued_bytes += reply_bytes;
        if (tcp_queued_bytes >= kMuxQueueHighWaterBytes) {
            tcp_backpressured = true;
        }
        WakeReplyWriter();
        return true;
    }

    void PushControl(MuxReply&& reply) {
        queue.push_back(std::move(reply));
        WakeReplyWriter();
    }

    void PushUdpPrepared(MuxReply&& reply, size_t reply_bytes) {
        queue.push_back(std::move(reply));
        udp_queued_bytes += reply_bytes;
        WakeReplyWriter();
    }

    bool Pop(MuxReply& reply) {
        if (queue.empty()) return false;
        reply = std::move(queue.front());
        queue.pop_front();
        const bool was_tcp = !reply.is_udp;
        if (!reply.is_end && !reply.dispatch_done) {
            const size_t reply_bytes = reply.PayloadSize() + kMuxReplyOverhead;
            if (!was_tcp) {
                udp_queued_bytes -= std::min(udp_queued_bytes, reply_bytes);
            } else {
                tcp_queued_bytes -= std::min(tcp_queued_bytes, reply_bytes);
            }
        }
        if (was_tcp && tcp_backpressured && TcpReadWindowOpen()) {
            tcp_backpressured = false;
            WakeWaitingWriters();
        }
        return true;
    }

    // TCP 背压：仅看 TCP 自身的积压量
    bool ShouldBackpressureTcpReads() const noexcept {
        return tcp_backpressured;
    }

    bool TcpReadWindowOpen() const noexcept {
        return tcp_queued_bytes <= kMuxQueueLowWaterBytes;
    }

    [[nodiscard]] bool Empty() const noexcept {
        return queue.empty();
    }

    void WakeReplyWriter() noexcept {
        (void)main_signal_.try_send(IoErrorCode{});
    }

    void MarkTcpOverflow() noexcept {
        tcp_overflowed = true;
        WakeReplyWriter();
    }

    void AddSubLoop() noexcept {
        ++active_sub_loops;
    }

    void MarkSubLoopDone() noexcept {
        if (active_sub_loops > 0) {
            --active_sub_loops;
        }
        WakeReplyWriter();
    }

    void AddSubInput(size_t bytes) noexcept {
        sub_input_bytes += bytes;
        if (sub_input_bytes >= kMuxQueueHighWaterBytes) {
            client_frames_backpressured = true;
        }
    }

    void ReleaseSubInput(size_t bytes) noexcept {
        sub_input_bytes -= std::min(sub_input_bytes, bytes);
        if (client_frames_backpressured && sub_input_bytes <= kMuxQueueLowWaterBytes) {
            client_frames_backpressured = false;
            WakeReplyWriter();
        }
    }

    [[nodiscard]] bool ShouldBackpressureClientFrames() const noexcept {
        return client_frames_backpressured;
    }
};

class SubLoopLease final {
public:
    explicit SubLoopLease(ReplyQueueState& state) noexcept
        : state_(&state) {
        state_->AddSubLoop();
    }

    ~SubLoopLease() noexcept {
        if (state_) {
            state_->MarkSubLoopDone();
        }
    }

    SubLoopLease(const SubLoopLease&) = delete;
    SubLoopLease& operator=(const SubLoopLease&) = delete;

    SubLoopLease(SubLoopLease&& other) noexcept
        : state_(std::exchange(other.state_, nullptr)) {}

    SubLoopLease& operator=(SubLoopLease&&) = delete;

private:
    ReplyQueueState* state_ = nullptr;
};

struct ClientReadQueueState {
    explicit ClientReadQueueState(net::io_context& io_context, SignalChannel& main_signal)
        : space_signal(net::any_io_executor(io_context.get_executor()), 1)
        , main_signal_(main_signal) {}
    SignalChannel space_signal;
    SignalChannel& main_signal_;
    memory::ThreadLocalDeque<QueuedInput> queue;
    size_t queued_bytes = 0;
    bool running = true;
    bool read_backpressured = false;
    bool done = false;
    ErrorCode error = ErrorCode::OK;

    void WakeMain() noexcept {
        (void)main_signal_.try_send(IoErrorCode{});
    }

    void WakeSpace() noexcept {
        (void)space_signal.try_send(IoErrorCode{});
    }

    [[nodiscard]] bool Push(buf::MultiBuffer mb, size_t bytes) {
        if (QueueBytesWouldExceed(
                queued_bytes, bytes, kMuxQueueEmergencyBytes)) {
            mb.clear();
            return false;
        }
        if (!queue.empty()) {
            queue.back().payload.AppendAndCoalesce(std::move(mb));
            queue.back().bytes += bytes;
        } else {
            queue.emplace_back(std::move(mb), bytes);
        }
        queued_bytes += bytes;
        if (queued_bytes >= kMuxQueueHighWaterBytes) {
            read_backpressured = true;
        }
        WakeMain();
        return true;
    }

    bool Pop(buf::MultiBuffer& mb) {
        if (queue.empty()) {
            return false;
        }
        auto& input = queue.front();
        queued_bytes -= std::min(queued_bytes, input.bytes);
        mb = std::move(input.payload);
        queue.pop_front();
        if (read_backpressured && ReadWindowOpen()) {
            read_backpressured = false;
            WakeSpace();
        }
        return true;
    }

    [[nodiscard]] bool ShouldBackpressureReads() const noexcept {
        return read_backpressured;
    }

    [[nodiscard]] bool ReadWindowOpen() const noexcept {
        return queued_bytes <= kMuxQueueLowWaterBytes;
    }

    void MarkDone(ErrorCode ec) noexcept {
        if (done) {
            return;
        }
        done = true;
        error = ec;
        WakeMain();
    }
};

// Shared state machine of one Mux sub-session: the bounded client-input queue
// consumed by its dispatcher, cancellation, and the END / dispatch-done
// notifications queued for the frame loop. Queued input is charged to the
// connection-wide budget until it is read or discarded.
class MuxSubSession
    : public memory::ThreadAllocated
    , public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }

    MuxSubSession(const MuxSubSession&) = delete;
    MuxSubSession& operator=(const MuxSubSession&) = delete;
    ~MuxSubSession() noexcept override = default;

    void MarkDispatchDone() noexcept {
        dispatch_done_ = true;
        try {
            PushEnd();
        } catch (...) {
            reply_queue_.MarkTcpOverflow();
            Cancel();
        }
    }

    [[nodiscard]] bool IsUdp() const noexcept {
        return is_udp_;
    }

    virtual void PushClientFramePayload(
        buf::MultiBuffer mb,
        size_t data_len,
        const TargetAddress* packet_target = nullptr) = 0;

    [[nodiscard]] bool DispatchDone() const noexcept {
        return dispatch_done_;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (!cancelled_) {
            if (!input_queue_.empty()) {
                auto& input = input_queue_.front();
                const size_t bytes = input.bytes;
                buf::MultiBuffer payload = std::move(input.payload);
                input_queue_.pop_front();
                queued_bytes_ -= std::min(queued_bytes_, bytes);
                reply_queue_.ReleaseSubInput(bytes);
                co_return payload;
            }
            if (input_done_) {
                co_return buf::MultiBuffer{};
            }

            auto [ec] = co_await input_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                throw IoSystemError(
                    io_error::operation_aborted,
                    "Mux sub-session input cancelled");
            }
        }
        if (terminal_error_ == ErrorCode::RESOURCE_EXHAUSTED) {
            throw IoSystemError(io_error::no_buffer_space, "Mux sub-session input overflow");
        }
        throw IoSystemError(io_error::operation_aborted, "Mux sub-session input cancelled");
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        PushEnd();
        co_return;
    }

    void CloseClientInput() noexcept {
        if (input_done_) {
            return;
        }
        input_done_ = true;
        WakeInputReader();
    }

    // Refuses the child before dispatch; its END carries OptionError.
    void Reject() noexcept {
        end_error_ = true;
        Cancel();
    }

    void Cancel(ErrorCode error = ErrorCode::CANCELLED) noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        terminal_error_ = error;
        cancellation_.Stop(error);
        input_done_ = true;
        OnCancel();
        WakeInputReader();
        input_queue_.clear();
        reply_queue_.ReleaseSubInput(std::exchange(queued_bytes_, 0));
    }

    session::Context ctx;

protected:
    MuxSubSession(
        net::io_context& io_context,
        uint16_t session_id,
        ReplyQueueState& reply_queue,
        bool is_udp)
        : session_id_(session_id)
        , reply_queue_(reply_queue)
        , is_udp_(is_udp)
        , input_signal_(net::any_io_executor(io_context.get_executor()), 1) {}

    // Called once from Cancel() before queued input is discarded.
    virtual void OnCancel() noexcept {}

    [[nodiscard]] bool InputClosed() const noexcept {
        return cancelled_ || input_done_;
    }

    [[nodiscard]] bool EndSent() const noexcept {
        return end_sent_;
    }

    // Per-sub backlog needs no own cap: the frame loop stops parsing client
    // frames once all sub-sessions together hold kMuxQueueHighWaterBytes.
    void QueueInput(buf::MultiBuffer mb, size_t bytes, bool coalesce = false) {
        if (coalesce && !input_queue_.empty()) {
            input_queue_.back().payload.AppendAndCoalesce(std::move(mb));
            input_queue_.back().bytes += bytes;
        } else {
            input_queue_.emplace_back(std::move(mb), bytes);
        }
        queued_bytes_ += bytes;
        reply_queue_.AddSubInput(bytes);
        WakeInputReader();
    }

    void PushEnd() {
        if (!reply_queue_.running) {
            return;
        }
        const bool send_end = !end_sent_;
        const bool notify_dispatch_done =
            dispatch_done_ && !dispatch_done_notified_;
        if (!send_end && !notify_dispatch_done) {
            return;
        }
        MuxReply reply;
        reply.session_id = session_id_;
        reply.is_end = send_end;
        reply.is_error = send_end && end_error_;
        reply.dispatch_done = notify_dispatch_done;
        reply_queue_.PushControl(std::move(reply));
        end_sent_ = end_sent_ || send_end;
        dispatch_done_notified_ =
            dispatch_done_notified_ || notify_dispatch_done;
    }

    const uint16_t session_id_;
    ReplyQueueState& reply_queue_;
    const bool is_udp_ = false;
    bool input_done_ = false;
    bool cancelled_ = false;

private:
    void WakeInputReader() noexcept {
        (void)input_signal_.try_send(IoErrorCode{});
    }

    SignalChannel input_signal_;
    transport::CancellationSource cancellation_;
    memory::ThreadLocalDeque<QueuedInput> input_queue_;
    size_t queued_bytes_ = 0;
    ErrorCode terminal_error_ = ErrorCode::CANCELLED;
    bool end_sent_ = false;
    bool end_error_ = false;
    bool dispatch_done_ = false;
    bool dispatch_done_notified_ = false;
};

class TcpSubState final : public MuxSubSession {
public:
    TcpSubState(
        net::io_context& io_context,
        uint16_t session_id,
        ReplyQueueState& reply_queue)
        : MuxSubSession(io_context, session_id, reply_queue, false)
        , output_signal_(net::any_io_executor(io_context.get_executor()), 1) {}
    ~TcpSubState() noexcept override {
        Cancel();
    }

    void PushClientPayload(buf::MultiBuffer mb) {
        const size_t bytes = mb.byte_size();
        if (InputClosed() || bytes == 0) {
            mb.clear();
            return;
        }
        QueueInput(std::move(mb), bytes, true);
    }

    void PushClientFramePayload(
        buf::MultiBuffer mb,
        size_t data_len,
        const TargetAddress* packet_target) override {
        (void)data_len;
        (void)packet_target;
        if (mb.byte_size() != 0) {
            PushClientPayload(std::move(mb));
        }
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::ShutdownPeerWrite;
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        co_await WaitForOutputWindow();
        if (cancelled_ || !reply_queue_.running) {
            mb.clear();
            throw IoSystemError(
                io_error::operation_aborted,
                "Mux TCP reply path closed");
        }
        if (EndSent()) {
            mb.clear();
            throw transport::WriteClosed{};
        }

        for (buf::Buffer*& buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                mb.FreeSlot(buffer);
            }
        }
        const size_t payload_bytes = mb.byte_size();
        if (payload_bytes == 0) {
            mb.clear();
            co_return;
        }

        constexpr size_t kMaxFramePayload = std::numeric_limits<uint16_t>::max();
        const size_t reply_count =
            (payload_bytes + kMaxFramePayload - 1) / kMaxFramePayload;
        if (!reply_queue_.CanPushTcp(payload_bytes, reply_count)) {
            reply_queue_.MarkTcpOverflow();
            mb.clear();
            Cancel();
            throw IoSystemError(
                io_error::no_buffer_space,
                "Mux TCP reply queue full");
        }

        while (mb.byte_size() != 0) {
            const size_t chunk_size = std::min(mb.byte_size(), kMaxFramePayload);
            MuxReply reply;
            reply.session_id = session_id_;
            reply.is_end = false;
            reply.is_udp = false;
            reply.payload_size = chunk_size;
            if (mb.byte_size() == chunk_size) {
                reply.payload = std::move(mb);
            } else if (!mb.MovePrefixTo(reply.payload, chunk_size)) {
                mb.clear();
                Cancel();
                throw std::bad_alloc();
            }
            if (!reply_queue_.PushTcp(std::move(reply))) {
                reply_queue_.MarkTcpOverflow();
                Cancel();
                mb.clear();
                throw IoSystemError(
                    io_error::no_buffer_space,
                    "Mux TCP reply queue admission changed");
            }
        }
        mb.clear();
    }

private:
    void OnCancel() noexcept override {
        reply_queue_.RemoveWaitingWriter(this);
        WakeOutputWriter();
    }

    void WakeOutputWriter() noexcept {
        (void)output_signal_.try_send(IoErrorCode{});
    }

    net::awaitable<void> WaitForOutputWindow() {
        struct WaitingWriterGuard {
            ReplyQueueState& queue;
            TcpSubState* writer;
            WaitingWriterGuard(ReplyQueueState& q, TcpSubState* w) noexcept
                : queue(q), writer(w) {
                queue.AddWaitingWriter(writer);
            }
            ~WaitingWriterGuard() noexcept {
                queue.RemoveWaitingWriter(writer);
            }
        };
        while (!cancelled_ && !EndSent() && reply_queue_.running &&
               reply_queue_.ShouldBackpressureTcpReads()) {
            WaitingWriterGuard guard(reply_queue_, this);
            auto [ec] = co_await output_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                break;
            }
        }
    }

    friend struct ReplyQueueState;

    SignalChannel output_signal_;
    TcpSubState* next_waiting_writer_ = nullptr;
    bool waiting_in_reply_queue_ = false;
};

void ReplyQueueState::AddWaitingWriter(TcpSubState* writer) noexcept {
    if (!writer || writer->waiting_in_reply_queue_) {
        return;
    }
    writer->waiting_in_reply_queue_ = true;
    writer->next_waiting_writer_ = waiting_writers_head;
    waiting_writers_head = writer;
}

void ReplyQueueState::RemoveWaitingWriter(TcpSubState* writer) noexcept {
    if (!writer || !writer->waiting_in_reply_queue_) {
        return;
    }
    TcpSubState** cur = &waiting_writers_head;
    while (*cur) {
        if (*cur == writer) {
            *cur = writer->next_waiting_writer_;
            break;
        }
        cur = &(*cur)->next_waiting_writer_;
    }
    writer->next_waiting_writer_ = nullptr;
    writer->waiting_in_reply_queue_ = false;
}

void ReplyQueueState::WakeWaitingWriters() noexcept {
    TcpSubState* cur = waiting_writers_head;
    waiting_writers_head = nullptr;
    while (cur) {
        TcpSubState* next = cur->next_waiting_writer_;
        cur->next_waiting_writer_ = nullptr;
        cur->waiting_in_reply_queue_ = false;
        cur->WakeOutputWriter();
        cur = next;
    }
}

class UdpSubState final : public MuxSubSession {
public:
    UdpSubState(
        net::io_context& io_context,
        uint16_t session_id,
        ReplyQueueState& reply_queue,
        uint64_t parent_conn_id,
        TargetAddress default_target)
        : MuxSubSession(io_context, session_id, reply_queue, true)
        , parent_conn_id_(parent_conn_id)
        , default_target_(std::move(default_target)) {}

    ~UdpSubState() noexcept override {
        Cancel();
    }

    void PushClientPayload(
        buf::MultiBuffer mb, size_t bytes, const TargetAddress* target = nullptr) {
        if (InputClosed()) {
            mb.clear();
            return;
        }
        if (!buf::SetUdpTarget(mb, target ? *target : default_target_)) {
            throw std::bad_alloc();
        }
        // Empty datagrams still own a Buffer and a queue entry.
        QueueInput(std::move(mb), std::max(bytes, size_t{buf::Buffer::kSize}));
    }

    void PushClientFramePayload(
        buf::MultiBuffer mb,
        size_t data_len,
        const TargetAddress* packet_target) override {
        PushClientPayload(std::move(mb), data_len, packet_target);
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (cancelled_ || !reply_queue_.running) {
            mb.clear();
            throw IoSystemError(
                io_error::operation_aborted,
                "Mux UDP reply path closed");
        }
        if (EndSent()) {
            mb.clear();
            throw transport::WriteClosed{};
        }

        const auto datagram = buf::InspectUdpDatagram(mb);
        if (datagram.status == buf::UdpDatagramStatus::Empty) {
            mb.clear();
            co_return;
        }
        if (!datagram.Valid()) {
            mb.clear();
            throw IoSystemError(
                io_error::invalid_argument,
                "Mux UDP reply contains missing or mixed endpoints");
        }
        if (!datagram.target->IsValid() ||
            datagram.payload_size > std::numeric_limits<uint16_t>::max()) {
            mb.clear();
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        }
        if (!reply_queue_.CanPushUdp(datagram.payload_size)) {
            const uint64_t dropped = ++reply_queue_.udp_dropped;
            if (dropped % 100 == 1) {
                LOG_CONN_DEBUG(parent_conn_id_,
                    "UDP reply queue full, dropped {} packets", dropped);
            }
            mb.clear();
            Cancel();
            throw IoSystemError(
                io_error::no_buffer_space,
                "Mux UDP reply queue full");
        }

        MuxReply reply;
        reply.session_id = session_id_;
        reply.is_end = false;
        reply.is_udp = true;
        reply.udp_src = *datagram.target;
        reply.payload_size = datagram.payload_size;
        mb.MoveTo(reply.payload, true);
        reply_queue_.PushUdpPrepared(
            std::move(reply), datagram.payload_size + kMuxReplyOverhead);
        co_return;
    }

private:

    uint64_t parent_conn_id_ = 0;
    TargetAddress default_target_;
};

net::awaitable<void> RunSubDispatch(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& policy,
    ConnectionLimiter* limiter,
    MuxSubSession* sub,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    SubLoopLease sub_loop)
{
    (void)sub_loop;
    transport::Link link{
        static_cast<transport::MultiBufferReader*>(sub),
        static_cast<transport::MultiBufferWriter*>(sub)
    };

    try {
        // Held for the child's lifetime; a refusal ends only this child.
        const auto admission =
            co_await proxy::AdmitInboundSubstream(limiter, stats, sub->ctx);
        if (!admission) {
            sub->Reject();
        } else {
            (void)co_await dispatcher.Dispatch(
                io_context,
                policy,
                nullptr,
                link,
                InitialPayload{},
                sub->ctx,
                stats,
                timeouts);
        }
    } catch (...) {
        LOG_CONN_DEBUG(sub->ctx, "sub-session dispatch failed with an exception");
        sub->Cancel();
    }

    sub->MarkDispatchDone();
}

}  // namespace

// ============================================================================
// ProcessInbound
//
// 处理已解密的 Mux.Cool 帧流。
// 每帧可携带 TCP 或 UDP 子会话数据；服务端负责为每个子会话拨号出站。
// ============================================================================
net::awaitable<RelayResult> ProcessInbound(
    net::io_context& io_context,
    transport::Link client_link,
    AsyncStream& client_control,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& policy,
    ConnectionLimiter* limiter,
    session::Context& parent_ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout)
{
    RelayResult result;
    try {
    LOG_ACCESS(FormatAccessLog(parent_ctx));
    if (!client_link.Valid()) {
        client_control.CloseAbortive();
        result.error = ErrorCode::PROTOCOL_DECODE_FAILED;
        co_return result;
    }
    (void)client_control.ConsumePhaseDeadline();
    client_control.ClearPhaseDeadline();
    auto relay_idle_timeout = timeouts.IdleTimeout();
    if (pressure_idle_timeout > 0) {
        relay_idle_timeout = std::min(
            relay_idle_timeout, std::chrono::seconds(pressure_idle_timeout));
    }
    client_control.SetIdleTimeout(relay_idle_timeout);
    client_control.SetReadTimeout(std::chrono::seconds(0));
    client_control.SetWriteTimeout(
        std::min(timeouts.WriteTimeout(), relay_idle_timeout));

    // 回包队列：单线程，无锁；running 保护回调不在 ProcessInbound 退出后继续推送。
    SignalChannel main_signal{
        net::any_io_executor(io_context.get_executor()),
        1};
    ReplyQueueState reply_queue{main_signal};
    ClientReadQueueState client_reads{io_context, main_signal};

    // TCP / UDP 共用同一个 session_id 命名空间。
    memory::ThreadLocalUnorderedMap<uint16_t, std::unique_ptr<MuxSubSession>> sub_sessions;

    // 帧累积缓冲区（处理粘包）：持有从流读取的 Buffer，解析前短暂 flatten。
    buf::MultiBuffer frame_buf;
    size_t frame_buf_bytes = 0;

    parent_ctx.traffic.bytes_up = 0;
    parent_ctx.traffic.bytes_down = 0;

    const uint64_t parent_conn_id = parent_ctx.conn_id;

    bool running = true;
    bool client_input_done = false;

    auto client_reader_loop = [&]() -> net::awaitable<void> {
        while (client_reads.running) {
            try {
                buf::MultiBuffer read_mb = co_await client_link.reader->ReadMultiBuffer();
                if (read_mb.byte_size() == 0) {
                    client_reads.MarkDone(ErrorCode::OK);
                    co_return;
                }
                const size_t read_bytes = read_mb.byte_size();
                if (!client_reads.Push(std::move(read_mb), read_bytes)) {
                    client_reads.MarkDone(ErrorCode::RESOURCE_EXHAUSTED);
                    co_return;
                }
                while (client_reads.running &&
                       client_reads.ShouldBackpressureReads()) {
                    auto [ec] = co_await client_reads.space_signal.async_receive(
                        net::as_tuple(net::use_awaitable));
                    if (ec) {
                        client_reads.MarkDone(ErrorCode::OK);
                        co_return;
                    }
                }
            } catch (const transport::LinkError& e) {
                ErrorCode ec = client_reads.running ? e.code() : ErrorCode::OK;
                if (ConsumeReadSideTimeout(client_control)) {
                    ec = ErrorCode::RELAY_TIMEOUT;
                }
                client_reads.MarkDone(ec);
                co_return;
            } catch (const IoSystemError& e) {
                ErrorCode ec =
                    client_reads.running ? MapAsioError(e.code()) : ErrorCode::OK;
                if (ConsumeReadSideTimeout(client_control)) {
                    ec = ErrorCode::RELAY_TIMEOUT;
                }
                client_reads.MarkDone(ec);
                co_return;
            } catch (const std::bad_alloc&) {
                client_reads.MarkDone(ErrorCode::RESOURCE_EXHAUSTED);
                co_return;
            } catch (...) {
                client_reads.MarkDone(ErrorCode::INTERNAL);
                co_return;
            }
        }
        client_reads.MarkDone(ErrorCode::OK);
    };

    auto process_frames = [&](AwaitableTaskGroup& tasks) -> net::awaitable<void> {
        auto write_frame_to_client =
            [&](std::span<const uint8_t> frame) -> net::awaitable<bool> {
                const size_t frame_size = frame.size();
                if (frame_size == 0) {
                    co_return true;
                }

                std::array<net::const_buffer, 1> buffers{
                    net::const_buffer(frame.data(), frame.size())};
                try {
                    co_await client_link.writer->WriteBuffers(buffers);
                    parent_ctx.traffic.bytes_down += frame_size;
                    result.bytes_down += frame_size;
                    co_return true;
                } catch (const IoSystemError& e) {
                    if (ConsumeWriteSideTimeout(client_control)) {
                        result.error = ErrorCode::RELAY_TIMEOUT;
                    } else if (e.code() != io_error::operation_aborted) {
                        result.error = MapAsioError(e.code());
                    }
                } catch (const transport::LinkError& e) {
                    result.error = ConsumeWriteSideTimeout(client_control)
                        ? ErrorCode::RELAY_TIMEOUT
                        : e.code();
                } catch (const std::bad_alloc&) {
                    result.error = ErrorCode::RESOURCE_EXHAUSTED;
                } catch (...) {
                    result.error = ErrorCode::INTERNAL;
                }
                co_return false;
            };

        auto write_payload_frame_to_client =
            [&](MuxReply& reply) -> net::awaitable<bool> {
                const size_t payload_size = reply.PayloadSize();
                std::array<uint8_t, 2 + 4 + 1 + kMaxBaseEncodedAddressSize + 2> write_frame{};
                size_t header_len = 0;
                if (reply.is_udp) {
                    header_len = mux::EncodeKeepUDPHeaderTo(
                        write_frame,
                        reply.session_id,
                        reply.udp_src,
                        payload_size);
                    if (header_len == 0) {
                        LOG_CONN_DEBUG(parent_ctx,
                            "UDP reply header encode failed sid={} src={} payload={}B",
                            reply.session_id, reply.udp_src, payload_size);
                        reply.payload.clear();
                        co_return true;
                    }
                } else {
                    header_len = mux::EncodeKeepDataHeaderTo(
                        write_frame,
                        reply.session_id,
                        payload_size);
                    if (header_len == 0) {
                        reply.payload.clear();
                        result.error = ErrorCode::PROTOCOL_ENCODE_FAILED;
                        co_return false;
                    }
                }
                const size_t frame_size = header_len + payload_size;
                if (frame_size == 0) {
                    co_return true;
                }

                ConstBufferSpanBuilder<1 + buf::MultiBuffer::kInlineCapacity> framed;
                framed.Append(net::const_buffer(write_frame.data(), header_len));
                framed.AppendMultiBuffer(reply.payload);
                try {
                    co_await client_link.writer->WriteBuffers(framed.Span());
                    reply.payload.clear();
                    parent_ctx.traffic.bytes_down += frame_size;
                    result.bytes_down += frame_size;
                    co_return true;
                } catch (const IoSystemError& e) {
                    if (ConsumeWriteSideTimeout(client_control)) {
                        result.error = ErrorCode::RELAY_TIMEOUT;
                    } else if (e.code() != io_error::operation_aborted) {
                        result.error = MapAsioError(e.code());
                    }
                } catch (const transport::LinkError& e) {
                    result.error = ConsumeWriteSideTimeout(client_control)
                        ? ErrorCode::RELAY_TIMEOUT
                        : e.code();
                } catch (const std::bad_alloc&) {
                    result.error = ErrorCode::RESOURCE_EXHAUSTED;
                } catch (...) {
                    result.error = ErrorCode::INTERNAL;
                }
                reply.payload.clear();
                co_return false;
            };
        try {
            LOG_CONN_DEBUG(parent_ctx, "starting mux relay");

            while (running) {
            // --------------------------------------------------------------------
            // 1. 排空回包队列 → 序列化写回客户端
            // --------------------------------------------------------------------
            MuxReply reply;
            while (reply_queue.Pop(reply)) {
                if (reply.is_end || reply.dispatch_done) {
                    if (reply.dispatch_done) {
                        sub_sessions.erase(reply.session_id);
                        MaybeShrinkHashContainer(sub_sessions, 8);
                    }
                    if (!reply.is_end) {
                        continue;
                    }
                    std::array<uint8_t, 6> write_frame{};
                    const size_t header_len = mux::EncodeEndTo(
                        write_frame, reply.session_id, reply.is_error);
                    if (!co_await write_frame_to_client(
                            std::span<const uint8_t>(write_frame.data(), header_len))) {
                        running = false;
                        break;
                    }
                    continue;
                }
                if (!co_await write_payload_frame_to_client(reply)) {
                    running = false;
                    break;
                }
            }
            if (!running) break;

            if (reply_queue.tcp_overflowed) {
                reply_queue.tcp_overflowed = false;
                LOG_CONN_DEBUG(parent_ctx,
                    "reply queue overflow: tcp={}B udp={}B items={} emergency_limit={}B",
                    reply_queue.tcp_queued_bytes, reply_queue.udp_queued_bytes,
                    reply_queue.queue.size(), kMuxQueueEmergencyBytes);
                result.error = ErrorCode::RESOURCE_EXHAUSTED;
                break;
            }

            if (client_input_done) {
                if (reply_queue.Empty() && reply_queue.active_sub_loops == 0) {
                    break;
                }
                auto [ec] = co_await main_signal.async_receive(
                    net::as_tuple(net::use_awaitable));
                if (ec) {
                    running = false;
                    break;
                }
                continue;
            }

            if (client_reads.done && client_reads.error != ErrorCode::OK &&
                client_reads.queue.empty()) {
                result.error = client_reads.error;
                running = false;
                break;
            }

            // Sub-session input shares one budget. Parsing more client frames
            // waits until dispatchers drain it below the low watermark.
            if (reply_queue.ShouldBackpressureClientFrames()) {
                auto [ec] = co_await main_signal.async_receive(
                    net::as_tuple(net::use_awaitable));
                if (ec) {
                    running = false;
                    break;
                }
                continue;
            }

            // --------------------------------------------------------------------
            // 2. 消费客户端读队列。读操作由独立协程持有，避免为了轮询回包而
            //    Cancel 底层协议 reader，导致 VMess/VLESS 流被提前关闭。
            // --------------------------------------------------------------------
            buf::MultiBuffer read_mb;
            const bool popped_read = client_reads.Pop(read_mb);
            if (popped_read) {
                const size_t read_bytes = read_mb.byte_size();
                if (read_bytes > 0) {
                    parent_ctx.traffic.bytes_up += read_bytes;
                    result.bytes_up += read_bytes;
                    frame_buf.AppendAndCoalesce(std::move(read_mb));
                    frame_buf_bytes += read_bytes;
                } else {
                    read_mb.clear();
                }
            }

            // --------------------------------------------------------------------
            // 3. 循环解析并分发 Mux 帧
            // --------------------------------------------------------------------
            bool decoded_any_frame = false;
            while (running && frame_buf_bytes > 0 &&
                   !reply_queue.ShouldBackpressureClientFrames() &&
                   !reply_queue.tcp_overflowed) {
                const auto opt_hdr = mux::DecodeFrame(frame_buf);
                if (!opt_hdr) break;  // 数据不足，等待下次读取
                decoded_any_frame = true;

                const mux::FrameHeader& hdr = *opt_hdr;
                if (hdr.frame_size == 0) {
                    LOG_CONN_DEBUG(parent_ctx, "invalid frame");
                    result.error = ErrorCode::PROTOCOL_DECODE_FAILED;
                    running = false;
                    break;
                }

                buf::MultiBuffer frame_payload;
                const bool should_extract_payload =
                    hdr.has_data && hdr.data_len > 0 &&
                    hdr.status != mux::SessionStatus::KEEPALIVE &&
                    (hdr.status == mux::SessionStatus::NEW ||
                     (hdr.option & mux::kOptionError) == 0);
                if (should_extract_payload) {
                    if (frame_buf.DropPrefixBytes(hdr.data_offset) != hdr.data_offset ||
                        !frame_buf.MovePrefixTo(frame_payload, hdr.data_len)) {
                        LOG_CONN_DEBUG(parent_ctx, "payload extraction failed");
                        result.error = ErrorCode::RESOURCE_EXHAUSTED;
                        running = false;
                        break;
                    }
                } else {
                    frame_buf.DropPrefixBytes(hdr.frame_size);
                }
                frame_buf_bytes -= std::min(frame_buf_bytes, hdr.frame_size);
                if (frame_buf_bytes == 0) {
                    frame_buf.ReleaseIfIdle();
                }

                switch (hdr.status) {

                // ----------------------------------------------------------------
                case mux::SessionStatus::KEEPALIVE: {
                    std::array<uint8_t, 6> write_frame{};
                    const size_t header_len = mux::EncodeKeepAliveTo(write_frame);
                    if (!co_await write_frame_to_client(
                            std::span<const uint8_t>(write_frame.data(), header_len))) {
                        running = false;
                    }
                    break;
                }

                // ----------------------------------------------------------------
                case mux::SessionStatus::NEW: {
                    const bool is_udp = hdr.network == mux::NetworkType::UDP;
                    // A reused ID or a sub-session beyond the budget is refused
                    // with an error END; the refused frame's payload is dropped.
                    if (sub_sessions.contains(hdr.session_id) ||
                        sub_sessions.size() >= kMaxConcurrentSubSessions) {
                        session::Context rejected_ctx;
                        rejected_ctx.InitSubstreamFrom(parent_ctx);
                        proxy::BindInboundRequestTarget(
                            rejected_ctx,
                            proxy::InboundRequestTarget{
                                is_udp ? Network::UDP : Network::TCP,
                                hdr.target,
                                std::move(hdr.forwarded)});
                        LOG_CONN_DEBUG(rejected_ctx,
                            "refused NEW sid={} active={}",
                            hdr.session_id, sub_sessions.size());
                        LOG_ACCESS(FormatAccessLog(rejected_ctx, AccessStatus::Rejected,
                            sub_sessions.contains(hdr.session_id)
                                ? "duplicate stream ID" : "concurrent stream limit"));
                        std::array<uint8_t, 6> write_frame{};
                        const size_t header_len =
                            mux::EncodeEndTo(write_frame, hdr.session_id, true);
                        if (!co_await write_frame_to_client(
                                std::span<const uint8_t>(write_frame.data(), header_len))) {
                            running = false;
                        }
                        break;
                    }
                    const uint16_t sid = hdr.session_id;
                    std::unique_ptr<MuxSubSession> sub_state;
                    if (is_udp) {
                        LOG_CONN_DEBUG(parent_ctx,
                            "new UDP sid={} target={} data={}B",
                            sid, hdr.target, hdr.data_len);
                        sub_state = std::make_unique<UdpSubState>(
                            io_context,
                            sid,
                            reply_queue,
                            parent_conn_id,
                            hdr.target);
                    } else {
                        LOG_CONN_DEBUG(parent_ctx, "new TCP sid={} -> {}",
                            sid, hdr.target);
                        sub_state = std::make_unique<TcpSubState>(
                            io_context, sid, reply_queue);
                    }
                    sub_state->ctx.InitSubstreamFrom(parent_ctx);
                    proxy::BindInboundRequestTarget(
                        sub_state->ctx,
                        proxy::InboundRequestTarget{
                            is_udp ? Network::UDP : Network::TCP,
                            hdr.target,
                            std::move(hdr.forwarded)});
                    if (hdr.has_data) {
                        sub_state->PushClientFramePayload(
                            std::move(frame_payload), hdr.data_len);
                    }

                    auto [insert_it, inserted] = sub_sessions.try_emplace(
                        sid, std::move(sub_state));
                    (void)inserted;
                    MuxSubSession* sub_ptr = insert_it->second.get();

                    // 计数仅用于正常 EOF 排空；任务组持有并 join 真正的完成回调。
                    try {
                        tasks.Spawn(RunSubDispatch(
                                io_context,
                                dispatcher,
                                policy,
                                limiter,
                                sub_ptr,
                                stats,
                                timeouts,
                                SubLoopLease{reply_queue}));
                    } catch (...) {
                        sub_ptr->Cancel();
                        sub_ptr->MarkDispatchDone();
                        result.error = ErrorCode::RESOURCE_EXHAUSTED;
                        running = false;
                    }
                    break;
                }

                // ----------------------------------------------------------------
                case mux::SessionStatus::KEEP: {
                    auto session_it = sub_sessions.find(hdr.session_id);
                    MuxSubSession* sub = session_it == sub_sessions.end()
                        ? nullptr
                        : session_it->second.get();
                    if ((!sub || !sub->IsUdp()) && hdr.has_target) {
                        result.error = ErrorCode::PROTOCOL_DECODE_FAILED;
                        running = false;
                        break;
                    }
                    if (!sub) {
                        break;
                    }
                    if ((hdr.option & mux::kOptionError) != 0) {
                        sub->Cancel();
                        break;
                    }
                    if (hdr.has_data) {
                        sub->PushClientFramePayload(
                            std::move(frame_payload),
                            hdr.data_len,
                            hdr.has_target ? &hdr.target : nullptr);
                    }
                    break;
                }

                // ----------------------------------------------------------------
                case mux::SessionStatus::END: {
                    const uint16_t sid = hdr.session_id;
                    auto session_it = sub_sessions.find(sid);
                    const bool known_session = session_it != sub_sessions.end();

                    if (known_session) {
                        MuxSubSession& sub = *session_it->second;
                        if ((hdr.option & mux::kOptionError) != 0) {
                            sub.Cancel();
                        } else {
                            if (hdr.has_data) {
                                sub.PushClientFramePayload(
                                    std::move(frame_payload), hdr.data_len);
                            }
                            sub.CloseClientInput();
                        }
                    }

                    // 已知子会话的 END 只表示客户端输入结束；真正回给客户端的
                    // END 由子会话 dispatch 完成时发送，避免先于最后一批回包到达。
                    // 映射项只由 dispatch_done 回包移除：此处提前移除会让排队中的
                    // 旧回包在同 sid 的新 NEW 之后误删新子会话。
                    if (!known_session) {
                        std::array<uint8_t, 6> write_frame{};
                        const size_t header_len = mux::EncodeEndTo(write_frame, sid);
                        if (!co_await write_frame_to_client(
                                std::span<const uint8_t>(write_frame.data(), header_len))) {
                            running = false;
                        }
                    }
                    break;
                }

                }  // switch (hdr.status)
            }
            if (!running) break;
            if (popped_read || decoded_any_frame ||
                !reply_queue.Empty() || reply_queue.tcp_overflowed ||
                reply_queue.ShouldBackpressureClientFrames()) {
                continue;
            }
            if (client_reads.done) {
                if (client_reads.error != ErrorCode::OK) {
                    if (client_reads.error == ErrorCode::RELAY_TIMEOUT) {
                        LOG_CONN_DEBUG(parent_ctx, "read-side timeout");
                    }
                    result.error = client_reads.error;
                    running = false;
                    break;
                }
                if (frame_buf_bytes != 0) {
                    result.error = ErrorCode::PROTOCOL_DECODE_FAILED;
                    running = false;
                    break;
                }
                client_input_done = true;
                for (auto& [sid, sub] : sub_sessions) {
                    sub->CloseClientInput();
                }
                continue;
            }

            auto [ec] = co_await main_signal.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                running = false;
                break;
            }
            }
        } catch (const std::bad_alloc&) {
            result.error = ErrorCode::RESOURCE_EXHAUSTED;
        } catch (...) {
            result.error = ErrorCode::INTERNAL;
        }

        // ------------------------------------------------------------------------
        // 清理所有存活的子会话
        // ------------------------------------------------------------------------
        // 先标记停止，阻止回调继续推送到 reply_queue
        reply_queue.running = false;
        reply_queue.WakeWaitingWriters();
        client_reads.running = false;
        client_reads.WakeSpace();
        client_control.Cancel();
        LOG_CONN_DEBUG(parent_ctx, "cleaning up sub_sessions={}",
            sub_sessions.size());

        for (auto& [sid, sub] : sub_sessions) {
            sub->Cancel();
        }
        tasks.Cancel();
    };

    // Acquire the join continuation before any task starts. Session storage is
    // released only after the reader, frame loop and every dynamic dispatch have
    // delivered their co_spawn completion, including failure/cancellation.
    co_await RunAwaitableTaskGroup(co_await net::this_coro::executor,
        [&](AwaitableTaskGroup& tasks) {
            tasks.Spawn(client_reader_loop());
            tasks.Spawn(process_frames(tasks));
        });

#ifndef NDEBUG
    const uint64_t udp_dropped = reply_queue.udp_dropped;
    if (udp_dropped > 0) {
        LOG_CONN_DEBUG(parent_ctx, "UDP replies dropped={}", udp_dropped);
    }
#endif

    } catch (const std::bad_alloc&) {
        stats.OnError();
        result.error = ErrorCode::RESOURCE_EXHAUSTED;
    } catch (const IoSystemError& error) {
        stats.OnError();
        result.error = MapAsioError(error.code());
    } catch (...) {
        stats.OnError();
        result.error = ErrorCode::INTERNAL;
    }
    if (result.error != ErrorCode::OK) {
        client_control.CloseAbortive();
    }
    co_return result;
}

}  // namespace mux
