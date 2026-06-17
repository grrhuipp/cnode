#include "acppnode/common/mux/mux_relay.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/common/mux/mux_codec.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/experimental/channel.hpp>

#include <unordered_map>
#include <deque>
#include <memory>
#include <array>
#include <chrono>
#include <cstring>
#include <vector>

namespace acpp::mux {

// ============================================================================
// 内部类型
// ============================================================================
namespace {

constexpr size_t kMuxQueueHighWaterBytes = 4 * 1024 * 1024;
constexpr size_t kMuxQueueLowWaterBytes  = 2 * 1024 * 1024;
constexpr size_t kMuxQueueEmergencyBytes = 8 * 1024 * 1024;
constexpr size_t kMuxQueueShrinkItems    = 128;
constexpr size_t kMuxFrameBufKeepCap     = 0;
constexpr size_t kMuxReplyOverhead       = 128;

void AppendOwnedBuffers(buf::MultiBuffer& dst, buf::MultiBuffer& src) {
    for (buf::Buffer*& buffer : src) {
        if (!buffer || buffer->IsEmpty()) {
            buf::Buffer::Free(buffer);
            buffer = nullptr;
            continue;
        }
        dst.push_back(buffer);
        buffer = nullptr;
    }
    src.clear();
}

void MoveOwnedPayloadBuffers(buf::MultiBuffer& dst, buf::MultiBuffer& src) {
    for (buf::Buffer*& buffer : src) {
        if (!buffer || buffer->IsEmpty()) {
            buf::Buffer::Free(buffer);
            buffer = nullptr;
            continue;
        }
        buffer->ClearUDP();
        dst.push_back(buffer);
        buffer = nullptr;
    }
    src.clear();
}

void CopyMultiBufferToScratch(const buf::MultiBuffer& mb,
                              std::vector<uint8_t>& scratch) {
    scratch.clear();
    scratch.reserve(buf::TotalLen(mb));
    for (const auto* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        scratch.insert(scratch.end(), bytes.begin(), bytes.end());
    }
}

void ConsumeMultiBuffer(buf::MultiBuffer& mb, size_t bytes) noexcept {
    size_t remaining = bytes;
    for (buf::Buffer*& buffer : mb) {
        if (!buffer || remaining == 0) {
            continue;
        }
        const size_t len = buffer->Len();
        if (remaining >= len) {
            remaining -= len;
            buf::Buffer::Free(buffer);
            buffer = nullptr;
            continue;
        }
        buffer->Advance(static_cast<uint32_t>(remaining));
        remaining = 0;
        break;
    }

    if (buf::TotalLen(mb) == 0) {
        mb.clear();
    }
}

// 回包元素（出站 → 客户端）
struct MuxReply {
    uint16_t session_id = 0;
    bool is_end = false;
    bool is_udp = false;     // true → EncodeKeepUDP（带源地址）
    TargetAddress udp_src;   // UDP 源地址（is_udp == true 时有效）
    buf::MultiBuffer payload;
    size_t payload_size = 0;

    [[nodiscard]] size_t PayloadSize() const noexcept {
        return payload_size;
    }
};

struct ReplyQueueState {
    explicit ReplyQueueState(net::io_context& io_context)
        : reply_signal(io_context, 1)
        , sub_done_signal(io_context, 1) {}

    memory::ThreadLocalDeque<MuxReply> queue;
    size_t tcp_queued_bytes = 0;   // TCP 子会话回包字节（含 overhead）
    size_t udp_queued_bytes = 0;   // UDP 子会话回包字节（含 overhead）
    uint32_t active_sub_loops = 0;
    net::experimental::channel<void(IoErrorCode)> reply_signal;
    net::experimental::channel<void(IoErrorCode)> sub_done_signal;
    bool running = true;
    bool tcp_overflowed = false;
    uint64_t udp_dropped = 0;
    bool shrink_queue_on_drain = false;

    size_t TotalBytes() const noexcept { return tcp_queued_bytes + udp_queued_bytes; }

    bool CanPushUdp(size_t payload_bytes) const noexcept {
        return udp_queued_bytes + payload_bytes + kMuxReplyOverhead <= kMuxQueueHighWaterBytes;
    }

    bool PushTcp(MuxReply&& reply) {
        const size_t reply_bytes = reply.PayloadSize() + kMuxReplyOverhead;
        if (tcp_queued_bytes + reply_bytes > kMuxQueueEmergencyBytes) {
            return false;
        }
        tcp_queued_bytes += reply_bytes;
        queue.push_back(std::move(reply));
        if (queue.size() >= 128 || TotalBytes() >= kMuxQueueHighWaterBytes) {
            shrink_queue_on_drain = true;
        }
        WakeReplyWriter();
        return true;
    }

    void PushUdpPrepared(MuxReply&& reply, size_t reply_bytes) {
        udp_queued_bytes += reply_bytes;
        queue.push_back(std::move(reply));
        if (queue.size() >= 128 || TotalBytes() >= kMuxQueueHighWaterBytes) {
            shrink_queue_on_drain = true;
        }
        WakeReplyWriter();
    }

    bool Pop(MuxReply& reply) {
        if (queue.empty()) return false;
        const size_t reply_bytes = queue.front().PayloadSize() + kMuxReplyOverhead;
        if (queue.front().is_udp) {
            udp_queued_bytes -= std::min(udp_queued_bytes, reply_bytes);
        } else {
            tcp_queued_bytes -= std::min(tcp_queued_bytes, reply_bytes);
        }
        reply = std::move(queue.front());
        queue.pop_front();
        if (queue.empty() && shrink_queue_on_drain) {
            TryShrinkSequence(queue);
            shrink_queue_on_drain = false;
        }
        return true;
    }

    // TCP 背压：仅看 TCP 自身的积压量
    bool ShouldBackpressureTcpReads() const noexcept {
        return tcp_queued_bytes >= kMuxQueueHighWaterBytes;
    }

    bool TcpReadWindowOpen() const noexcept {
        return tcp_queued_bytes <= kMuxQueueLowWaterBytes;
    }

    [[nodiscard]] bool Empty() const noexcept {
        return queue.empty();
    }

    void WakeReplyWriter() noexcept {
        (void)reply_signal.try_send(IoErrorCode{});
    }

    void AddSubLoop() noexcept {
        ++active_sub_loops;
    }

    void MarkSubLoopDone() noexcept {
        if (active_sub_loops > 0) {
            --active_sub_loops;
        }
        (void)sub_done_signal.try_send(IoErrorCode{});
        WakeReplyWriter();
    }
};

class TcpSubState final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    TcpSubState(
        net::io_context& io_context,
        uint16_t session_id,
        ReplyQueueState& reply_queue)
        : io_context_(io_context)
        , output_sleep_(io_context)
        , input_signal_(io_context, 1)
        , session_id_(session_id)
        , reply_queue_(reply_queue) {}

    ~TcpSubState() noexcept override {
        Cancel();
    }

    TcpSubState(const TcpSubState&) = delete;
    TcpSubState& operator=(const TcpSubState&) = delete;

    [[nodiscard]] bool PushClientPayload(std::span<const uint8_t> payload) {
        if (payload.empty()) {
            return true;
        }
        buf::MultiBuffer mb;
        mb.reserve((payload.size() + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
        if (!buf::AppendSpanToMultiBuffer(payload, mb)) {
            return false;
        }
        PushClientPayload(std::move(mb));
        return true;
    }

    void PushClientPayload(buf::MultiBuffer mb) {
        if (cancelled_ || input_done_) {
            mb.clear();
            return;
        }
        input_queue_.push_back(std::move(mb));
        if (input_queue_.size() >= kMuxQueueShrinkItems) {
            shrink_input_queue_on_drain_ = true;
        }
        WakeInputReader();
    }

    void CloseClientInput() {
        if (input_done_) {
            return;
        }
        input_done_ = true;
        WakeInputReader();
    }

    void MarkDispatchDone() {
        dispatch_done_ = true;
        PushEnd();
        reply_queue_.MarkSubLoopDone();
    }

    [[nodiscard]] bool DispatchDone() const noexcept {
        return dispatch_done_;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (!cancelled_) {
            if (!input_queue_.empty()) {
                buf::MultiBuffer mb = std::move(input_queue_.front());
                input_queue_.pop_front();
                if (input_queue_.empty() && shrink_input_queue_on_drain_) {
                    TryShrinkSequence(input_queue_);
                    shrink_input_queue_on_drain_ = false;
                }
                co_return mb;
            }
            if (input_done_) {
                co_return buf::MultiBuffer{};
            }

            auto [ec] = co_await input_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            (void)ec;
        }
        co_return buf::MultiBuffer{};
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        while (!cancelled_ && reply_queue_.running &&
               reply_queue_.ShouldBackpressureTcpReads()) {
            co_await output_sleep_.WaitFor(std::chrono::milliseconds(10));
        }

        if (cancelled_ || !reply_queue_.running) {
            mb.clear();
            co_return;
        }

        for (buf::Buffer*& buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                buf::Buffer::Free(buffer);
                buffer = nullptr;
                continue;
            }

            MuxReply reply;
            reply.session_id = session_id_;
            reply.is_end = false;
            reply.is_udp = false;
            reply.payload_size = buffer->Len();
            reply.payload.push_back(buffer);
            buffer = nullptr;
            if (!reply_queue_.PushTcp(std::move(reply))) {
                reply_queue_.tcp_overflowed = true;
                Cancel();
                break;
            }
        }
        mb.clear();
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        PushEnd();
        co_return;
    }

    void Cancel() noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        input_done_ = true;
        output_sleep_.Cancel();
        WakeInputReader();
        input_queue_.clear();
        shrink_input_queue_on_drain_ = false;
    }

    void Close() {
        Cancel();
    }

    session::Context ctx;

private:
    void WakeInputReader() noexcept {
        (void)input_signal_.try_send(IoErrorCode{});
    }

    void PushEnd() {
        if (end_sent_ || !reply_queue_.running) {
            return;
        }
        MuxReply reply;
        reply.session_id = session_id_;
        reply.is_end = true;
        end_sent_ = true;
        if (!reply_queue_.PushTcp(std::move(reply))) {
            reply_queue_.tcp_overflowed = true;
            Cancel();
        }
    }

    net::io_context& io_context_;
    ScheduledSleep output_sleep_;
    net::experimental::channel<void(IoErrorCode)> input_signal_;
    uint16_t session_id_ = 0;
    ReplyQueueState& reply_queue_;
    memory::ThreadLocalDeque<buf::MultiBuffer> input_queue_;
    bool shrink_input_queue_on_drain_ = false;
    bool input_done_ = false;
    bool cancelled_ = false;
    bool end_sent_ = false;
    bool dispatch_done_ = false;
};

using TcpSubInfo = std::unique_ptr<TcpSubState>;

class UdpSubState final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    UdpSubState(
        net::io_context& io_context,
        uint16_t session_id,
        ReplyQueueState& reply_queue,
        uint64_t parent_conn_id)
        : io_context_(io_context)
        , input_signal_(io_context, 1)
        , session_id_(session_id)
        , reply_queue_(reply_queue)
        , parent_conn_id_(parent_conn_id) {}

    ~UdpSubState() noexcept override {
        Cancel();
    }

    UdpSubState(const UdpSubState&) = delete;
    UdpSubState& operator=(const UdpSubState&) = delete;

    [[nodiscard]] bool PushClientPayload(
        const TargetAddress& target,
        std::span<const uint8_t> payload) {
        if (payload.empty()) {
            return true;
        }
        buf::MultiBuffer mb;
        mb.reserve((payload.size() + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
        if (!buf::AppendSpanToMultiBuffer(payload, mb)) {
            return false;
        }
        for (buf::Buffer* buffer : mb) {
            if (buffer && !buffer->IsEmpty()) {
                buffer->SetUDP(target);
            }
        }
        PushClientPayload(std::move(mb));
        return true;
    }

    void PushClientPayload(buf::MultiBuffer mb) {
        const size_t bytes = buf::TotalLen(mb);
        if (cancelled_ || input_done_ || bytes == 0) {
            mb.clear();
            return;
        }
        if (queued_bytes_ + bytes > kMuxQueueEmergencyBytes) {
            mb.clear();
            Cancel();
            return;
        }
        queued_bytes_ += bytes;
        input_queue_.push_back(std::move(mb));
        if (input_queue_.size() >= kMuxQueueShrinkItems ||
            queued_bytes_ >= kMuxQueueHighWaterBytes) {
            shrink_input_queue_on_drain_ = true;
        }
        WakeInputReader();
    }

    void CloseClientInput() {
        if (input_done_) {
            return;
        }
        input_done_ = true;
        WakeInputReader();
    }

    void MarkDispatchDone() {
        dispatch_done_ = true;
        PushEnd();
        reply_queue_.MarkSubLoopDone();
    }

    [[nodiscard]] bool DispatchDone() const noexcept {
        return dispatch_done_;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (!cancelled_) {
            if (!input_queue_.empty()) {
                buf::MultiBuffer mb = std::move(input_queue_.front());
                queued_bytes_ -= std::min(queued_bytes_, buf::TotalLen(mb));
                input_queue_.pop_front();
                if (input_queue_.empty() && shrink_input_queue_on_drain_) {
                    TryShrinkSequence(input_queue_);
                    shrink_input_queue_on_drain_ = false;
                }
                co_return mb;
            }
            if (input_done_) {
                co_return buf::MultiBuffer{};
            }

            auto [ec] = co_await input_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            (void)ec;
        }
        co_return buf::MultiBuffer{};
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (cancelled_ || !reply_queue_.running) {
            mb.clear();
            co_return;
        }

        for (buf::Buffer*& buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                buf::Buffer::Free(buffer);
                buffer = nullptr;
                continue;
            }
            if (!buffer->HasUDP()) {
                buf::Buffer::Free(buffer);
                buffer = nullptr;
                continue;
            }

            const size_t payload_bytes = buffer->Len();
            if (!reply_queue_.CanPushUdp(payload_bytes)) {
                const uint64_t dropped = ++reply_queue_.udp_dropped;
                if (dropped % 100 == 1) {
                    LOG_ACCESS_DEBUG(
                        "[conn={}] [MuxRelay] UDP reply queue full, dropped {} packets",
                        parent_conn_id_, dropped);
                }
                buf::Buffer::Free(buffer);
                buffer = nullptr;
                continue;
            }

            MuxReply reply;
            reply.session_id = session_id_;
            reply.is_end = false;
            reply.is_udp = true;
            reply.udp_src = buffer->UDP();
            reply.payload_size = payload_bytes;
            reply.payload.push_back(buffer);
            buffer = nullptr;
            reply_queue_.PushUdpPrepared(
                std::move(reply), payload_bytes + kMuxReplyOverhead);
        }
        mb.clear();
        co_return;
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        PushEnd();
        co_return;
    }

    void Cancel() noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        input_done_ = true;
        WakeInputReader();
        input_queue_.clear();
        queued_bytes_ = 0;
        shrink_input_queue_on_drain_ = false;
    }

    void Close() {
        Cancel();
    }

    session::Context ctx;

private:
    void WakeInputReader() noexcept {
        (void)input_signal_.try_send(IoErrorCode{});
    }

    void PushEnd() {
        if (end_sent_ || !reply_queue_.running) {
            return;
        }
        MuxReply reply;
        reply.session_id = session_id_;
        reply.is_end = true;
        end_sent_ = true;
        if (!reply_queue_.PushTcp(std::move(reply))) {
            reply_queue_.tcp_overflowed = true;
            Cancel();
        }
    }

    net::io_context& io_context_;
    net::experimental::channel<void(IoErrorCode)> input_signal_;
    uint16_t session_id_ = 0;
    ReplyQueueState& reply_queue_;
    uint64_t parent_conn_id_ = 0;
    memory::ThreadLocalDeque<buf::MultiBuffer> input_queue_;
    size_t queued_bytes_ = 0;
    bool shrink_input_queue_on_drain_ = false;
    bool input_done_ = false;
    bool cancelled_ = false;
    bool end_sent_ = false;
    bool dispatch_done_ = false;
};

using UdpSubInfo = std::unique_ptr<UdpSubState>;

net::awaitable<void> RunTcpSubDispatch(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    TcpSubState* sub,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout,
    UDPRelayConfig config)
{
    (void)config;
    transport::Link link{
        static_cast<transport::MultiBufferReader*>(sub),
        static_cast<transport::MultiBufferWriter*>(sub)
    };

    try {
        (void)co_await dispatcher.Dispatch(
            io_context,
            receiver,
            nullptr,
            link,
            InitialPayload{},
            sub->ctx,
            stats,
            timeouts,
            pressure_idle_timeout);
    } catch (...) {
        sub->Cancel();
    }

    sub->MarkDispatchDone();
}

net::awaitable<void> RunUdpSubDispatch(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    UdpSubState* sub,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout,
    UDPRelayConfig config)
{
    (void)config;
    transport::Link link{
        static_cast<transport::MultiBufferReader*>(sub),
        static_cast<transport::MultiBufferWriter*>(sub)
    };

    try {
        (void)co_await dispatcher.Dispatch(
            io_context,
            receiver,
            nullptr,
            link,
            InitialPayload{},
            sub->ctx,
            stats,
            timeouts,
            pressure_idle_timeout);
    } catch (...) {
        sub->Cancel();
    }

    sub->MarkDispatchDone();
}

}  // namespace

// ============================================================================
// DoMuxRelay
//
// 处理已解密的 Mux.Cool 帧流。
// 每帧可携带 TCP 或 UDP 子会话数据；服务端负责为每个子会话拨号出站。
// ============================================================================
net::awaitable<RelayResult> DoMuxRelay(
    net::io_context& io_context,
    transport::Link client_link,
    AsyncStream* client_control,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    session::Context& parent_ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout,
    const UDPRelayConfig& config)
{
    if (!client_link.Valid()) {
        RelayResult error;
        error.error = ErrorCode::PROTOCOL_DECODE_FAILED;
        co_return error;
    }

    // 回包队列：单线程，无锁；running 保护回调不在 DoMuxRelay 退出后继续推送。
    ReplyQueueState reply_queue{io_context};

    // 子会话集合
    memory::ThreadLocalUnorderedMap<uint16_t, UdpSubInfo> udp_subs;
    memory::ThreadLocalUnorderedMap<uint16_t, TcpSubInfo> tcp_subs;

    // 帧累积缓冲区（处理粘包）：持有从流读取的 Buffer，解析前短暂 flatten。
    buf::MultiBuffer frame_buf;
    std::vector<uint8_t> write_frame;

    RelayResult result;
    parent_ctx.traffic.bytes_up = 0;
    parent_ctx.traffic.bytes_down = 0;

    auto& timeout_scheduler = TimeoutScheduler::ForIoContext(io_context);
    TimeoutToken read_poll_token;
    const uint64_t parent_conn_id = parent_ctx.conn_id;

    struct ReadPollState {
        bool timed_out = false;
        bool active = true;
        void Reset() noexcept {
            timed_out = false;
            active = true;
        }
        bool TakeActive() noexcept {
            if (!active) {
                return false;
            }
            active = false;
            return true;
        }
        void MarkInactive() noexcept {
            active = false;
        }
    };
    ReadPollState read_poll;

    bool running = true;
    bool client_input_done = false;
    auto release_write_frame = [&]() noexcept {
        write_frame.clear();
        ReleaseIdleBuffer(write_frame, kMuxFrameBufKeepCap);
    };
    auto write_multibuffer_to_client =
        [&](buf::MultiBuffer frame_mb, size_t frame_size) -> net::awaitable<bool> {
            try {
                if (frame_size == 0) {
                    frame_mb.clear();
                    co_return true;
                }

                co_await client_link.writer->WriteMultiBuffer(std::move(frame_mb));
                frame_mb.clear();
                parent_ctx.traffic.bytes_down += frame_size;
                result.bytes_down += frame_size;
                co_return true;
            } catch (const IoSystemError&) {
                if (client_control && ConsumeWriteSideTimeout(*client_control)) {
                    result.error = ErrorCode::RELAY_TIMEOUT;
                }
                co_return false;
            } catch (...) {
                co_return false;
            }
        };

    auto write_frame_to_client =
        [&](std::vector<uint8_t>& frame) -> net::awaitable<bool> {
            const size_t frame_size = frame.size();
            if (frame_size == 0) {
                release_write_frame();
                co_return true;
            }

            buf::MultiBuffer frame_mb;
            frame_mb.reserve((frame_size + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
            if (!buf::AppendSpanToMultiBuffer(
                    std::span<const uint8_t>(frame.data(), frame.size()),
                    frame_mb)) {
                result.error = ErrorCode::RESOURCE_EXHAUSTED;
                release_write_frame();
                co_return false;
            }

            const bool ok = co_await write_multibuffer_to_client(
                std::move(frame_mb), frame_size);
            release_write_frame();
            co_return ok;
        };

    auto write_payload_frame_to_client =
        [&](std::vector<uint8_t>& frame, MuxReply& reply) -> net::awaitable<bool> {
            const size_t payload_size = reply.PayloadSize();
            const size_t frame_size = frame.size() + payload_size;
            if (frame_size == 0) {
                release_write_frame();
                co_return true;
            }

            buf::MultiBuffer frame_mb;
            frame_mb.reserve(1 + reply.payload.size());
            if (!buf::AppendSpanToMultiBuffer(
                    std::span<const uint8_t>(frame.data(), frame.size()),
                    frame_mb)) {
                result.error = ErrorCode::RESOURCE_EXHAUSTED;
                release_write_frame();
                co_return false;
            }
            MoveOwnedPayloadBuffers(frame_mb, reply.payload);

            const bool ok = co_await write_multibuffer_to_client(
                std::move(frame_mb), frame_size);
            release_write_frame();
            co_return ok;
        };

    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Start");

    while (running) {
        // --------------------------------------------------------------------
        // 1. 排空回包队列 → 序列化写回客户端
        // --------------------------------------------------------------------
        MuxReply reply;
        while (reply_queue.Pop(reply)) {
            if (reply.is_end) {
                mux::EncodeEndTo(write_frame, reply.session_id);
                // 子会话已结束，清理本地记录
                if (auto udp_it = udp_subs.find(reply.session_id); udp_it != udp_subs.end()) {
                    if (udp_it->second->DispatchDone()) {
                        udp_subs.erase(udp_it);
                    }
                }
                if (auto tcp_it = tcp_subs.find(reply.session_id); tcp_it != tcp_subs.end() &&
                    tcp_it->second->DispatchDone()) {
                    tcp_subs.erase(tcp_it);
                }
            } else if (reply.is_udp) {
                const size_t payload_size = reply.PayloadSize();
                if (!mux::EncodeKeepUDPHeaderTo(
                    write_frame,
                    reply.session_id, reply.udp_src,
                    payload_size)) {
                    continue;
                }
                if (!co_await write_payload_frame_to_client(write_frame, reply)) {
                    running = false;
                    break;
                }
                continue;
            } else {
                mux::EncodeKeepDataHeaderTo(
                    write_frame,
                    reply.session_id,
                    reply.PayloadSize());
                if (!co_await write_payload_frame_to_client(write_frame, reply)) {
                    running = false;
                    break;
                }
                continue;
            }

            if (!co_await write_frame_to_client(write_frame)) {
                running = false;
                break;
            }
        }
        if (!running) break;

        if (client_input_done) {
            if (reply_queue.Empty() && reply_queue.active_sub_loops == 0) {
                break;
            }
            auto [ec] = co_await reply_queue.reply_signal.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                running = false;
                break;
            }
            continue;
        }

        if (reply_queue.tcp_overflowed) {
            reply_queue.tcp_overflowed = false;
            LOG_CONN_DEBUG(parent_ctx,
                "[MuxRelay] Reply queue overflow: tcp={}B udp={}B items={} emergency_limit={}B",
                reply_queue.tcp_queued_bytes, reply_queue.udp_queued_bytes,
                reply_queue.queue.size(), kMuxQueueEmergencyBytes);
            result.error = ErrorCode::RESOURCE_EXHAUSTED;
            break;
        }

        // --------------------------------------------------------------------
        // 2. 从客户端读取（100ms 轮询：超时则回到步骤 1 排空回包队列）
        // --------------------------------------------------------------------
        read_poll.Reset();
        read_poll_token = timeout_scheduler.ScheduleAfter(
            std::chrono::milliseconds(100),
            [&read_poll, client_control]() {
            if (client_control && read_poll.TakeActive()) {
                read_poll.timed_out = true;
                client_control->Cancel();
            }
        });

        buf::MultiBuffer read_mb;
        size_t read_bytes = 0;
        try {
            read_mb = co_await client_link.reader->ReadMultiBuffer();
            read_bytes = buf::TotalLen(read_mb);
            read_poll.MarkInactive();
            timeout_scheduler.Cancel(read_poll_token);
        } catch (const IoSystemError&) {
            read_poll.MarkInactive();
            timeout_scheduler.Cancel(read_poll_token);
            if (read_poll.timed_out) {
                if (client_control && ConsumeReadSideTimeout(*client_control)) {
                    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                    result.error = ErrorCode::RELAY_TIMEOUT;
                    running = false;
                    break;
                }
                // 100ms 超时：继续排空回包队列
                continue;
            }
            if (client_control && ConsumeReadSideTimeout(*client_control)) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
            }
            // 真实 I/O 错误
            running = false;
            break;
        }

        if (read_poll.timed_out && read_bytes == 0) {
            if (client_control && ConsumeReadSideTimeout(*client_control)) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
                running = false;
                break;
            }
            continue;
        }

        if (read_bytes == 0) {
            if (client_control && ConsumeReadSideTimeout(*client_control)) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
                running = false;
                break;
            }
            client_input_done = true;
            continue;
        }
        parent_ctx.traffic.bytes_up += read_bytes;
        result.bytes_up += read_bytes;

        AppendOwnedBuffers(frame_buf, read_mb);

        std::vector<uint8_t> frame_scratch;
        std::span<const uint8_t> parse_bytes;
        if (frame_buf.size() == 1) {
            const buf::Buffer* buffer = *frame_buf.begin();
            if (buffer && !buffer->IsEmpty()) {
                parse_bytes = buffer->Bytes();
            }
        }
        if (parse_bytes.empty() && !frame_buf.empty()) {
            CopyMultiBufferToScratch(frame_buf, frame_scratch);
            parse_bytes = std::span<const uint8_t>(
                frame_scratch.data(),
                frame_scratch.size());
        }
        const uint8_t* parse_data = parse_bytes.data();
        const size_t parse_size = parse_bytes.size();
        size_t parse_offset = 0;

        // --------------------------------------------------------------------
        // 3. 循环解析并分发 Mux 帧
        // --------------------------------------------------------------------
        while (running && parse_offset < parse_size) {
            size_t remaining = parse_size - parse_offset;
            auto opt_hdr = mux::DecodeFrame(parse_data + parse_offset, remaining);
            if (!opt_hdr) break;  // 数据不足，等待下次读取

            const mux::FrameHeader& hdr = *opt_hdr;
            if (hdr.frame_size == 0) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Invalid frame");
                result.error = ErrorCode::PROTOCOL_DECODE_FAILED;
                running = false;
                break;
            }

            // Payload 指针（仅 has_data 时有效）
            const uint8_t* payload = nullptr;
            if (hdr.has_data && hdr.data_len > 0) {
                payload = parse_data + parse_offset + (hdr.frame_size - hdr.data_len);
            }

            switch (hdr.status) {

            // ----------------------------------------------------------------
            case mux::SessionStatus::KEEPALIVE: {
                mux::EncodeKeepAliveTo(write_frame);
                if (!co_await write_frame_to_client(write_frame)) {
                    running = false;
                }
                break;
            }

            // ----------------------------------------------------------------
            case mux::SessionStatus::NEW: {
                if (hdr.network == mux::NetworkType::UDP) {
                    // ---- 新建 UDP 子会话 ----
                    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] New UDP sid={}", hdr.session_id);

                    uint16_t sid = hdr.session_id;
                    if (!hdr.has_target || udp_subs.find(sid) != udp_subs.end()) {
                        mux::EncodeEndTo(write_frame, hdr.session_id, true);
                        (void)co_await write_frame_to_client(write_frame);
                        break;
                    }

                    auto sub_state = std::make_unique<UdpSubState>(
                        io_context, sid, reply_queue, parent_conn_id);
                    auto& sub_ctx = sub_state->ctx;
                    sub_ctx.conn_id                  = session::NewID(parent_ctx.worker_id);
                    sub_ctx.worker_id                = parent_ctx.worker_id;
                    sub_ctx.inbound.source_addr      = parent_ctx.inbound.source_addr;
                    sub_ctx.inbound.source_port      = parent_ctx.inbound.source_port;
                    sub_ctx.inbound.source_ip        = parent_ctx.inbound.source_ip;
                    sub_ctx.inbound.local_endpoint   = parent_ctx.inbound.local_endpoint;
                    sub_ctx.inbound.tag              = parent_ctx.inbound.tag;
                    sub_ctx.inbound.tags             = parent_ctx.inbound.tags;
                    sub_ctx.inbound.user_id          = parent_ctx.inbound.user_id;
                    sub_ctx.inbound.user_email       = parent_ctx.inbound.user_email;
                    sub_ctx.outbound.tag             = parent_ctx.outbound.tag;
                    sub_ctx.content.speed_limit      = parent_ctx.content.speed_limit;
                    sub_ctx.content.network          = Network::UDP;
                    sub_ctx.outbound.original_target = hdr.target;
                    sub_ctx.outbound.target          = hdr.target;

                    if (payload && hdr.data_len > 0 &&
                        !sub_state->PushClientPayload(
                            hdr.target,
                            std::span<const uint8_t>(payload, hdr.data_len))) {
                        LOG_CONN_DEBUG(parent_ctx,
                            "[MuxRelay] UDP payload buffer allocation failed sid={}", sid);
                        mux::EncodeEndTo(write_frame, hdr.session_id, true);
                        (void)co_await write_frame_to_client(write_frame);
                        break;
                    }

                    auto [insert_it, inserted] = udp_subs.try_emplace(
                        sid,
                        std::move(sub_state));
                    (void)inserted;
                    UdpSubState* sub_ptr = insert_it->second.get();

                    reply_queue.AddSubLoop();
                    net::co_spawn(io_context.get_executor(),
                        RunUdpSubDispatch(
                            io_context,
                            dispatcher,
                            receiver,
                            sub_ptr,
                            stats,
                            timeouts,
                            pressure_idle_timeout,
                            config),
                        net::detached);

                } else {
                    // ---- 新建 TCP 子会话 ----
                    if (hdr.has_target) {
                        LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] New TCP sid={} -> {}",
                            hdr.session_id, hdr.target);
                    } else {
                        LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] New TCP sid={} -> ?",
                            hdr.session_id);
                    }

                    uint16_t    sid  = hdr.session_id;

                    if (tcp_subs.find(sid) != tcp_subs.end()) {
                        LOG_CONN_DEBUG(parent_ctx,
                            "[MuxRelay] duplicate TCP sid={}", sid);
                        mux::EncodeEndTo(write_frame, hdr.session_id, true);
                        (void)co_await write_frame_to_client(write_frame);
                        break;
                    }

                    auto sub_state = std::make_unique<TcpSubState>(
                        io_context, sid, reply_queue);
                    auto& sub_ctx = sub_state->ctx;
                    sub_ctx.conn_id                  = session::NewID(parent_ctx.worker_id);
                    sub_ctx.worker_id                = parent_ctx.worker_id;
                    sub_ctx.inbound.source_addr      = parent_ctx.inbound.source_addr;
                    sub_ctx.inbound.source_port      = parent_ctx.inbound.source_port;
                    sub_ctx.inbound.source_ip        = parent_ctx.inbound.source_ip;
                    sub_ctx.inbound.local_endpoint   = parent_ctx.inbound.local_endpoint;
                    sub_ctx.inbound.tag              = parent_ctx.inbound.tag;
                    sub_ctx.inbound.tags             = parent_ctx.inbound.tags;
                    sub_ctx.inbound.user_id          = parent_ctx.inbound.user_id;
                    sub_ctx.inbound.user_email       = parent_ctx.inbound.user_email;
                    sub_ctx.outbound.tag             = parent_ctx.outbound.tag;
                    sub_ctx.content.speed_limit      = parent_ctx.content.speed_limit;
                    sub_ctx.content.network          = Network::TCP;
                    if (hdr.has_target) {
                        sub_ctx.outbound.original_target = hdr.target;
                        sub_ctx.outbound.target          = hdr.target;
                    }

                    if (payload && hdr.data_len > 0 &&
                        !sub_state->PushClientPayload(
                            std::span<const uint8_t>(payload, hdr.data_len))) {
                        LOG_CONN_DEBUG(parent_ctx,
                            "[MuxRelay] TCP payload buffer allocation failed sid={}", sid);
                        mux::EncodeEndTo(write_frame, hdr.session_id, true);
                        (void)co_await write_frame_to_client(write_frame);
                        break;
                    }

                    auto [insert_it, inserted] = tcp_subs.try_emplace(
                        sid,
                        std::move(sub_state));
                    (void)inserted;
                    TcpSubState* sub_ptr = insert_it->second.get();

                    // 启动 dispatcher.Dispatch；DoMuxRelay 退出前等待 active_sub_loops
                    // 归零，保证 TcpSubState 生命周期覆盖 detached coroutine。
                    reply_queue.AddSubLoop();
                    net::co_spawn(io_context.get_executor(),
                        RunTcpSubDispatch(
                            io_context,
                            dispatcher,
                            receiver,
                            sub_ptr,
                            stats,
                            timeouts,
                            pressure_idle_timeout,
                            config),
                        net::detached);
                }
                break;
            }

            // ----------------------------------------------------------------
            case mux::SessionStatus::KEEP: {
                if (hdr.has_target) {
                    // UDP 数据包（携带目标/源地址）
                    auto it = udp_subs.find(hdr.session_id);
                    if (it != udp_subs.end() && payload && hdr.data_len > 0) {
                        if (!it->second->PushClientPayload(
                                hdr.target,
                                std::span<const uint8_t>(payload, hdr.data_len))) {
                            it->second->Cancel();
                        }
                    }
                } else {
                    // TCP 数据
                    auto it = tcp_subs.find(hdr.session_id);
                    bool tcp_write_failed = false;
                    if (it != tcp_subs.end() && payload && hdr.data_len > 0) {
                        if (!it->second->PushClientPayload(
                                std::span<const uint8_t>(payload, hdr.data_len))) {
                            tcp_write_failed = true;
                            it->second->Cancel();
                        }
                    }
                    if (tcp_write_failed) {
                        mux::EncodeEndTo(write_frame, hdr.session_id);
                        if (!co_await write_frame_to_client(write_frame)) {
                            running = false;
                        }
                    }
                }
                break;
            }

            // ----------------------------------------------------------------
            case mux::SessionStatus::END: {
                uint16_t sid = hdr.session_id;
                bool known_session = false;

                // 注销 UDP 子会话
                auto udp_it = udp_subs.find(sid);
                if (udp_it != udp_subs.end()) {
                    known_session = true;
                    udp_it->second->CloseClientInput();
                    if (udp_it->second->DispatchDone()) {
                        udp_subs.erase(udp_it);
                    }
                }

                // 取消 TCP 子会话
                auto tcp_it = tcp_subs.find(sid);
                if (tcp_it != tcp_subs.end()) {
                    known_session = true;
                    tcp_it->second->CloseClientInput();
                    if (tcp_it->second->DispatchDone()) {
                        tcp_subs.erase(tcp_it);
                    }
                }

                // 已知子会话的 END 只表示客户端输入结束；真正回给客户端的
                // END 由子会话 dispatch 完成时发送，避免先于最后一批回包到达。
                if (!known_session) {
                    mux::EncodeEndTo(write_frame, sid);
                    if (!co_await write_frame_to_client(write_frame)) {
                        running = false;
                    }
                }
                break;
            }

            }  // switch (hdr.status)

            // 移动偏移游标（O(1)），代替逐帧 erase 的 O(n) memmove
            parse_offset += hdr.frame_size;
        }

        if (parse_offset > 0) {
            ConsumeMultiBuffer(frame_buf, parse_offset);
        }
        ReleaseIdleBuffer(frame_scratch, 0);
    }

    release_write_frame();

    // ------------------------------------------------------------------------
    // 清理所有存活的子会话
    // ------------------------------------------------------------------------
    // 先标记停止，阻止回调继续推送到 reply_queue
    reply_queue.running = false;
    read_poll.MarkInactive();
    timeout_scheduler.Cancel(read_poll_token);
    co_await net::post(io_context.get_executor(), net::use_awaitable);

    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Cleanup: UDP={} TCP={}",
        udp_subs.size(), tcp_subs.size());

    for (auto& [sid, udp_sub] : udp_subs) {
        udp_sub->Cancel();
    }
    for (auto& [sid, tcp_sub] : tcp_subs) {
        tcp_sub->Cancel();
    }
    while (reply_queue.active_sub_loops > 0) {
        auto [ec] = co_await reply_queue.sub_done_signal.async_receive(
            net::as_tuple(net::use_awaitable));
        (void)ec;
    }

#ifndef NDEBUG
    const uint64_t udp_dropped = reply_queue.udp_dropped;
    if (udp_dropped > 0) {
        LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] UDP replies dropped={}", udp_dropped);
    }
#endif

    co_return result;
}

}  // namespace acpp::mux
