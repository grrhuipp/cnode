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
constexpr size_t kMuxFrameBufKeepCap     = 512;
constexpr size_t kMuxReplyOverhead       = 128;

using SignalChannel = net::experimental::channel<void(IoErrorCode)>;

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
    explicit ReplyQueueState(net::io_context& io_context, SignalChannel& main_signal)
        : io_context_(io_context)
        , sub_done_signal(io_context, 1)
        , main_signal_(main_signal) {}

    net::io_context& io_context_;
    memory::ThreadLocalDeque<MuxReply> queue;
    size_t tcp_queued_bytes = 0;   // TCP 子会话回包字节（含 overhead）
    size_t udp_queued_bytes = 0;   // UDP 子会话回包字节（含 overhead）
    uint32_t active_sub_loops = 0;
    SignalChannel sub_done_signal;
    SignalChannel& main_signal_;
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
        if (io_context_.stopped()) {
            return;
        }
        (void)main_signal_.try_send(IoErrorCode{});
    }

    void AddSubLoop() noexcept {
        ++active_sub_loops;
    }

    void MarkSubLoopDone() noexcept {
        if (active_sub_loops > 0) {
            --active_sub_loops;
        }
        if (io_context_.stopped()) {
            return;
        }
        (void)sub_done_signal.try_send(IoErrorCode{});
        WakeReplyWriter();
    }
};

struct ClientReadQueueState {
    explicit ClientReadQueueState(net::io_context& io_context, SignalChannel& main_signal)
        : io_context_(io_context)
        , space_signal(io_context, 1)
        , done_signal(io_context, 1)
        , main_signal_(main_signal) {}

    net::io_context& io_context_;
    SignalChannel space_signal;
    SignalChannel done_signal;
    SignalChannel& main_signal_;
    struct QueuedInput {
        QueuedInput(buf::MultiBuffer p, size_t n) noexcept
            : payload(std::move(p))
            , bytes(n) {}

        buf::MultiBuffer payload;
        size_t bytes = 0;
    };
    memory::ThreadLocalDeque<QueuedInput> queue;
    size_t queued_bytes = 0;
    bool running = true;
    bool done = false;
    ErrorCode error = ErrorCode::OK;
    bool shrink_queue_on_drain = false;

    void WakeMain() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)main_signal_.try_send(IoErrorCode{});
    }

    void WakeDone() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)done_signal.try_send(IoErrorCode{});
        WakeMain();
    }

    void WakeSpace() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)space_signal.try_send(IoErrorCode{});
    }

    [[nodiscard]] bool Push(buf::MultiBuffer mb, size_t bytes) {
        if (queued_bytes + bytes > kMuxQueueEmergencyBytes) {
            mb.clear();
            return false;
        }
        queued_bytes += bytes;
        queue.emplace_back(std::move(mb), bytes);
        if (queue.size() >= kMuxQueueShrinkItems ||
            queued_bytes >= kMuxQueueHighWaterBytes) {
            shrink_queue_on_drain = true;
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
        if (queue.empty() && shrink_queue_on_drain) {
            TryShrinkSequence(queue);
            shrink_queue_on_drain = false;
        }
        if (ReadWindowOpen()) {
            WakeSpace();
        }
        return true;
    }

    [[nodiscard]] bool ShouldBackpressureReads() const noexcept {
        return queued_bytes >= kMuxQueueHighWaterBytes;
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
        WakeDone();
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

    [[nodiscard]] bool PushClientPayload(buf::MultiBuffer mb) {
        const size_t bytes = buf::TotalLen(mb);
        if (cancelled_ || input_done_ || bytes == 0) {
            mb.clear();
            return true;
        }
        queued_bytes_ += bytes;
        input_queue_.emplace_back(std::move(mb), bytes);
        if (input_queue_.size() >= kMuxQueueShrinkItems ||
            queued_bytes_ >= kMuxQueueHighWaterBytes) {
            shrink_input_queue_on_drain_ = true;
        }
        WakeInputReader();
        return true;
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
                auto& input = input_queue_.front();
                queued_bytes_ -= std::min(queued_bytes_, input.bytes);
                buf::MultiBuffer payload = std::move(input.payload);
                input_queue_.pop_front();
                if (input_queue_.empty() && shrink_input_queue_on_drain_) {
                    TryShrinkSequence(input_queue_);
                    shrink_input_queue_on_drain_ = false;
                }
                co_return payload;
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

    [[nodiscard]] bool ForwardHalfCloseToPeerOnEof() const noexcept {
        return true;
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
                mb.FreeSlot(buffer);
                continue;
            }

            MuxReply reply;
            reply.session_id = session_id_;
            reply.is_end = false;
            reply.is_udp = false;
            reply.payload_size = buffer->Len();
            reply.payload.push_back(mb.ReleaseSlot(buffer));
            if (!reply_queue_.PushTcp(std::move(reply))) {
                reply_queue_.tcp_overflowed = true;
                Cancel();
                break;
            }
        }
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        while (!cancelled_ && reply_queue_.running &&
               reply_queue_.ShouldBackpressureTcpReads()) {
            co_await output_sleep_.WaitFor(std::chrono::milliseconds(10));
        }

        if (cancelled_ || !reply_queue_.running) {
            co_return;
        }

        for (const net::const_buffer& buffer : buffers) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            if (!data || buffer.size() == 0) {
                continue;
            }

            buf::MultiBuffer payload;
            if (!buf::AppendSpanToMultiBuffer(
                    std::span<const uint8_t>(data, buffer.size()),
                    payload)) {
                throw std::bad_alloc();
            }

            MuxReply reply;
            reply.session_id = session_id_;
            reply.is_end = false;
            reply.is_udp = false;
            reply.payload_size = buffer.size();
            reply.payload = std::move(payload);
            if (!reply_queue_.PushTcp(std::move(reply))) {
                reply_queue_.tcp_overflowed = true;
                Cancel();
                break;
            }
        }
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
        queued_bytes_ = 0;
        shrink_input_queue_on_drain_ = false;
    }

    void Close() {
        Cancel();
    }

    session::Context ctx;

private:
    void WakeInputReader() noexcept {
        if (io_context_.stopped()) {
            return;
        }
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
    struct QueuedInput {
        QueuedInput(buf::MultiBuffer p, size_t n) noexcept
            : payload(std::move(p))
            , bytes(n) {}

        buf::MultiBuffer payload;
        size_t bytes = 0;
    };
    memory::ThreadLocalDeque<QueuedInput> input_queue_;
    size_t queued_bytes_ = 0;
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
        uint64_t parent_conn_id,
        TargetAddress default_target,
        bool xudp_packet_mode)
        : io_context_(io_context)
        , input_signal_(io_context, 1)
        , session_id_(session_id)
        , reply_queue_(reply_queue)
        , parent_conn_id_(parent_conn_id)
        , default_target_(std::move(default_target))
        , xudp_packet_mode_(xudp_packet_mode) {}

    ~UdpSubState() noexcept override {
        Cancel();
    }

    UdpSubState(const UdpSubState&) = delete;
    UdpSubState& operator=(const UdpSubState&) = delete;

    void PushClientPayload(buf::MultiBuffer mb) {
        const size_t bytes = buf::TotalLen(mb);
        PushClientPayload(std::move(mb), bytes);
    }

    void PushClientPayload(buf::MultiBuffer mb, size_t bytes) {
        if (cancelled_ || input_done_ || bytes == 0) {
            mb.clear();
            return;
        }
        if (queued_bytes_ + bytes > kMuxQueueEmergencyBytes) {
            mb.clear();
            Cancel();
            return;
        }
        if (xudp_packet_mode_) {
            FeedXudpPackets(std::move(mb));
            return;
        }
        StampDefaultTarget(mb);
        queued_bytes_ += bytes;
        input_queue_.emplace_back(std::move(mb), bytes);
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
                auto& input = input_queue_.front();
                queued_bytes_ -= std::min(queued_bytes_, input.bytes);
                buf::MultiBuffer payload = std::move(input.payload);
                input_queue_.pop_front();
                if (input_queue_.empty() && shrink_input_queue_on_drain_) {
                    TryShrinkSequence(input_queue_);
                    shrink_input_queue_on_drain_ = false;
                }
                co_return payload;
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
                mb.FreeSlot(buffer);
                continue;
            }
            if (!buffer->HasUDP()) {
                mb.FreeSlot(buffer);
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
                mb.FreeSlot(buffer);
                continue;
            }

            MuxReply reply;
            reply.session_id = session_id_;
            reply.is_end = false;
            reply.is_udp = true;
            reply.udp_src = buffer->UDP();
            reply.payload_size = payload_bytes;
            reply.payload.push_back(mb.ReleaseSlot(buffer));
            reply_queue_.PushUdpPrepared(
                std::move(reply), payload_bytes + kMuxReplyOverhead);
        }
        mb.clear();
        co_return;
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer>) override {
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
        if (io_context_.stopped()) {
            return;
        }
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
    TargetAddress default_target_;
    bool xudp_packet_mode_ = false;
    buf::MultiBuffer xudp_pending_;
    size_t xudp_pending_bytes_ = 0;
    struct QueuedInput {
        QueuedInput(buf::MultiBuffer p, size_t n) noexcept
            : payload(std::move(p))
            , bytes(n) {}

        buf::MultiBuffer payload;
        size_t bytes = 0;
    };
    memory::ThreadLocalDeque<QueuedInput> input_queue_;
    size_t queued_bytes_ = 0;
    bool shrink_input_queue_on_drain_ = false;
    bool input_done_ = false;
    bool cancelled_ = false;
    bool end_sent_ = false;
    bool dispatch_done_ = false;

    void StampDefaultTarget(buf::MultiBuffer& mb) {
        for (auto* buffer : mb) {
            if (buffer && !buffer->IsEmpty() && !buffer->HasUDP()) {
                buffer->SetUDP(default_target_);
            }
        }
    }

    void QueueDecodedPayload(buf::MultiBuffer payload, size_t bytes) {
        if (bytes == 0) {
            payload.clear();
            return;
        }
        if (queued_bytes_ + bytes > kMuxQueueEmergencyBytes) {
            payload.clear();
            Cancel();
            return;
        }
        StampDefaultTarget(payload);
        queued_bytes_ += bytes;
        input_queue_.emplace_back(std::move(payload), bytes);
        if (input_queue_.size() >= kMuxQueueShrinkItems ||
            queued_bytes_ >= kMuxQueueHighWaterBytes) {
            shrink_input_queue_on_drain_ = true;
        }
        WakeInputReader();
    }

    void FeedXudpPackets(buf::MultiBuffer mb) {
        const size_t bytes = buf::TotalLen(mb);
        if (bytes == 0) {
            return;
        }
        mb.MoveTo(xudp_pending_);
        xudp_pending_bytes_ += bytes;

        while (xudp_pending_bytes_ >= 2) {
            std::array<uint8_t, 2> len_bytes{};
            if (xudp_pending_.CopyPrefixTo(len_bytes) != len_bytes.size()) {
                return;
            }
            const size_t packet_len =
                (static_cast<size_t>(len_bytes[0]) << 8) |
                static_cast<size_t>(len_bytes[1]);
            if (packet_len > buf::Buffer::kSize) {
                xudp_pending_.clear();
                xudp_pending_bytes_ = 0;
                Cancel();
                return;
            }
            if (xudp_pending_bytes_ < 2 + packet_len) {
                return;
            }

            xudp_pending_.DropPrefixBytes(2);
            xudp_pending_bytes_ -= 2;
            buf::MultiBuffer payload;
            if (!xudp_pending_.MovePrefixTo(payload, packet_len)) {
                xudp_pending_.clear();
                xudp_pending_bytes_ = 0;
                Cancel();
                return;
            }
            xudp_pending_bytes_ -= packet_len;
            QueueDecodedPayload(std::move(payload), packet_len);
        }
    }
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
    using namespace net::experimental::awaitable_operators;

    if (!client_link.Valid()) {
        RelayResult error;
        error.error = ErrorCode::PROTOCOL_DECODE_FAILED;
        co_return error;
    }

    // 回包队列：单线程，无锁；running 保护回调不在 DoMuxRelay 退出后继续推送。
    SignalChannel main_signal{io_context, 1};
    ReplyQueueState reply_queue{io_context, main_signal};
    ClientReadQueueState client_reads{io_context, main_signal};

    // 子会话集合
    memory::ThreadLocalUnorderedMap<uint16_t, UdpSubInfo> udp_subs;
    memory::ThreadLocalUnorderedMap<uint16_t, TcpSubInfo> tcp_subs;

    // 帧累积缓冲区（处理粘包）：持有从流读取的 Buffer，解析前短暂 flatten。
    buf::MultiBuffer frame_buf;
    size_t frame_buf_bytes = 0;
    memory::ByteVector write_frame;

    RelayResult result;
    parent_ctx.traffic.bytes_up = 0;
    parent_ctx.traffic.bytes_down = 0;

    const uint64_t parent_conn_id = parent_ctx.conn_id;

    bool running = true;
    bool client_input_done = false;

    auto client_reader_loop = [&]() -> net::awaitable<void> {
        while (client_reads.running) {
            try {
                buf::MultiBuffer read_mb = co_await client_link.reader->ReadMultiBuffer();
                if (!buf::HasData(read_mb)) {
                    client_reads.MarkDone(ErrorCode::OK);
                    co_return;
                }
                const size_t read_bytes = buf::TotalLen(read_mb);
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
            } catch (const IoSystemError&) {
                ErrorCode ec = ErrorCode::OK;
                if (client_control && ConsumeReadSideTimeout(*client_control)) {
                    ec = ErrorCode::RELAY_TIMEOUT;
                }
                client_reads.MarkDone(ec);
                co_return;
            } catch (...) {
                client_reads.MarkDone(ErrorCode::INTERNAL);
                co_return;
            }
        }
        client_reads.MarkDone(ErrorCode::OK);
    };

    net::co_spawn(io_context.get_executor(), client_reader_loop(), net::detached);
    auto release_write_frame = [&]() noexcept {
        write_frame.clear();
        ReleaseIdleBuffer(write_frame, kMuxFrameBufKeepCap);
    };
    auto write_frame_to_client =
        [&](memory::ByteVector& frame) -> net::awaitable<bool> {
            const size_t frame_size = frame.size();
            if (frame_size == 0) {
                release_write_frame();
                co_return true;
            }

            std::array<net::const_buffer, 1> buffers{
                net::const_buffer(frame.data(), frame.size())};
            try {
                co_await client_link.writer->WriteBuffers(buffers);
                parent_ctx.traffic.bytes_down += frame_size;
                result.bytes_down += frame_size;
                release_write_frame();
                co_return true;
            } catch (const IoSystemError&) {
                if (client_control && ConsumeWriteSideTimeout(*client_control)) {
                    result.error = ErrorCode::RELAY_TIMEOUT;
                }
            } catch (...) {
            }
            release_write_frame();
            co_return false;
        };

    auto write_payload_frame_to_client =
        [&](memory::ByteVector& frame, MuxReply& reply) -> net::awaitable<bool> {
            const size_t payload_size = reply.PayloadSize();
            const size_t frame_size = frame.size() + payload_size;
            if (frame_size == 0) {
                release_write_frame();
                co_return true;
            }

            std::array<net::const_buffer, 1 + buf::MultiBuffer::kInlineCapacity>
                inline_buffers{};
            memory::ThreadLocalVector<net::const_buffer> spill_buffers;
            size_t buffer_count = 0;
            auto append_buffer = [&](net::const_buffer send_buffer) {
                if (buffer_count < inline_buffers.size()) {
                    inline_buffers[buffer_count++] = send_buffer;
                    return;
                }
                if (spill_buffers.empty()) {
                    spill_buffers.reserve(1 + reply.payload.size());
                    spill_buffers.insert(
                        spill_buffers.end(),
                        inline_buffers.begin(),
                        inline_buffers.begin() + buffer_count);
                }
                spill_buffers.emplace_back(send_buffer);
                ++buffer_count;
            };

            if (!frame.empty()) {
                append_buffer(net::const_buffer(frame.data(), frame.size()));
            }
            for (const auto* buffer : reply.payload) {
                if (!buffer || buffer->IsEmpty()) {
                    continue;
                }
                const auto bytes = buffer->Bytes();
                append_buffer(net::const_buffer(bytes.data(), bytes.size()));
            }

            const auto buffers = spill_buffers.empty()
                ? std::span<const net::const_buffer>(
                    inline_buffers.data(),
                    buffer_count)
                : std::span<const net::const_buffer>(
                    spill_buffers.data(),
                    spill_buffers.size());

            try {
                co_await client_link.writer->WriteBuffers(buffers);
                reply.payload.clear();
                parent_ctx.traffic.bytes_down += frame_size;
                result.bytes_down += frame_size;
                release_write_frame();
                co_return true;
            } catch (const IoSystemError&) {
                if (client_control && ConsumeWriteSideTimeout(*client_control)) {
                    result.error = ErrorCode::RELAY_TIMEOUT;
                }
            } catch (...) {
            }
            reply.payload.clear();
            release_write_frame();
            co_return false;
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
                    LOG_CONN_DEBUG(parent_ctx,
                        "[MuxRelay] UDP reply header encode failed sid={} src={} payload={}B",
                        reply.session_id, reply.udp_src, payload_size);
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

        if (reply_queue.tcp_overflowed) {
            reply_queue.tcp_overflowed = false;
            LOG_CONN_DEBUG(parent_ctx,
                "[MuxRelay] Reply queue overflow: tcp={}B udp={}B items={} emergency_limit={}B",
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

        // --------------------------------------------------------------------
        // 2. 消费客户端读队列。读操作由独立协程持有，避免为了轮询回包而
        //    Cancel 底层协议 reader，导致 VMess/VLESS 流被提前关闭。
        // --------------------------------------------------------------------
        buf::MultiBuffer read_mb;
        if (!client_reads.Pop(read_mb)) {
            if (!reply_queue.Empty()) {
                continue;
            }
            if (client_reads.done) {
                if (client_reads.error != ErrorCode::OK) {
                    if (client_reads.error == ErrorCode::RELAY_TIMEOUT) {
                        LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                    }
                    result.error = client_reads.error;
                    running = false;
                    break;
                }
                client_input_done = true;
                continue;
            }

            auto [ec] = co_await main_signal.async_receive(
                net::as_tuple(net::use_awaitable));
            (void)ec;
            continue;
        }

        const size_t read_bytes = buf::TotalLen(read_mb);
        if (read_bytes == 0) {
            if (client_reads.done && client_reads.error == ErrorCode::RELAY_TIMEOUT) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
                running = false;
                break;
            }
            if (client_reads.done && client_reads.error != ErrorCode::OK) {
                result.error = client_reads.error;
                running = false;
                break;
            }
            continue;
        }
        parent_ctx.traffic.bytes_up += read_bytes;
        result.bytes_up += read_bytes;

        read_mb.MoveTo(frame_buf);
        frame_buf_bytes += read_bytes;

        // --------------------------------------------------------------------
        // 3. 循环解析并分发 Mux 帧
        // --------------------------------------------------------------------
        while (running && frame_buf_bytes > 0) {
            std::optional<mux::FrameHeader> opt_hdr;
            const auto prefix = frame_buf.FrontSpan();
            if (!prefix.empty()) {
                opt_hdr = mux::DecodeFramePrefix(
                    prefix.data(),
                    prefix.size(),
                    frame_buf_bytes);
            }
            if (!opt_hdr) {
                opt_hdr = mux::DecodeFrame(frame_buf, 0, frame_buf_bytes);
            }
            if (!opt_hdr) break;  // 数据不足，等待下次读取

            const mux::FrameHeader& hdr = *opt_hdr;
            if (hdr.frame_size == 0) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Invalid frame");
                result.error = ErrorCode::PROTOCOL_DECODE_FAILED;
                running = false;
                break;
            }

            buf::MultiBuffer frame_payload;
            if (hdr.has_data && hdr.data_len > 0) {
                if (frame_buf.DropPrefixBytes(hdr.data_offset) != hdr.data_offset ||
                    !frame_buf.MovePrefixTo(frame_payload, hdr.data_len)) {
                    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] payload extraction failed");
                    result.error = ErrorCode::RESOURCE_EXHAUSTED;
                    running = false;
                    break;
                }
            } else {
                frame_buf.DropPrefixBytes(hdr.frame_size);
            }
            frame_buf_bytes -= std::min(frame_buf_bytes, hdr.frame_size);

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
                    LOG_CONN_DEBUG(parent_ctx,
                        "[MuxRelay] New UDP sid={} target={} data={}B global_id={}",
                        hdr.session_id, hdr.target, hdr.data_len, hdr.has_global_id);

                    uint16_t sid = hdr.session_id;
                    if (!hdr.has_target || udp_subs.find(sid) != udp_subs.end()) {
                        mux::EncodeEndTo(write_frame, hdr.session_id, true);
                        (void)co_await write_frame_to_client(write_frame);
                        break;
                    }

                    auto sub_state = std::make_unique<UdpSubState>(
                        io_context,
                        sid,
                        reply_queue,
                        parent_conn_id,
                        hdr.target,
                        hdr.has_global_id);
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

                    if (buf::HasData(frame_payload)) {
                        for (auto* buffer : frame_payload) {
                            if (buffer && !buffer->IsEmpty()) {
                                buffer->SetUDP(hdr.target);
                            }
                        }
                        sub_state->PushClientPayload(std::move(frame_payload), hdr.data_len);
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

                    if (buf::HasData(frame_payload) &&
                        !sub_state->PushClientPayload(std::move(frame_payload))) {
                        LOG_CONN_DEBUG(parent_ctx,
                            "[MuxRelay] TCP input queue overflow sid={}", sid);
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
                auto udp_it = udp_subs.find(hdr.session_id);
                if (udp_it != udp_subs.end()) {
                    if (hdr.has_target && buf::HasData(frame_payload)) {
                        for (auto* buffer : frame_payload) {
                            if (buffer && !buffer->IsEmpty()) {
                                buffer->SetUDP(hdr.target);
                            }
                        }
                    }
                    if (buf::HasData(frame_payload)) {
                        udp_it->second->PushClientPayload(std::move(frame_payload), hdr.data_len);
                    }
                } else {
                    // TCP 数据
                    auto it = tcp_subs.find(hdr.session_id);
                    bool tcp_write_failed = false;
                    if (it != tcp_subs.end() && buf::HasData(frame_payload)) {
                        if (!it->second->PushClientPayload(std::move(frame_payload))) {
                            tcp_write_failed = true;
                        }
                    }
                    if (tcp_write_failed) {
                        if (it != tcp_subs.end()) {
                            it->second->Cancel();
                        }
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
                    if (hdr.has_target && buf::HasData(frame_payload)) {
                        for (auto* buffer : frame_payload) {
                            if (buffer && !buffer->IsEmpty()) {
                                buffer->SetUDP(hdr.target);
                            }
                        }
                    }
                    if (buf::HasData(frame_payload)) {
                        udp_it->second->PushClientPayload(std::move(frame_payload), hdr.data_len);
                    }
                    udp_it->second->CloseClientInput();
                    if (udp_it->second->DispatchDone()) {
                        udp_subs.erase(udp_it);
                    }
                }

                // 取消 TCP 子会话
                auto tcp_it = tcp_subs.find(sid);
                if (tcp_it != tcp_subs.end()) {
                    known_session = true;
                    if (buf::HasData(frame_payload) &&
                        !tcp_it->second->PushClientPayload(std::move(frame_payload))) {
                        tcp_it->second->Cancel();
                    }
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
        }
    }

    release_write_frame();

    // ------------------------------------------------------------------------
    // 清理所有存活的子会话
    // ------------------------------------------------------------------------
    // 先标记停止，阻止回调继续推送到 reply_queue
    reply_queue.running = false;
    client_reads.running = false;
    client_reads.WakeSpace();
    if (client_control) {
        client_control->Cancel();
    }
    while (!client_reads.done) {
        auto [ec] = co_await client_reads.done_signal.async_receive(
            net::as_tuple(net::use_awaitable));
        if (ec) {
            break;
        }
    }
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
