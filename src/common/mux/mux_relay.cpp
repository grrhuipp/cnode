#include "acppnode/common/mux/mux_relay.hpp"
#include "acppnode/features/outbound/outbound.hpp"
#include "acppnode/common/mux/mux_codec.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/infra/log.hpp"

#include <unordered_map>
#include <deque>
#include <memory>
#include <array>
#include <chrono>
#include <cstring>
#include <vector>

#include <asio/steady_timer.hpp>

namespace acpp::mux {

// ============================================================================
// 内部类型
// ============================================================================
namespace {

constexpr size_t kMuxQueueHighWaterBytes = 4 * 1024 * 1024;
constexpr size_t kMuxQueueLowWaterBytes  = 2 * 1024 * 1024;
constexpr size_t kMuxQueueEmergencyBytes = 8 * 1024 * 1024;
constexpr size_t kMuxFrameBufKeepCap     = 0;
constexpr size_t kMuxReplyOverhead       = 128;

[[nodiscard]] bool AppendSpanToMultiBuffer(std::span<const uint8_t> data,
                                           buf::MultiBuffer& out_mb) {
    size_t offset = 0;
    while (offset < data.size()) {
        buf::BufferGuard out{buf::Buffer::New()};
        if (!out) {
            return false;
        }
        const size_t chunk = std::min(
            data.size() - offset,
            static_cast<size_t>(out->Available()));
        std::memcpy(out->Tail().data(), data.data() + offset, chunk);
        out->Produce(static_cast<uint32_t>(chunk));
        out_mb.push_back(out.release());
        offset += chunk;
    }
    return true;
}

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

    [[nodiscard]] size_t PayloadSize() const noexcept {
        return buf::TotalLen(payload);
    }

    [[nodiscard]] std::span<const uint8_t> PayloadBytes(std::vector<uint8_t>& scratch) const {
        if (payload.empty()) {
            return {};
        }

        if (payload.size() == 1) {
            const buf::Buffer* buffer = *payload.begin();
            if (!buffer || buffer->IsEmpty()) {
                return {};
            }
            return buffer->Bytes();
        }

        scratch.clear();
        scratch.reserve(PayloadSize());
        for (const auto* buffer : payload) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            scratch.insert(scratch.end(), bytes.begin(), bytes.end());
        }
        return std::span<const uint8_t>(scratch.data(), scratch.size());
    }
};

struct ReplyQueueState {
    memory::ThreadLocalDeque<MuxReply> queue;
    size_t tcp_queued_bytes = 0;   // TCP 子会话回包字节（含 overhead）
    size_t udp_queued_bytes = 0;   // UDP 子会话回包字节（含 overhead）
    uint32_t active_tcp_loops = 0;
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
        return true;
    }

    void PushUdpPrepared(MuxReply&& reply, size_t reply_bytes) {
        udp_queued_bytes += reply_bytes;
        queue.push_back(std::move(reply));
        if (queue.size() >= 128 || TotalBytes() >= kMuxQueueHighWaterBytes) {
            shrink_queue_on_drain = true;
        }
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
};

// 可跨 Mux 连接共享的 UDP 拨号状态（GlobalID 复用）。dial 是 Worker 的
// UDPSessionManager 拥有的 UDPSession，非占有指针。
struct SharedUdpDial {
    UDPSession* dial = nullptr;
    std::array<uint8_t, 8> global_id{};
    uint64_t global_key = 0;
    uint32_t refs = 0;
};

// 当前 DoMuxRelay 持有的 UDP 子会话句柄
struct UdpSubInfo {
    SharedUdpDial* shared = nullptr;
    SharedUdpDial local;
    uint64_t callback_id = 0;   // 注册在本 Mux 连接上的回调 ID
    TargetAddress last_target;  // 最近发送的目标（KEEP 帧可能复用）

    UdpSubInfo() = default;
    UdpSubInfo(const UdpSubInfo&) = delete;
    UdpSubInfo& operator=(const UdpSubInfo&) = delete;

    UdpSubInfo(UdpSubInfo&& other) noexcept {
        MoveFrom(std::move(other));
    }

    UdpSubInfo& operator=(UdpSubInfo&& other) noexcept {
        if (this != &other) {
            MoveFrom(std::move(other));
        }
        return *this;
    }

    [[nodiscard]] bool UsesGlobalRegistry() const noexcept {
        return shared != nullptr && shared != &local && shared->global_key != 0;
    }

private:
    void MoveFrom(UdpSubInfo&& other) noexcept {
        const bool uses_local = other.shared == &other.local;
        local = std::move(other.local);
        shared = uses_local ? &local : other.shared;
        callback_id = other.callback_id;
        last_target = std::move(other.last_target);

        other.shared = nullptr;
        other.callback_id = 0;
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
        : input_timer_(io_context)
        , output_timer_(io_context)
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
        if (!AppendSpanToMultiBuffer(payload, mb)) {
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
        input_timer_.cancel();
    }

    void CloseClientInput() {
        if (input_done_) {
            return;
        }
        input_done_ = true;
        input_timer_.cancel();
    }

    void MarkDispatchDone() {
        dispatch_done_ = true;
        PushEnd();
        if (reply_queue_.active_tcp_loops > 0) {
            --reply_queue_.active_tcp_loops;
        }
    }

    [[nodiscard]] bool DispatchDone() const noexcept {
        return dispatch_done_;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (!cancelled_) {
            if (!input_queue_.empty()) {
                buf::MultiBuffer mb = std::move(input_queue_.front());
                input_queue_.pop_front();
                if (input_queue_.empty()) {
                    TryShrinkSequence(input_queue_);
                }
                co_return mb;
            }
            if (input_done_) {
                co_return buf::MultiBuffer{};
            }

            input_timer_.expires_after(std::chrono::hours(24));
            auto [ec] = co_await input_timer_.async_wait(
                net::as_tuple(net::use_awaitable));
            if (ec == io_error::operation_aborted) {
                continue;
            }
        }
        co_return buf::MultiBuffer{};
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        while (!cancelled_ && reply_queue_.running &&
               reply_queue_.ShouldBackpressureTcpReads()) {
            output_timer_.expires_after(std::chrono::milliseconds(10));
            auto [ec] = co_await output_timer_.async_wait(
                net::as_tuple(net::use_awaitable));
            if (ec == io_error::operation_aborted) {
                continue;
            }
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
        input_timer_.cancel();
        output_timer_.cancel();
        input_queue_.clear();
    }

    void Close() {
        Cancel();
    }

    session::Context ctx;

private:
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

    net::steady_timer input_timer_;
    net::steady_timer output_timer_;
    uint16_t session_id_ = 0;
    ReplyQueueState& reply_queue_;
    memory::ThreadLocalDeque<buf::MultiBuffer> input_queue_;
    bool input_done_ = false;
    bool cancelled_ = false;
    bool end_sent_ = false;
    bool dispatch_done_ = false;
};

using TcpSubInfo = std::unique_ptr<TcpSubState>;

// ============================================================================
// thread_local GlobalID 映射（per-Worker，接受跨 Worker 无法复用的限制）
// ============================================================================
thread_local memory::ThreadLocalUnorderedMap<uint64_t, SharedUdpDial>
    g_global_id_map;

void CleanupGlobalIdMap() {
    // 每次新建 UDP 子会话时清理无引用条目（频率不高，无需限流）。
    bool removed_idle = false;
    for (auto it = g_global_id_map.begin(); it != g_global_id_map.end(); ) {
        if (it->second.refs == 0) {
            it = g_global_id_map.erase(it);
            removed_idle = true;
        } else {
            ++it;
        }
    }
    if (removed_idle) {
        MaybeShrinkHashContainer(g_global_id_map, 64);
    }
}

SharedUdpDial* AcquireGlobalUdpDial(uint64_t key) {
    auto it = g_global_id_map.find(key);
    if (it == g_global_id_map.end()) {
        return nullptr;
    }
    ++it->second.refs;
    return &it->second;
}

SharedUdpDial* InsertGlobalUdpDial(uint64_t key,
                                   std::array<uint8_t, 8> global_id,
                                   UDPSession* dial) {
    auto [it, inserted] = g_global_id_map.try_emplace(key);
    (void)inserted;
    it->second.dial = dial;
    it->second.global_id = global_id;
    it->second.global_key = key;
    it->second.refs = 1;
    return &it->second;
}

void ReleaseUdpSub(UdpSubInfo& sub) {
    if (!sub.shared) {
        return;
    }
    if (sub.callback_id != 0) {
        if (sub.shared->dial) {
            sub.shared->dial->UnregisterCallback(sub.callback_id);
        }
        sub.callback_id = 0;
    }
    if (sub.UsesGlobalRegistry() && sub.shared->refs > 0) {
        --sub.shared->refs;
        if (sub.shared->refs == 0) {
            g_global_id_map.erase(sub.shared->global_key);
            MaybeShrinkHashContainer(g_global_id_map, 64);
        }
    }
    sub.shared = nullptr;
    sub.local = SharedUdpDial{};
}

net::awaitable<void> RunTcpSubDispatch(
    net::io_context& io_context,
    ::acpp::features::outbound::Handler& outbound_handler,
    TcpSubState* sub,
    UDPRelayConfig config)
{
    TimeoutsConfig timeouts;
    RelayConfig relay_config;
    relay_config.uplink_only = timeouts.UplinkOnlyTimeout();
    relay_config.downlink_only = timeouts.DownlinkOnlyTimeout();
    relay_config.speed_limit = config.speed_limit;

    transport::Link link{
        static_cast<transport::MultiBufferReader*>(sub),
        static_cast<transport::MultiBufferWriter*>(sub)
    };
    buf::MultiBuffer first_payload;

    try {
        (void)co_await outbound_handler.Dispatch(
            io_context,
            nullptr,
            sub->ctx,
            timeouts,
            link,
            relay_config,
            std::span<const uint8_t>{},
            first_payload,
            timeouts.StreamIdleTimeout(),
            timeouts.WriteTimeout());
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
    AsyncStream& client_stream,
    ::acpp::features::outbound::Handler& outbound_handler,
    session::Context& parent_ctx,
    const UDPRelayConfig& config)
{
    // 回包队列：单线程，无锁；running 保护回调不在 DoMuxRelay 退出后继续推送。
    ReplyQueueState reply_queue;

    // 子会话集合
    memory::ThreadLocalUnorderedMap<uint16_t, UdpSubInfo> udp_subs;
    memory::ThreadLocalUnorderedMap<uint16_t, TcpSubInfo> tcp_subs;

    // 帧累积缓冲区（处理粘包）：持有从流读取的 Buffer，解析前短暂 flatten。
    buf::MultiBuffer frame_buf;
    std::vector<uint8_t> write_frame;

    RelayResult result;
    parent_ctx.traffic.bytes_up = 0;
    parent_ctx.traffic.bytes_down = 0;

    // 轮询定时器（100ms 打断读，回到循环排空回包队列）
    net::steady_timer timer(io_context);
    const uint64_t parent_conn_id = parent_ctx.conn_id;
    AsyncStream* client_ptr = &client_stream;

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
    auto release_write_frame = [&]() noexcept {
        write_frame.clear();
        ReleaseIdleBuffer(write_frame, kMuxFrameBufKeepCap);
    };
    auto write_frame_to_client =
        [&](std::vector<uint8_t>& frame) -> net::awaitable<bool> {
            try {
                const size_t frame_size = frame.size();
                if (frame_size == 0) {
                    release_write_frame();
                    co_return true;
                }

                buf::MultiBuffer frame_mb;
                frame_mb.reserve((frame_size + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
                if (!AppendSpanToMultiBuffer(
                        std::span<const uint8_t>(frame.data(), frame.size()),
                        frame_mb)) {
                    result.error = ErrorCode::RESOURCE_EXHAUSTED;
                    release_write_frame();
                    co_return false;
                }

                co_await client_stream.WriteMultiBuffer(std::move(frame_mb));
                frame_mb.clear();
                parent_ctx.traffic.bytes_down += frame_size;
                result.bytes_down += frame_size;
                release_write_frame();
                co_return true;
            } catch (const IoSystemError&) {
                if (ConsumeWriteSideTimeout(client_stream)) {
                    result.error = ErrorCode::RELAY_TIMEOUT;
                }
                release_write_frame();
                co_return false;
            } catch (...) {
                release_write_frame();
                co_return false;
            }
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
                    ReleaseUdpSub(udp_it->second);
                    udp_subs.erase(udp_it);
                }
                if (auto tcp_it = tcp_subs.find(reply.session_id); tcp_it != tcp_subs.end() &&
                    tcp_it->second->DispatchDone()) {
                    tcp_subs.erase(tcp_it);
                }
            } else if (reply.is_udp) {
                std::vector<uint8_t> payload_scratch;
                const auto payload = reply.PayloadBytes(payload_scratch);
                if (!mux::EncodeKeepUDPTo(
                    write_frame,
                    reply.session_id, reply.udp_src,
                    payload.data(), payload.size())) {
                    ReleaseIdleBuffer(payload_scratch, 0);
                    continue;
                }
                ReleaseIdleBuffer(payload_scratch, 0);
            } else {
                std::vector<uint8_t> payload_scratch;
                const auto payload = reply.PayloadBytes(payload_scratch);
                mux::EncodeKeepDataTo(
                    write_frame,
                    reply.session_id,
                    payload.data(), payload.size());
                ReleaseIdleBuffer(payload_scratch, 0);
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

        // --------------------------------------------------------------------
        // 2. 从客户端读取（100ms 轮询：超时则回到步骤 1 排空回包队列）
        // --------------------------------------------------------------------
        read_poll.Reset();
        timer.expires_after(std::chrono::milliseconds(100));
        timer.async_wait([&read_poll, client_ptr](
                              const IoErrorCode& ec) {
            if (!ec && read_poll.TakeActive()) {
                read_poll.timed_out = true;
                client_ptr->Cancel();
            }
        });

        buf::MultiBuffer read_mb;
        size_t read_bytes = 0;
        try {
            read_mb = co_await client_stream.ReadMultiBuffer();
            read_bytes = buf::TotalLen(read_mb);
            read_poll.MarkInactive();
            timer.cancel();
        } catch (const IoSystemError&) {
            read_poll.MarkInactive();
            timer.cancel();
            if (read_poll.timed_out) {
                if (ConsumeReadSideTimeout(client_stream)) {
                    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                    result.error = ErrorCode::RELAY_TIMEOUT;
                    running = false;
                    break;
                }
                // 100ms 超时：继续排空回包队列
                continue;
            }
            if (ConsumeReadSideTimeout(client_stream)) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
            }
            // 真实 I/O 错误
            running = false;
            break;
        }

        if (read_poll.timed_out && read_bytes == 0) {
            if (ConsumeReadSideTimeout(client_stream)) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
                running = false;
                break;
            }
            continue;
        }

        if (read_bytes == 0) {
            if (ConsumeReadSideTimeout(client_stream)) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
            }
            running = false;
            break;
        }
        parent_ctx.traffic.bytes_up += read_bytes;
        result.bytes_up += read_bytes;

        AppendOwnedBuffers(frame_buf, read_mb);

        std::vector<uint8_t> frame_scratch;
        CopyMultiBufferToScratch(frame_buf, frame_scratch);
        const uint8_t* parse_data = frame_scratch.data();
        const size_t parse_size = frame_scratch.size();
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

                    // GlobalID 复用检查
                    SharedUdpDial* shared = nullptr;
                    SharedUdpDial local_udp;
                    bool use_local_udp = false;
                    if (hdr.has_global_id && !mux::IsNullGlobalId(hdr.global_id)) {
                        CleanupGlobalIdMap();
                        uint64_t gid_key = mux::GlobalIdToKey(hdr.global_id);
                        shared = AcquireGlobalUdpDial(gid_key);
                    }

                    if (!shared) {
                        // 新建 UDP 拨号
                        UDPSession* udp_dial = co_await outbound_handler.DispatchUDP(parent_ctx);
                        if (!udp_dial) {
                            LOG_CONN_DEBUG(parent_ctx,
                                "[MuxRelay] UDP dial failed sid={}", hdr.session_id);
                            mux::EncodeEndTo(write_frame, hdr.session_id, true);
                            (void)co_await write_frame_to_client(write_frame);
                            break;
                        }
                        if (hdr.has_global_id && !mux::IsNullGlobalId(hdr.global_id)) {
                            shared = InsertGlobalUdpDial(
                                mux::GlobalIdToKey(hdr.global_id),
                                hdr.global_id,
                                udp_dial);
                        } else {
                            local_udp.dial = udp_dial;
                            shared = &local_udp;
                            use_local_udp = true;
                        }
                    }

                    // 注册回包回调，推入 reply_queue。
                    // ReplyQueueState 自带 running 标志，退出时阻止继续推送。
                    uint16_t sid       = hdr.session_id;
                    auto*    rq        = &reply_queue;
                    uint64_t cb_id = shared->dial->RegisterCallback(
                        [rq, sid, parent_conn_id](UDPPacketView pkt) {
                            if (!rq->running) return;
                            LOG_ACCESS_DEBUG("[conn={}] [MuxRelay] UDP recv sid={} {}B",
                                      parent_conn_id, sid, pkt.data.size());
                            if (!rq->CanPushUdp(pkt.data.size())) {
                                const uint64_t dropped = ++rq->udp_dropped;
                                if (dropped % 100 == 1) {
                                    LOG_ACCESS_DEBUG(
                                        "[conn={}] [MuxRelay] UDP reply queue full, dropped {} packets",
                                        parent_conn_id, dropped);
                                }
                                return;
                            }
                            MuxReply reply;
                            reply.session_id = sid;
                            reply.is_end     = false;
                            reply.is_udp     = true;
                            reply.udp_src    = pkt.target;
                            if (pkt.data.size() <= buf::Buffer::kSize) {
                                buf::BufferGuard payload_buf{buf::Buffer::New()};
                                if (!payload_buf) {
                                    const uint64_t dropped = ++rq->udp_dropped;
                                    if (dropped % 100 == 1) {
                                        LOG_ACCESS_DEBUG(
                                            "[conn={}] [MuxRelay] UDP reply buffer alloc failed, dropped {} packets",
                                            parent_conn_id, dropped);
                                    }
                                    return;
                                }
                                std::memcpy(payload_buf->Tail().data(), pkt.data.data(), pkt.data.size());
                                payload_buf->Produce(static_cast<uint32_t>(pkt.data.size()));
                                reply.payload.push_back(payload_buf.release());
                            } else {
                                if (!AppendSpanToMultiBuffer(pkt.data, reply.payload)) {
                                    const uint64_t dropped = ++rq->udp_dropped;
                                    if (dropped % 100 == 1) {
                                        LOG_ACCESS_DEBUG(
                                            "[conn={}] [MuxRelay] UDP reply buffer alloc failed, dropped {} packets",
                                            parent_conn_id, dropped);
                                    }
                                    return;
                                }
                            }
                            rq->PushUdpPrepared(
                                std::move(reply),
                                pkt.data.size() + kMuxReplyOverhead);
                        });

                    UdpSubInfo sub;
                    if (use_local_udp) {
                        sub.local = std::move(local_udp);
                        sub.shared = &sub.local;
                    } else {
                        sub.shared = shared;
                    }
                    sub.callback_id = cb_id;
                    if (hdr.has_target) sub.last_target = hdr.target;

                    // 转发首包数据
                    if (payload && hdr.data_len > 0 && hdr.has_target) {
                        try {
                            co_await sub.shared->dial->SendTo(
                                hdr.target, payload, hdr.data_len, cb_id);
                        }
                        catch (...) {}
                    }

                    if (auto old = udp_subs.find(hdr.session_id); old != udp_subs.end()) {
                        ReleaseUdpSub(old->second);
                        udp_subs.erase(old);
                    }
                    udp_subs.emplace(hdr.session_id, std::move(sub));

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
                    sub_ctx.conn_id                  = parent_ctx.conn_id;
                    sub_ctx.worker_id                = parent_ctx.worker_id;
                    sub_ctx.inbound.source_addr      = parent_ctx.inbound.source_addr;
                    sub_ctx.inbound.source_port      = parent_ctx.inbound.source_port;
                    sub_ctx.inbound.source_ip        = parent_ctx.inbound.source_ip;
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

                    // 启动 outbound.Process；DoMuxRelay 退出前等待 active_tcp_loops
                    // 归零，保证 TcpSubState 生命周期覆盖 detached coroutine。
                    ++reply_queue.active_tcp_loops;
                    net::co_spawn(io_context.get_executor(),
                        RunTcpSubDispatch(
                            io_context, outbound_handler, sub_ptr, config),
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
                        it->second.last_target = hdr.target;
                        try {
                            co_await it->second.shared->dial->SendTo(
                                hdr.target,
                                payload,
                                hdr.data_len,
                                it->second.callback_id);
                        } catch (...) {}
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

                // 注销 UDP 子会话
                auto udp_it = udp_subs.find(sid);
                if (udp_it != udp_subs.end()) {
                    ReleaseUdpSub(udp_it->second);
                    udp_subs.erase(udp_it);
                }

                // 取消 TCP 子会话
                auto tcp_it = tcp_subs.find(sid);
                if (tcp_it != tcp_subs.end()) {
                    tcp_it->second->CloseClientInput();
                    if (tcp_it->second->DispatchDone()) {
                        tcp_subs.erase(tcp_it);
                    }
                }

                // 回送 End 帧
                mux::EncodeEndTo(write_frame, sid);
                if (!co_await write_frame_to_client(write_frame)) {
                    running = false;
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
    timer.cancel();
    co_await net::post(io_context.get_executor(), net::use_awaitable);

    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Cleanup: UDP={} TCP={}",
        udp_subs.size(), tcp_subs.size());

    for (auto& [sid, udp_sub] : udp_subs) {
        ReleaseUdpSub(udp_sub);
    }
    for (auto& [sid, tcp_sub] : tcp_subs) {
        tcp_sub->Cancel();
    }
    while (reply_queue.active_tcp_loops > 0) {
        co_await net::post(io_context.get_executor(), net::use_awaitable);
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
