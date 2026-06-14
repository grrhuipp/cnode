#include "acppnode/app/relay.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/app/token_bucket.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/steady_timer.hpp>
#include <cstring>
#include <deque>
#include <format>
#include <memory>

namespace acpp {

namespace {

constexpr uint64_t kUdpRelayStatsFlushBytes = 64 * 1024;

class UdpRateTimerGuard {
public:
    explicit UdpRateTimerGuard(net::io_context& io_context) noexcept
        : io_context_(io_context) {}

    ~UdpRateTimerGuard() noexcept {
        if (!timer_) {
            return;
        }
        std::destroy_at(timer_);
        memory::ThreadLocalAllocator<net::steady_timer> alloc;
        alloc.deallocate(timer_, 1);
    }

    UdpRateTimerGuard(const UdpRateTimerGuard&) = delete;
    UdpRateTimerGuard& operator=(const UdpRateTimerGuard&) = delete;

    [[nodiscard]] net::steady_timer& Get() {
        if (!timer_) {
            memory::ThreadLocalAllocator<net::steady_timer> alloc;
            timer_ = alloc.allocate(1);
            std::construct_at(timer_, io_context_);
        }
        return *timer_;
    }

private:
    net::io_context& io_context_;
    net::steady_timer* timer_ = nullptr;
};

void FlushUdpRelayStats(StatsShard& stats, LocalStatsAccumulator& acc) {
    if (acc.bytes_in == 0 && acc.bytes_out == 0) {
        return;
    }
    stats.CommitAccumulator(acc);
    acc.Reset();
}

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

}  // namespace

// ============================================================================
// DoUDPRelayLink — xray-core outbound.Process 数据面（协议无关 UDP relay）
//
// 由 UDP-capable 出站的 Process 在 dispatcher.Dispatch -> outbound.Process
// 链路内调用：client_reader/client_writer 是入站 transport::Link 端点，session
// 是该 Worker 本地 Full Cone UDP socket。逐包目标由 buffer.udp 携带
// （入站 reader/writer helper 填写）；relay 层不感知具体协议。上行与回包
// 作为同一 Worker io_context 上的两个并发协程运行，client 侧空闲读取由入站
// stream 的 idle timeout 终止，不再依赖单一 poll + AsyncStream::Cancel。
// ============================================================================
net::awaitable<RelayResult> DoUDPRelayLink(
    net::io_context& io_context,
    transport::MultiBufferReader& client_reader,
    transport::MultiBufferWriter& client_writer,
    UDPSession& session,
    session::Context& ctx,
    StatsShard& stats,
    const UDPRelayConfig& config) {

    using namespace net::experimental::awaitable_operators;

    RelayResult result;
    ctx.traffic.bytes_up = 0;
    ctx.traffic.bytes_down = 0;

    // 回包队列：单线程，无锁。UDP 接收回调在同一 Worker io_context 上 push，
    // download 协程 pop。wake 计时器用于在新回包到达时唤醒等待中的 download。
    struct SharedState {
        struct UdpRelayReply {
            TargetAddress target;
            buf::MultiBuffer payload;

            [[nodiscard]] size_t Size() const noexcept {
                return buf::TotalLen(payload);
            }
        };

        bool running = true;
        memory::ThreadLocalDeque<UdpRelayReply> reply_queue;
        size_t queued_bytes = 0;
        uint64_t total_replies = 0;
        bool shrink_queue_on_drain = false;
        net::steady_timer* wake = nullptr;

        void push(UdpRelayReply&& pkt) {
            const size_t pkt_bytes = pkt.Size();
            queued_bytes += pkt_bytes;
            reply_queue.push_back(std::move(pkt));
            if (reply_queue.size() >= 64 || queued_bytes >= 256 * 1024) {
                shrink_queue_on_drain = true;
            }
            if (wake) {
                wake->cancel();
            }
        }

        void push(UDPPacketView pkt) {
            UdpRelayReply owned;
            owned.target = pkt.target;
            if (!AppendSpanToMultiBuffer(pkt.data, owned.payload)) {
                return;
            }
            push(std::move(owned));
        }

        bool pop(UdpRelayReply& pkt) {
            if (reply_queue.empty()) return false;
            queued_bytes -= reply_queue.front().Size();
            pkt = std::move(reply_queue.front());
            reply_queue.pop_front();
            if (reply_queue.empty() && shrink_queue_on_drain) {
                TryShrinkSequence(reply_queue);
                shrink_queue_on_drain = false;
            }
            return true;
        }

        bool empty() const { return reply_queue.empty(); }
    };
    SharedState state;

    net::steady_timer reply_wake(io_context);
    state.wake = &reply_wake;

    const uint64_t conn_id = ctx.conn_id;
    uint64_t callback_id = session.RegisterCallback(
        [&state, conn_id](UDPPacketView pkt) {
            if (!state.running) return;
            LOG_ACCESS_DEBUG("[conn={}] UDP Full Cone received {} bytes from {}",
                      conn_id, pkt.data.size(), pkt.target);
            ++state.total_replies;
            state.push(pkt);
        });
    LOG_CONN_DEBUG(ctx, "Registered Full Cone callback {}", callback_id);

    // 上行/下行各自独立的限速器与限速计时器，避免两个协程共享同一 timer。
    TokenBucket upload_limiter(config.speed_limit);
    TokenBucket download_limiter(config.speed_limit);
    UdpRateTimerGuard upload_rate_timer(io_context);
    UdpRateTimerGuard download_rate_timer(io_context);
    LocalStatsAccumulator stats_acc;

    // 回包交给 client_writer：buffer 携带来源地址（buffer.udp），由入站
    // reader-writer helper 负责封帧/编码。relay 层不感知具体协议。
    auto send_reply = [&](SharedState::UdpRelayReply& packet) -> net::awaitable<bool> {
        try {
            const size_t send_len = packet.Size();
            if (send_len == 0) {
                co_return false;
            }
            // 标注来源地址，供 client_writer 封帧（回包通常 <= 8KB，仅一个 buffer）。
            for (buf::Buffer* b : packet.payload) {
                if (b) {
                    b->SetUDP(packet.target);
                }
            }

            // 下行限速
            auto wait_time = download_limiter.Consume(send_len);
            if (wait_time.count() > 0) {
                auto& timer = download_rate_timer.Get();
                timer.expires_after(wait_time);
                co_await timer.async_wait(net::use_awaitable);
            }

            co_await client_writer.WriteMultiBuffer(std::move(packet.payload));
            packet.payload.clear();
            ctx.traffic.bytes_down += send_len;
            result.bytes_down += send_len;
            stats_acc.AddBytesIn(send_len);
            if (stats_acc.bytes_in + stats_acc.bytes_out >= kUdpRelayStatsFlushBytes) {
                FlushUdpRelayStats(stats, stats_acc);
            }
            co_return true;

        } catch (const std::exception& e) {
            LOG_CONN_DEBUG(ctx, "UDP reply write failed: {}", e.what());
            co_return false;
        }
    };

    LOG_CONN_DEBUG(ctx, "UDP relay started, target={}", ctx.outbound.original_target);

    // ── 上行：client -> framer/passthrough -> remote ──────────────────────────
    auto upload = [&]() -> net::awaitable<void> {
        while (state.running) {
            buf::MultiBuffer read_mb;
            size_t read_bytes = 0;
            try {
                read_mb = co_await client_reader.ReadMultiBuffer();
                read_bytes = buf::TotalLen(read_mb);
            } catch (const IoSystemError& e) {
                if (result.error == ErrorCode::OK) {
                    result.error = MapAsioError(e.code());
                }
                break;
            } catch (...) {
                if (result.error == ErrorCode::OK) {
                    result.error = ErrorCode::INTERNAL;
                }
                break;
            }

            if (read_bytes == 0) {
                // 入站读到 EOF：client 关闭隧道，结束上行并触发回包收尾。
                LOG_CONN_DEBUG(ctx, "UDP relay: client EOF, up={}B down={}B",
                               result.bytes_up, result.bytes_down);
                result.client_closed_first = true;
                break;
            }

            ctx.traffic.bytes_up += read_bytes;
            result.bytes_up += read_bytes;
            stats_acc.AddBytesOut(read_bytes);
            if (stats_acc.bytes_in + stats_acc.bytes_out >= kUdpRelayStatsFlushBytes) {
                FlushUdpRelayStats(stats, stats_acc);
            }

            // 上行限速
            {
                auto wait_time = upload_limiter.Consume(read_bytes);
                if (wait_time.count() > 0) {
                    auto& timer = upload_rate_timer.Get();
                    timer.expires_after(wait_time);
                    co_await timer.async_wait(net::use_awaitable);
                }
            }

            // 每个 buffer 携带自身目标（buffer.udp），由协议 reader-writer helper
            // 在入站侧解析填好；relay 只按 buffer.udp 逐包发往 Full Cone session。
            for (buf::Buffer* buffer : read_mb) {
                if (!buffer || buffer->IsEmpty()) {
                    continue;
                }
                if (!buffer->HasUDP()) {
                    LOG_CONN_DEBUG(ctx, "UDP relay: buffer without target dropped {}B",
                                   buffer->Len());
                    continue;
                }
                auto bytes = buffer->Bytes();
                LOG_CONN_DEBUG(ctx, "UDP send: target={}, data_len={}",
                               buffer->udp, bytes.size());
                auto send_result = co_await session.SendTo(
                    buffer->udp, bytes.data(), bytes.size(), callback_id);
                if (send_result != ErrorCode::OK) {
                    LOG_CONN_DEBUG(ctx, "UDP send failed: {}", ErrorCodeToString(send_result));
                }
            }
        }

        // 上行结束：通知 download 收尾。
        state.running = false;
        reply_wake.cancel();
        co_return;
    };

    // ── 回包：remote -> framer -> client ──────────────────────────────────────
    auto download = [&]() -> net::awaitable<void> {
        while (true) {
            SharedState::UdpRelayReply pkt;
            size_t sent_batch = 0;
            while (sent_batch < 32 && state.pop(pkt)) {
                bool ok = co_await send_reply(pkt);
                if (!ok) {
                    state.running = false;
                    reply_wake.cancel();
                    co_return;
                }
                ++sent_batch;
            }
            if (sent_batch > 0) {
                LOG_CONN_DEBUG(ctx, "Sent {} reply packets (batched)", sent_batch);
            }

            if (!state.running && state.empty()) {
                co_return;
            }

            // 等待新回包；100ms 兜底轮询防止 push 唤醒竞态丢失。
            reply_wake.expires_after(std::chrono::milliseconds(100));
            try {
                co_await reply_wake.async_wait(net::use_awaitable);
            } catch (...) {
            }
        }
    };

    co_await (upload() && download());

    state.running = false;
    reply_wake.cancel();
    session.UnregisterCallback(callback_id);
    LOG_CONN_DEBUG(ctx, "Unregistered Full Cone callback {}", callback_id);
    co_await net::post(io_context.get_executor(), net::use_awaitable);
    FlushUdpRelayStats(stats, stats_acc);

#ifndef NDEBUG
    if (state.total_replies > 0) {
        LOG_CONN_DEBUG(ctx, "UDP relay stats: total_replies={}, queued_bytes={}",
                       state.total_replies, state.queued_bytes);
    }
    LOG_CONN_DEBUG(ctx, "UDP relay finished: up={} down={}", result.bytes_up, result.bytes_down);
#endif

    co_return result;
}

}  // namespace acpp
