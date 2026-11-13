#pragma once

#include "common/asio_types.hpp"
#include "common/multi_buffer.hpp"
#include "transport/link.hpp"

#include <asio/this_coro.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace proxy {

// 带 pending 缓冲的精确读取器：握手与记录层按字节数精确消费底层
// MultiBufferReader，多读到的字节留在 pending，之后经 ReadMultiBuffer 原样交出。
// 进度可由调用方持有，取消后续读不丢失已到达的字节。
class BufferedStreamReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return src_.ReadEofAction(); }
    [[nodiscard]] bool EnableRawRead() noexcept override { return src_.EnableRawRead(); }
    explicit BufferedStreamReader(transport::MultiBufferReader& src) noexcept : src_(src) {}

    [[nodiscard]] bool ReadBuffered(uint8_t* data, size_t len, size_t& done) noexcept {
        return ReadBufferedFrom(pending_, data, len, done);
    }
    [[nodiscard]] static bool ReadBufferedFrom(
        common::MultiBuffer& pending, uint8_t* data, size_t len, size_t& done) noexcept {
        if (done < len)
            done += pending.ConsumePrefixTo(std::span<uint8_t>(data + done, len - done));
        return done >= len;
    }

    net::awaitable<bool> ReadExact(uint8_t* data, size_t len, size_t* progress = nullptr) {
        return ReadExactFrom(src_, pending_, data, len, progress);
    }
    static net::awaitable<bool> ReadExactFrom(
        transport::MultiBufferReader& src, common::MultiBuffer& pending,
        uint8_t* data, size_t len, size_t* progress = nullptr) {
        return ReadPendingFrom(src, pending, data, len, progress, true, SIZE_MAX);
    }
    // UoT 等按地址/长度头分段窥读时保留缓冲所有权，不复制已收到的帧。
    static net::awaitable<bool> EnsureBufferedFrom(
        transport::MultiBufferReader& src, common::MultiBuffer& pending, size_t required,
        size_t maximum = SIZE_MAX) {
        return ReadPendingFrom(src, pending, nullptr, required, nullptr, false, maximum);
    }

    net::awaitable<bool> DiscardExact(size_t len, size_t* progress = nullptr) {
        size_t local_done = 0;
        size_t& done = progress ? *progress : local_done;
        while (done < len) {
            done += pending_.DropPrefixBytes(len - done);
            if (done == len) break;
            if (!co_await EnsureBufferedFrom(src_, pending_, 1)) co_return false;
        }
        co_return true;
    }
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        if (pending_.byte_size() != 0) return TakePending();
        return src_.ReadMultiBuffer();
    }

private:
    // 精确消费与只缓冲两种读取共用这一处 I/O、追加和取消处理。
    static net::awaitable<bool> ReadPendingFrom(
        transport::MultiBufferReader& src, common::MultiBuffer& pending,
        uint8_t* data, size_t len, size_t* progress, bool consume, size_t maximum) {
        size_t local_done = 0;
        size_t& done = progress ? *progress : local_done;
        while (consume ? !ReadBufferedFrom(pending, data, len, done)
                       : pending.byte_size() < len) {
            pending.ReleaseIfIdle();
            auto incoming = co_await src.ReadMultiBuffer();
            const bool received = incoming.byte_size() != 0;
            if (received) {
                if (pending.byte_size() > maximum || incoming.byte_size() > maximum - pending.byte_size())
                    throw IoSystemError(io_error::message_size, "stream pending buffer exceeded");
                incoming.MoveTo(pending, true);
            }
            if ((co_await net::this_coro::cancellation_state).cancelled() != net::cancellation_type::none)
                throw IoSystemError(io_error::operation_aborted);
            if (!received) co_return false;
        }
        co_return true;
    }
    net::awaitable<common::MultiBuffer> TakePending() { co_return std::move(pending_); }
    transport::MultiBufferReader& src_;
    common::MultiBuffer pending_;
};

}  // namespace proxy
