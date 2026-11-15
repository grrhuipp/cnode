#pragma once

#include "common/asio_types.hpp"
#include "common/cancellation.hpp"
#include "common/multi_buffer.hpp"
#include "common/error.hpp"

#include <asio/cancellation_signal.hpp>

#include <cstdint>
#include <exception>
#include <new>
#include <span>
#include <utility>

namespace transport {

class AsyncStream;

// 把父协程取消槽与可选的连接取消源合流为一个本地信号，供单次异步等待绑定。
// 驻留在等待协程帧内的稳定地址；析构先解除父槽，再由基类退订取消源。已停止的
// 取消源在构造期间同步投递，调用方须在开始等待前检查 Cancelled()。
class CancellationBridge final : private common::CancellationSubscription {
public:
    explicit CancellationBridge(net::cancellation_slot parent) : parent_(parent) {
        if (parent_.is_connected()) {
            parent_.assign([this](net::cancellation_type type) {
                cancelled_ = true;
                signal_.emit(type);
            });
        }
    }
    CancellationBridge(net::cancellation_slot parent, common::CancellationSource& source)
        : CancellationBridge(parent) {
        Resubscribe(source);
    }
    ~CancellationBridge() {
        if (parent_.is_connected()) parent_.clear();
    }

    [[nodiscard]] net::cancellation_slot Slot() noexcept { return signal_.slot(); }
    [[nodiscard]] bool Cancelled() const noexcept { return cancelled_; }
    // 只唤醒本地等待，由调用方按自身状态决定重试；不记为取消。
    void Interrupt() noexcept { signal_.emit(net::cancellation_type::terminal); }

private:
    void OnCancellation(common::Cancellation) noexcept override {
        cancelled_ = true;
        signal_.emit(net::cancellation_type::all);
    }

    net::cancellation_slot parent_;
    net::cancellation_signal signal_;
    bool cancelled_ = false;
};

// Logical I/O failures retain their application code across reader/writer
// boundaries. They are not fabricated operating-system socket errors.
class LinkError final : public std::exception {
public:
    explicit LinkError(common::ErrorCode code) noexcept : code_(code) {}
    [[nodiscard]] common::ErrorCode code() const noexcept { return code_; }
    const char* what() const noexcept override { return common::ErrorCodeToString(code_).data(); }

private:
    common::ErrorCode code_;
};

enum class EofAction : uint8_t {
    WaitForPeer,
    ShutdownPeerWrite,
    CloseLink,
};

// A clean write-side end, detected before starting a write. The read side may
// still contain previously received bytes, which relay must finish draining.
class WriteClosed final : public std::exception {
public:
    const char* what() const noexcept override { return "link write side is closed"; }
};

class MultiBufferReader {
public:
    virtual ~MultiBufferReader() noexcept = default;

    virtual net::awaitable<common::MultiBuffer> ReadMultiBuffer() = 0;
    // Synchronous step of ReadMultiBuffer(). True: one unit that
    // ReadMultiBuffer() would have returned without suspending was moved into
    // `out`. False: `out` is untouched; EOF, closure and errors are reported
    // by ReadMultiBuffer() alone. Never waits or performs I/O: it hands out
    // only what the reader's executor already queued, so a run of true
    // results is bounded by that queue.
    [[nodiscard]] virtual bool TryReadMultiBuffer(common::MultiBuffer&) noexcept { return false; }
    virtual common::CancellationSource& Cancellation() noexcept = 0;
    virtual EofAction ReadEofAction() const noexcept { return EofAction::WaitForPeer; }
    // Vision command 2 is a read-direction transition at an idle read boundary.
    // Wrappers retain already-read bytes; unsupported transports fail closed.
    [[nodiscard]] virtual bool EnableRawRead() noexcept { return false; }
};

class MultiBufferWriter {
public:
    virtual ~MultiBufferWriter() noexcept = default;

    virtual net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) = 0;
    virtual net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) = 0;
    virtual net::awaitable<void> AsyncShutdownWrite() { co_return; }
    virtual bool WriteShutdownClosesLink() const noexcept { return false; }

protected:
    // Copies borrowed spans into Buffers, then writes them as one batch.
    net::awaitable<void> WriteBuffersAsMultiBuffer(
        std::span<const net::const_buffer> buffers) {
        common::MultiBuffer payload;
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto bytes = std::span<const uint8_t>(
                static_cast<const uint8_t*>(buffer.data()),
                buffer.size());
            if (!payload.AppendSpan(bytes)) {
                throw std::bad_alloc();
            }
        }
        return WriteMultiBuffer(std::move(payload));
    }
};

struct Link {
    MultiBufferReader* reader = nullptr;
    MultiBufferWriter* writer = nullptr;
    AsyncStream* control = nullptr;

    [[nodiscard]] bool Valid() const noexcept {
        return reader && writer;
    }
};


// 异常 → ErrorCode 的唯一分类入口。LinkError 保留跨读写边界携带的应用错误码，
// 系统 I/O 错误经 MapAsioError 映射（operation_aborted → CANCELLED），分配失败归为
// RESOURCE_EXHAUSTED；其余异常由调用方按所处阶段给出 unknown。
[[nodiscard]] inline common::ErrorCode ClassifyFailure(
    std::exception_ptr failure, common::ErrorCode unknown) noexcept {
    try {
        std::rethrow_exception(failure);
    } catch (const LinkError& error) {
        return error.code();
    } catch (const IoSystemError& error) {
        return common::MapAsioError(error.code());
    } catch (const std::bad_alloc&) {
        return common::ErrorCode::RESOURCE_EXHAUSTED;
    } catch (...) {
        return unknown;
    }
}
}  // namespace transport
