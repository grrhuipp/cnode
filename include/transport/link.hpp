#pragma once

#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"

#include <asio/cancellation_signal.hpp>

#include <cstdint>
#include <exception>
#include <new>
#include <span>
#include <utility>

namespace transport {

class AsyncStream;

}  // namespace transport

namespace transport {

struct Cancellation {
    common::ErrorCode reason;
    bool terminal;
};

class CancellationSubscription;

// Worker-local source with stable identity. Pending cancellation applies only
// to registered work. Stop is permanent and is also delivered to later work.
// Registration, notification and removal never allocate or post work.
class CancellationSource {
public:
    CancellationSource() noexcept = default;
    ~CancellationSource() noexcept;
    CancellationSource(const CancellationSource&) = delete;
    CancellationSource& operator=(const CancellationSource&) = delete;

    void CancelPending(common::ErrorCode reason = common::ErrorCode::CANCELLED) noexcept;
    void Stop(common::ErrorCode reason = common::ErrorCode::CANCELLED) noexcept;
    [[nodiscard]] bool Stopped() const noexcept { return terminal_reason_ != common::ErrorCode::OK; }

private:
    friend class CancellationSubscription;
    void Notify(Cancellation cancellation) noexcept;
    CancellationSubscription* head_ = nullptr;
    common::ErrorCode terminal_reason_ = common::ErrorCode::OK;
};

// One-shot listener embedded at a stable address. Derived state must be fully
// initialized before Resubscribe: a stopped source delivers synchronously.
class CancellationSubscription {
public:
    CancellationSubscription() noexcept = default;
    CancellationSubscription(const CancellationSubscription&) = delete;
    CancellationSubscription& operator=(const CancellationSubscription&) = delete;
    CancellationSubscription(CancellationSubscription&&) = delete;
    CancellationSubscription& operator=(CancellationSubscription&&) = delete;

    // A transport composing multiple sources can listen for the next operation
    // from inside its callback. The source's current batch remains detached.
    void Resubscribe(CancellationSource& source) noexcept {
        Unsubscribe();
        if (source.terminal_reason_ != common::ErrorCode::OK) {
            OnCancellation({source.terminal_reason_, true});
            return;
        }
        next_ = source.head_;
        previous_ = &source.head_;
        if (next_) next_->previous_ = &next_;
        source.head_ = this;
    }

    void Unsubscribe() noexcept {
        if (!previous_) return;
        *previous_ = next_;
        if (next_) next_->previous_ = previous_;
        previous_ = nullptr;
        next_ = nullptr;
    }

protected:
    ~CancellationSubscription() noexcept { Unsubscribe(); }
    virtual void OnCancellation(Cancellation cancellation) noexcept = 0;

private:
    friend class CancellationSource;

    CancellationSubscription* next_ = nullptr;
    CancellationSubscription** previous_ = nullptr;
};

inline CancellationSource::~CancellationSource() noexcept {
    while (head_) head_->Unsubscribe();
}

inline void CancellationSource::CancelPending(common::ErrorCode reason) noexcept {
    Notify({terminal_reason_ == common::ErrorCode::OK ? reason : terminal_reason_, terminal_reason_ != common::ErrorCode::OK});
}

inline void CancellationSource::Stop(common::ErrorCode reason) noexcept {
    if (terminal_reason_ != common::ErrorCode::OK) return;
    terminal_reason_ = reason == common::ErrorCode::OK ? common::ErrorCode::CANCELLED : reason;
    Notify({terminal_reason_, true});
}

inline void CancellationSource::Notify(Cancellation cancellation) noexcept {
    // Detach the batch before delivery: callbacks may remove subscriptions,
    // register later work, or notify reentrantly without invalidating iteration.
    auto* batch = std::exchange(head_, nullptr);
    if (batch) batch->previous_ = &batch;
    while (batch) {
        auto* subscription = batch;
        subscription->Unsubscribe();
        subscription->OnCancellation(cancellation);
    }
}

// 把父协程取消槽与可选的连接取消源合流为一个本地信号，供单次异步等待绑定。
// 驻留在等待协程帧内的稳定地址；析构先解除父槽，再由基类退订取消源。已停止的
// 取消源在构造期间同步投递，调用方须在开始等待前检查 Cancelled()。
class CancellationBridge final : private CancellationSubscription {
public:
    explicit CancellationBridge(net::cancellation_slot parent) : parent_(parent) {
        if (parent_.is_connected()) {
            parent_.assign([this](net::cancellation_type type) {
                cancelled_ = true;
                signal_.emit(type);
            });
        }
    }
    CancellationBridge(net::cancellation_slot parent, CancellationSource& source)
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
    void OnCancellation(Cancellation) noexcept override {
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

    virtual net::awaitable<buf::MultiBuffer> ReadMultiBuffer() = 0;
    virtual CancellationSource& Cancellation() noexcept = 0;
    virtual EofAction ReadEofAction() const noexcept { return EofAction::WaitForPeer; }
    // Vision command 2 is a read-direction transition at an idle read boundary.
    // Wrappers retain already-read bytes; unsupported transports fail closed.
    [[nodiscard]] virtual bool EnableRawRead() noexcept { return false; }
};

class MultiBufferWriter {
public:
    virtual ~MultiBufferWriter() noexcept = default;

    virtual net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) = 0;
    virtual net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) = 0;
    virtual net::awaitable<void> AsyncShutdownWrite() { co_return; }
    virtual bool WriteShutdownClosesLink() const noexcept { return false; }

protected:
    // Copies borrowed spans into Buffers, then writes them as one batch.
    net::awaitable<void> WriteBuffersAsMultiBuffer(
        std::span<const net::const_buffer> buffers) {
        buf::MultiBuffer payload;
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto bytes = std::span<const uint8_t>(
                static_cast<const uint8_t*>(buffer.data()),
                buffer.size());
            if (!buf::AppendSpanToMultiBuffer(bytes, payload)) {
                throw std::bad_alloc();
            }
        }
        co_await WriteMultiBuffer(std::move(payload));
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

}  // namespace transport
