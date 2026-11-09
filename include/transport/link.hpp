#pragma once

#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"

#include <cstdint>
#include <exception>
#include <new>
#include <span>
#include <utility>

class AsyncStream;

namespace transport {

struct Cancellation {
    ErrorCode reason;
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

    void CancelPending(ErrorCode reason = ErrorCode::CANCELLED) noexcept;
    void Stop(ErrorCode reason = ErrorCode::CANCELLED) noexcept;
    [[nodiscard]] bool Stopped() const noexcept { return terminal_reason_ != ErrorCode::OK; }

private:
    friend class CancellationSubscription;
    void Notify(Cancellation cancellation) noexcept;
    CancellationSubscription* head_ = nullptr;
    ErrorCode terminal_reason_ = ErrorCode::OK;
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
        if (source.terminal_reason_ != ErrorCode::OK) {
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

inline void CancellationSource::CancelPending(ErrorCode reason) noexcept {
    Notify({terminal_reason_ == ErrorCode::OK ? reason : terminal_reason_, terminal_reason_ != ErrorCode::OK});
}

inline void CancellationSource::Stop(ErrorCode reason) noexcept {
    if (terminal_reason_ != ErrorCode::OK) return;
    terminal_reason_ = reason == ErrorCode::OK ? ErrorCode::CANCELLED : reason;
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

// Logical I/O failures retain their application code across reader/writer
// boundaries. They are not fabricated operating-system socket errors.
class LinkError final : public std::exception {
public:
    explicit LinkError(ErrorCode code) noexcept : code_(code) {}
    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
    const char* what() const noexcept override { return ErrorCodeToString(code_).data(); }

private:
    ErrorCode code_;
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
    virtual net::awaitable<void> AsyncShutdownWrite() { co_return; }
    virtual bool WriteShutdownClosesLink() const noexcept { return false; }
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
