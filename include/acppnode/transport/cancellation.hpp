#pragma once

#include "acppnode/common/error.hpp"

#include <utility>

namespace acpp::transport {

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

private:
    friend class CancellationSubscription;
    void Notify(Cancellation cancellation) noexcept;
    CancellationSubscription* head_ = nullptr;
    ErrorCode terminal_reason_ = ErrorCode::OK;
};

// One-shot, scoped subscription. Subscribing to a stopped source invokes the
// callback synchronously; its context must already be fully initialized.
class CancellationSubscription {
public:
    using Callback = void (*)(void*, Cancellation) noexcept;

    CancellationSubscription(CancellationSource& source, Callback callback, void* context) noexcept
        : callback_(callback), context_(context) {
        Resubscribe(source);
    }
    ~CancellationSubscription() noexcept { Unlink(); }
    CancellationSubscription(const CancellationSubscription&) = delete;
    CancellationSubscription& operator=(const CancellationSubscription&) = delete;

    // A transport composing multiple sources can listen for the next operation
    // from inside its callback. The source's current batch remains detached.
    void Resubscribe(CancellationSource& source) noexcept {
        Unlink();
        if (source.terminal_reason_ != ErrorCode::OK) {
            callback_(context_, {source.terminal_reason_, true});
            return;
        }
        next_ = source.head_;
        previous_ = &source.head_;
        if (next_) next_->previous_ = &next_;
        source.head_ = this;
    }

private:
    friend class CancellationSource;
    void Unlink() noexcept {
        if (!previous_) return;
        *previous_ = next_;
        if (next_) next_->previous_ = previous_;
        previous_ = nullptr;
        next_ = nullptr;
    }

    CancellationSubscription* next_ = nullptr;
    CancellationSubscription** previous_ = nullptr;
    Callback callback_;
    void* context_;
};

inline CancellationSource::~CancellationSource() noexcept {
    while (head_) head_->Unlink();
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
        subscription->Unlink();
        const auto callback = subscription->callback_;
        void* const context = subscription->context_;
        callback(context, cancellation);
    }
}

}  // namespace acpp::transport
