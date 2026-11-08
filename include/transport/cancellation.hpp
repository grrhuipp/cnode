#pragma once

#include "common/error.hpp"

#include <utility>

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

}  // namespace transport
