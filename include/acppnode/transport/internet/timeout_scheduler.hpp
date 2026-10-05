#pragma once

#include "acppnode/common/asio_types.hpp"

#include <chrono>
#include <cstddef>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace acpp {

class TimeoutScheduler;
class TimeoutSchedulerService;

namespace detail {

// C++20 move-only callback with inline storage. Timeout callbacks are small
// owner-domain commands; keeping them inline avoids a second allocation and
// does not impose copyability on captured lifetime tickets.
class TimeoutCallback final {
public:
    static constexpr std::size_t kInlineBytes = 64;

    TimeoutCallback() noexcept = default;
    TimeoutCallback(std::nullptr_t) noexcept {}
    TimeoutCallback(const TimeoutCallback&) = delete;
    TimeoutCallback& operator=(const TimeoutCallback&) = delete;

    TimeoutCallback(TimeoutCallback&& other) noexcept { MoveFrom(std::move(other)); }
    TimeoutCallback& operator=(TimeoutCallback&& other) noexcept {
        if (this != &other) {
            Reset();
            MoveFrom(std::move(other));
        }
        return *this;
    }

    template<class Function>
        requires (!std::is_same_v<std::decay_t<Function>, TimeoutCallback> &&
                  std::is_invocable_v<std::decay_t<Function>&>)
    TimeoutCallback(Function&& function) {
        using F = std::decay_t<Function>;
        static_assert(sizeof(F) <= kInlineBytes,
            "timeout callback capture exceeds inline storage");
        static_assert(alignof(F) <= alignof(std::max_align_t),
            "timeout callback capture alignment exceeds inline storage");
        static_assert(std::is_nothrow_move_constructible_v<F>,
            "timeout callback must be nothrow move constructible");
        new (storage_) F(std::forward<Function>(function));
        invoke_ = [](void* storage) { (*static_cast<F*>(storage))(); };
        move_ = [](void* destination, void* source) noexcept {
            new (destination) F(std::move(*static_cast<F*>(source)));
            static_cast<F*>(source)->~F();
        };
        destroy_ = [](void* storage) noexcept { static_cast<F*>(storage)->~F(); };
    }

    ~TimeoutCallback() noexcept { Reset(); }

    explicit operator bool() const noexcept { return invoke_ != nullptr; }
    void operator()() {
        if (invoke_) invoke_(storage_);
    }

    void Reset() noexcept {
        if (destroy_) destroy_(storage_);
        invoke_ = nullptr;
        move_ = nullptr;
        destroy_ = nullptr;
    }

private:
    void MoveFrom(TimeoutCallback&& other) noexcept {
        invoke_ = other.invoke_;
        move_ = other.move_;
        destroy_ = other.destroy_;
        if (!move_) return;
        move_(storage_, other.storage_);
        other.invoke_ = nullptr;
        other.move_ = nullptr;
        other.destroy_ = nullptr;
    }

    alignas(std::max_align_t) std::byte storage_[kInlineBytes]{};
    void (*invoke_)(void*) = nullptr;
    void (*move_)(void*, void*) noexcept = nullptr;
    void (*destroy_)(void*) noexcept = nullptr;
};

}  // namespace detail

// The handle and its callback are accessed only on the callback executor.
// The scheduler owns deadlines, and never dereferences callback state.
class TimeoutToken {
public:
    TimeoutToken() noexcept = default;
    ~TimeoutToken() noexcept;
    TimeoutToken(const TimeoutToken&) = delete;
    TimeoutToken& operator=(const TimeoutToken&) = delete;
    TimeoutToken(TimeoutToken&&) noexcept;
    TimeoutToken& operator=(TimeoutToken&&) noexcept;
    [[nodiscard]] bool Valid() const noexcept;
    void Reset() noexcept;
private:
    friend class TimeoutScheduler;
    struct State;
    std::shared_ptr<State> state_;
};

// A context service owns one strand and one timer. The bounded admission ticket
// covers the scheduling command, deadline, cancellation, and completion message.
class TimeoutScheduler {
public:
    using Callback = detail::TimeoutCallback;
    static constexpr std::size_t kCapacity = 65536;
    struct ResourceStats {
        std::size_t active_events = 0;
        std::size_t heap_entries = 0;
        std::size_t heap_capacity = 0;
        std::size_t event_buckets = 0;
        std::size_t ready_events = 0;
        bool wait_pending = false;
    };

    // Runtime installs the centralized service with the shared io_context
    // executor before constructing any data-plane or control-plane owner.
    // Reinstalling the same executor is harmless; rebinding is rejected.
    static void Install(net::any_io_executor shared_executor);
    [[nodiscard]] static TimeoutScheduler& ForExecutor(net::any_io_executor executor);
    // Only after run() threads have joined; io_context also releases its service.
    static void ReleaseForExecutor(net::any_io_executor executor) noexcept;
    [[nodiscard]] TimeoutToken ScheduleAfter(std::chrono::milliseconds delay,
        net::any_io_executor callback_executor, Callback callback);
    void Cancel(TimeoutToken& token) noexcept;
    [[nodiscard]] net::awaitable<ResourceStats> GetResourceStats();

private:
    friend class TimeoutSchedulerService;
    friend class TimeoutToken;
    explicit TimeoutScheduler(net::any_io_executor executor);
    void Release() noexcept;
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

}  // namespace acpp
