#pragma once

#include "transport/internet/timeout_scheduler.hpp"

#include <chrono>
#include <cstdint>


class AsyncStream;

// Borrowed observation of one owner's absolute phase deadline. The owner must
// outlive the handle; replacing or clearing a deadline invalidates older views.
class PhaseDeadlineHandle {
public:
    PhaseDeadlineHandle() = default;

    PhaseDeadlineHandle(
        const uint8_t* flags,
        uint8_t expired_mask,
        const uint32_t* generation,
        uint32_t captured_generation) noexcept
        : flags_(flags)
        , expired_mask_(expired_mask)
        , generation_(generation)
        , captured_generation_(captured_generation) {}

    [[nodiscard]] bool Expired() const noexcept {
        return flags_ &&
               generation_ &&
               *generation_ == captured_generation_ &&
               ((*flags_ & expired_mask_) != 0);
    }

    explicit operator bool() const noexcept { return flags_ && generation_; }

private:
    const uint8_t* flags_ = nullptr;
    uint8_t expired_mask_ = 0;
    const uint32_t* generation_ = nullptr;
    uint32_t captured_generation_ = 0;
};

// One logical stream's phase deadline, owned inline by that stream. Its embedded
// event follows the execution domain across native handoff. The stream must
// outlive this member; no private timer or background task is owned here.
class StreamPhaseDeadline final : private TimeoutEvent {
public:
    StreamPhaseDeadline(net::io_context& io_context, AsyncStream& owner);
    ~StreamPhaseDeadline() noexcept;
    StreamPhaseDeadline(const StreamPhaseDeadline&) = delete;
    StreamPhaseDeadline& operator=(const StreamPhaseDeadline&) = delete;

    [[nodiscard]] PhaseDeadlineHandle Start(std::chrono::seconds timeout);
    // Clear invalidates borrowed handles; Consume only acknowledges expiry.
    void Clear() noexcept;
    [[nodiscard]] bool Consume() noexcept;

private:
    void OnTimeout() noexcept override;

    AsyncStream& owner_;
    uint32_t generation_ = 0;
    uint8_t expired_ = 0;
};

