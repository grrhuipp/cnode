#pragma once

#include <cstdint>

namespace acpp {

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

}  // namespace acpp
