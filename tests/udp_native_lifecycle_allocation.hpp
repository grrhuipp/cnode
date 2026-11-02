#pragma once

#include <cstddef>

namespace udp_native_lifecycle_fault {

enum class DispatchStageFault : unsigned char {
    StandardNew,
    AsioAlignedNew,
};

// Test-only, thread-local allocation controls. Arming is non-throwing; the
// actual selected allocator rejects its real next allocation.
void ArmStandardNew(int successful_allocations_before_failure) noexcept;
void ArmAtDispatchStage(
    DispatchStageFault fault, int successful_allocations_before_failure) noexcept;
void OnNativeDispatchStage() noexcept;
void Disarm() noexcept;
[[nodiscard]] std::size_t StandardNewFailures() noexcept;
[[nodiscard]] std::size_t AsioAlignedNewFailures() noexcept;

} // namespace udp_native_lifecycle_fault
