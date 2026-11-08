#pragma once

#include <cstddef>
#include <cstdint>

namespace benchmark {
[[nodiscard]] size_t ResidentBytes();
[[nodiscard]] size_t PeakResidentBytes();

// Counts intercepted throwing C++ new calls and mi_malloc_aligned entries.
// Neither category is a total of logical PMR allocations; do not add them.
struct AllocationCounts {
    uint64_t cpp_calls = 0;
    uint64_t cpp_bytes = 0;
    uint64_t aligned_calls = 0;
};

// The measured scope stays on one thread. Counting never replaces the allocator.
class AllocationCountScope final {
public:
    explicit AllocationCountScope(AllocationCounts& counts) noexcept;
    ~AllocationCountScope();
    AllocationCountScope(const AllocationCountScope&) = delete;
    AllocationCountScope& operator=(const AllocationCountScope&) = delete;
private:
    AllocationCounts* counts_;
};
} // namespace benchmark
