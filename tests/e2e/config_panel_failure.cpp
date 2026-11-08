#include "support.hpp"
#include "infra/runtime_failure.hpp"

#include <cstdlib>
#include <new>

namespace { bool reject_allocations = false; }
void* operator new(std::size_t bytes) {
    if (reject_allocations) throw std::bad_alloc();
    if (void* memory = std::malloc(bytes ? bytes : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }

TEST(RuntimeFailure, FatalInfrastructureReportingDoesNotAllocateOrUnwindLiveOwners) {
    ASSERT_EXIT({
        reject_allocations = true;
        ::FailRuntime("udp-receive", "registered socket receive loop stopped");
    }, testing::ExitedWithCode(1),
       "runtime failed phase=udp-receive error=registered socket receive loop stopped status=forced");
}
