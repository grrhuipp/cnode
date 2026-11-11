#include "allocation_hook.hpp"
#include "support.hpp"
#include "common/error.hpp"

#include <new>

namespace {
bool reject_allocations = false;
void RejectWhenRequested(std::size_t) {
    if (reject_allocations) throw std::bad_alloc();
}
}
constinit allocation_hook::Hooks allocation_hook::hooks{.before_new = RejectWhenRequested};

TEST(RuntimeFailure, FatalInfrastructureReportingDoesNotAllocateOrUnwindLiveOwners) {
    ASSERT_EXIT({
        reject_allocations = true;
        ::FailRuntime("udp-receive", "registered socket receive loop stopped");
    }, testing::ExitedWithCode(1),
       "runtime failed phase=udp-receive error=registered socket receive loop stopped status=forced");
}
