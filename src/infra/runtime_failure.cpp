#include "acppnode/infra/runtime_failure.hpp"

#include <cstdio>
#include <cstdlib>

namespace acpp {

[[noreturn]] void FailRuntime(const char* phase, const char* reason) noexcept {
    // The asynchronous logger may itself have failed. Do not allocate a
    // formatted message or inspect live Worker state from this boundary.
    std::fprintf(stderr, "runtime failed phase=%s error=%s status=forced\n", phase, reason);
    std::fflush(stderr);
    std::_Exit(EXIT_FAILURE);
}

} // namespace acpp
