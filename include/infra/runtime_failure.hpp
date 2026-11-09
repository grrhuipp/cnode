#pragma once

#include <cstdio>
#include <cstdlib>

// Live Worker state cannot be unwound safely after a runtime infrastructure
// failure. Emit a synchronous allocation-free diagnostic and exit nonzero.
[[noreturn]] inline void FailRuntime(const char* phase, const char* reason) noexcept {
    // The asynchronous logger may itself have failed. Do not allocate a
    // formatted message or inspect live Worker state from this boundary.
    std::fprintf(stderr, "runtime failed phase=%s error=%s status=forced\n", phase, reason);
    std::fflush(stderr);
    std::_Exit(EXIT_FAILURE);
}

