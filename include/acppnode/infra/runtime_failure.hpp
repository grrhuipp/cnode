#pragma once

namespace acpp {

// Live Worker state cannot be unwound safely after a runtime infrastructure
// failure. Emit a synchronous allocation-free diagnostic and exit nonzero.
[[noreturn]] void FailRuntime(const char* phase, const char* reason) noexcept;

} // namespace acpp
