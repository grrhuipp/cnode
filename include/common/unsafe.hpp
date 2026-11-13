#pragma once

// Centralized pointer reinterpretation helper. Keep this header narrow so
// unsafe operations remain easy to audit at call sites.

#include <cassert>
#include <cstdint>
#include <cstddef>
#include <type_traits>

namespace common {

template<typename To, typename From>
[[nodiscard]] inline To* ptr_cast(From* ptr) noexcept {
    static_assert(!std::is_same_v<std::remove_cv_t<To>, void>,
                  "Cannot cast to void*");

    assert((ptr == nullptr || reinterpret_cast<std::uintptr_t>(ptr) % alignof(To) == 0) &&
           "Unaligned pointer cast");

    return reinterpret_cast<To*>(ptr);
}

template<typename To, typename From>
[[nodiscard]] inline const To* ptr_cast(const From* ptr) noexcept {
    static_assert(!std::is_same_v<std::remove_cv_t<To>, void>,
                  "Cannot cast to void*");

    assert((ptr == nullptr || reinterpret_cast<std::uintptr_t>(ptr) % alignof(To) == 0) &&
           "Unaligned pointer cast");

    return reinterpret_cast<const To*>(ptr);
}
}  // namespace common

