#pragma once

// Centralized pointer reinterpretation helper. Keep this header narrow so
// unsafe operations remain easy to audit at call sites.

#include <cassert>
#include <cstdint>
#include <type_traits>

namespace acpp::unsafe {

template<typename To, typename From>
[[nodiscard]] inline To* ptr_cast(From* ptr) noexcept {
    static_assert(!std::is_same_v<std::remove_cv_t<To>, void>,
                  "Cannot cast to void*");

#ifdef ACPP_DEBUG
    if (ptr != nullptr) {
        assert(reinterpret_cast<std::uintptr_t>(ptr) % alignof(To) == 0 &&
               "Unaligned pointer cast");
    }
#endif

    return reinterpret_cast<To*>(ptr);
}

template<typename To, typename From>
[[nodiscard]] inline const To* ptr_cast(const From* ptr) noexcept {
    static_assert(!std::is_same_v<std::remove_cv_t<To>, void>,
                  "Cannot cast to void*");

#ifdef ACPP_DEBUG
    if (ptr != nullptr) {
        assert(reinterpret_cast<std::uintptr_t>(ptr) % alignof(To) == 0 &&
               "Unaligned pointer cast");
    }
#endif

    return reinterpret_cast<const To*>(ptr);
}

}  // namespace acpp::unsafe
