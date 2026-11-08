#pragma once

// Centralized pointer reinterpretation helper. Keep this header narrow so
// unsafe operations remain easy to audit at call sites.

#include <cassert>
#include <cstdint>
#include <cstddef>
#include <type_traits>

namespace unsafe {

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
}  // namespace unsafe


inline void SecureZeroMemory(void* ptr, std::size_t size) noexcept {
    if (!ptr || size == 0) {
        return;
    }
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (std::size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

[[nodiscard]] inline bool ConstantTimeEqual(
    const void* a, const void* b, std::size_t size) noexcept {
    if (size == 0) {
        return true;
    }
    const auto* pa = static_cast<const unsigned char*>(a);
    const auto* pb = static_cast<const unsigned char*>(b);
    unsigned char diff = 0;
    for (std::size_t i = 0; i < size; ++i) {
        diff |= static_cast<unsigned char>(pa[i] ^ pb[i]);
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : "+r"(diff) : : "memory");
#endif
    return diff == 0;
}

