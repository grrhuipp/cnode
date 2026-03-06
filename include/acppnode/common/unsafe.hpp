#pragma once

/**
 * acpp::unsafe - Unsafe 操作集中管理模块（ISSUE-02-02）
 * 
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ ⚠️  警告：本模块包含可能导致未定义行为的操作                              │
 * │                                                                         │
 * │ 设计目的：                                                              │
 * │   1. 将所有 unsafe 操作集中到一个可审计的位置                            │
 * │   2. 业务代码禁止直接使用 reinterpret_cast / memcpy 等                   │
 * │   3. 便于 Code Review 时识别和审查危险代码                               │
 * │   4. 支持 Debug 模式下的额外检查                                        │
 * │                                                                         │
 * │ 使用规范：                                                              │
 * │   - 只有在性能关键路径且确认安全时才使用                                  │
 * │   - 必须在调用处添加注释说明为何安全                                     │
 * │   - PR Review 时必须重点审查 unsafe:: 调用                              │
 * └─────────────────────────────────────────────────────────────────────────┘
 */

#include <cstdint>
#include <cstring>
#include <type_traits>
#include <cassert>
#include <span>
#include <limits>
#include <string>

namespace acpp {
namespace unsafe {

// ============================================================================
// 类型别名
// ============================================================================
using byte = uint8_t;

// ============================================================================
// 指针转换
// ============================================================================

/**
 * 将指针转换为另一类型
 * 
 * 危险：可能违反严格别名规则（Strict Aliasing）
 * 安全使用条件：
 *   - To 是 char/unsigned char/std::byte（总是安全）
 *   - From 和 To 布局兼容
 *   - 指针对齐正确
 * 
 * @tparam To 目标类型
 * @tparam From 源类型
 * @param ptr 源指针
 * @return 转换后的指针
 */
template<typename To, typename From>
[[nodiscard]] inline To* ptr_cast(From* ptr) noexcept {
    static_assert(!std::is_same_v<To, void>, "Cannot cast to void*");
    
#ifdef ACPP_DEBUG
    // Debug 模式：检查对齐
    if (ptr != nullptr) {
        assert(reinterpret_cast<uintptr_t>(ptr) % alignof(To) == 0 &&
               "Unaligned pointer cast!");
    }
#endif
    
    return reinterpret_cast<To*>(ptr);
}

/**
 * 将 const 指针转换为另一类型
 */
template<typename To, typename From>
[[nodiscard]] inline const To* ptr_cast(const From* ptr) noexcept {
    static_assert(!std::is_same_v<To, void>, "Cannot cast to void*");
    
#ifdef ACPP_DEBUG
    if (ptr != nullptr) {
        assert(reinterpret_cast<uintptr_t>(ptr) % alignof(To) == 0 &&
               "Unaligned pointer cast!");
    }
#endif
    
    return reinterpret_cast<const To*>(ptr);
}

template<typename T>
[[nodiscard]] inline uintptr_t addr_key(const T* ptr) noexcept {
    return reinterpret_cast<uintptr_t>(ptr);
}

// ============================================================================
// 字节操作
// ============================================================================

/**
 * 从字节数组读取整数（网络字节序/大端）
 * 
 * 安全条件：
 *   - src 至少有 sizeof(T) 字节可读
 *   - T 是整数类型
 * 
 * @tparam T 整数类型
 * @param src 源字节数组
 * @return 读取的值（已转换为主机字节序）
 */
template<typename T>
[[nodiscard]] inline T read_be(const byte* src) noexcept {
    static_assert(std::is_integral_v<T>, "T must be integral");
    
    if constexpr (sizeof(T) == 1) {
        return static_cast<T>(*src);
    } else if constexpr (sizeof(T) == 2) {
        return static_cast<T>(
            (static_cast<uint16_t>(src[0]) << 8) |
            (static_cast<uint16_t>(src[1]))
        );
    } else if constexpr (sizeof(T) == 4) {
        return static_cast<T>(
            (static_cast<uint32_t>(src[0]) << 24) |
            (static_cast<uint32_t>(src[1]) << 16) |
            (static_cast<uint32_t>(src[2]) << 8) |
            (static_cast<uint32_t>(src[3]))
        );
    } else if constexpr (sizeof(T) == 8) {
        return static_cast<T>(
            (static_cast<uint64_t>(src[0]) << 56) |
            (static_cast<uint64_t>(src[1]) << 48) |
            (static_cast<uint64_t>(src[2]) << 40) |
            (static_cast<uint64_t>(src[3]) << 32) |
            (static_cast<uint64_t>(src[4]) << 24) |
            (static_cast<uint64_t>(src[5]) << 16) |
            (static_cast<uint64_t>(src[6]) << 8) |
            (static_cast<uint64_t>(src[7]))
        );
    }
}

/**
 * 从字节数组读取整数（小端字节序）
 */
template<typename T>
[[nodiscard]] inline T read_le(const byte* src) noexcept {
    static_assert(std::is_integral_v<T>, "T must be integral");
    
    if constexpr (sizeof(T) == 1) {
        return static_cast<T>(*src);
    } else if constexpr (sizeof(T) == 2) {
        return static_cast<T>(
            (static_cast<uint16_t>(src[1]) << 8) |
            (static_cast<uint16_t>(src[0]))
        );
    } else if constexpr (sizeof(T) == 4) {
        return static_cast<T>(
            (static_cast<uint32_t>(src[3]) << 24) |
            (static_cast<uint32_t>(src[2]) << 16) |
            (static_cast<uint32_t>(src[1]) << 8) |
            (static_cast<uint32_t>(src[0]))
        );
    } else if constexpr (sizeof(T) == 8) {
        return static_cast<T>(
            (static_cast<uint64_t>(src[7]) << 56) |
            (static_cast<uint64_t>(src[6]) << 48) |
            (static_cast<uint64_t>(src[5]) << 40) |
            (static_cast<uint64_t>(src[4]) << 32) |
            (static_cast<uint64_t>(src[3]) << 24) |
            (static_cast<uint64_t>(src[2]) << 16) |
            (static_cast<uint64_t>(src[1]) << 8) |
            (static_cast<uint64_t>(src[0]))
        );
    }
}

/**
 * 向字节数组写入整数（网络字节序/大端）
 * 
 * 安全条件：
 *   - dst 至少有 sizeof(T) 字节可写
 *   - T 是整数类型
 */
template<typename T>
inline void write_be(byte* dst, T value) noexcept {
    static_assert(std::is_integral_v<T>, "T must be integral");
    
    if constexpr (sizeof(T) == 1) {
        *dst = static_cast<byte>(value);
    } else if constexpr (sizeof(T) == 2) {
        dst[0] = static_cast<byte>(value >> 8);
        dst[1] = static_cast<byte>(value);
    } else if constexpr (sizeof(T) == 4) {
        dst[0] = static_cast<byte>(value >> 24);
        dst[1] = static_cast<byte>(value >> 16);
        dst[2] = static_cast<byte>(value >> 8);
        dst[3] = static_cast<byte>(value);
    } else if constexpr (sizeof(T) == 8) {
        dst[0] = static_cast<byte>(value >> 56);
        dst[1] = static_cast<byte>(value >> 48);
        dst[2] = static_cast<byte>(value >> 40);
        dst[3] = static_cast<byte>(value >> 32);
        dst[4] = static_cast<byte>(value >> 24);
        dst[5] = static_cast<byte>(value >> 16);
        dst[6] = static_cast<byte>(value >> 8);
        dst[7] = static_cast<byte>(value);
    }
}

/**
 * 向字节数组写入整数（小端字节序）
 */
template<typename T>
inline void write_le(byte* dst, T value) noexcept {
    static_assert(std::is_integral_v<T>, "T must be integral");
    
    if constexpr (sizeof(T) == 1) {
        *dst = static_cast<byte>(value);
    } else if constexpr (sizeof(T) == 2) {
        dst[0] = static_cast<byte>(value);
        dst[1] = static_cast<byte>(value >> 8);
    } else if constexpr (sizeof(T) == 4) {
        dst[0] = static_cast<byte>(value);
        dst[1] = static_cast<byte>(value >> 8);
        dst[2] = static_cast<byte>(value >> 16);
        dst[3] = static_cast<byte>(value >> 24);
    } else if constexpr (sizeof(T) == 8) {
        dst[0] = static_cast<byte>(value);
        dst[1] = static_cast<byte>(value >> 8);
        dst[2] = static_cast<byte>(value >> 16);
        dst[3] = static_cast<byte>(value >> 24);
        dst[4] = static_cast<byte>(value >> 32);
        dst[5] = static_cast<byte>(value >> 40);
        dst[6] = static_cast<byte>(value >> 48);
        dst[7] = static_cast<byte>(value >> 56);
    }
}

// ============================================================================
// 内存操作
// ============================================================================

/**
 * 安全的内存复制（带边界检查）
 * 
 * @param dst 目标缓冲区
 * @param dst_size 目标缓冲区大小
 * @param src 源缓冲区
 * @param count 要复制的字节数
 * @return true 成功，false 缓冲区溢出
 */
[[nodiscard]] inline bool memcpy_safe(void* dst, size_t dst_size, 
                                       const void* src, size_t count) noexcept {
    if (count > dst_size) {
        return false;
    }
    std::memcpy(dst, src, count);
    return true;
}

/**
 * 不安全的内存复制（无边界检查，仅供性能关键路径使用）
 * 
 * 调用前必须确保：
 *   - dst 至少有 count 字节可写
 *   - src 至少有 count 字节可读
 *   - dst 和 src 不重叠（或使用 memmove）
 */
inline void memcpy_unsafe(void* dst, const void* src, size_t count) noexcept {
    std::memcpy(dst, src, count);
}

/**
 * 零拷贝类型转换
 * 
 * 将字节数组直接解释为指定类型（适用于 POD 类型）
 * 
 * 安全条件：
 *   - T 是 POD/trivially copyable 类型
 *   - src 至少有 sizeof(T) 字节
 *   - src 对齐到 alignof(T)
 */
template<typename T>
[[nodiscard]] inline T bit_cast(const byte* src) noexcept {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    
    T result;
    std::memcpy(&result, src, sizeof(T));
    return result;
}

// ============================================================================
// 类型双关（Type Punning）- 需要特别小心使用
// ============================================================================

/**
 * 将一种类型的位模式重新解释为另一种类型
 * 
 * 这是标准的 bit_cast 实现，在 C++20 中可使用 std::bit_cast
 * 
 * 安全条件：
 *   - sizeof(To) == sizeof(From)
 *   - To 和 From 都是 trivially copyable
 */
template<typename To, typename From>
[[nodiscard]] inline To bit_cast_type(const From& src) noexcept {
    static_assert(sizeof(To) == sizeof(From), "Size mismatch");
    static_assert(std::is_trivially_copyable_v<To>, "To must be trivially copyable");
    static_assert(std::is_trivially_copyable_v<From>, "From must be trivially copyable");
    
    To dst;
    std::memcpy(&dst, &src, sizeof(To));
    return dst;
}

// ============================================================================
// 调试辅助
// ============================================================================

#ifdef ACPP_DEBUG
/**
 * 断言不为空
 */
template<typename T>
inline void assert_not_null(T* ptr, const char* name = "pointer") {
    assert(ptr != nullptr && "Null pointer dereference");
}

/**
 * 断言在边界内
 */
inline void assert_in_bounds(size_t index, size_t size, const char* name = "index") {
    assert(index < size && "Index out of bounds");
}

/**
 * 断言对齐
 */
template<typename T>
inline void assert_aligned(const void* ptr) {
    assert(reinterpret_cast<uintptr_t>(ptr) % alignof(T) == 0 && "Unaligned access");
}

#else
// Release 模式下为空操作
template<typename T>
inline void assert_not_null(T*, const char* = nullptr) {}
inline void assert_in_bounds(size_t, size_t, const char* = nullptr) {}
template<typename T>
inline void assert_aligned(const void*) {}
#endif

// ============================================================================
// 安全整数运算（防止溢出）
// ============================================================================

/**
 * 安全加法：检测溢出
 * @return true 如果成功，false 如果溢出
 */
template<typename T>
[[nodiscard]] inline bool safe_add(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "T must be integral");
#if defined(__GNUC__) || defined(__clang__)
    return !__builtin_add_overflow(a, b, &result);
#else
    if constexpr (std::is_unsigned_v<T>) {
        result = a + b;
        return result >= a;  // 无符号溢出检测
    } else {
        // 有符号溢出检测
        if ((b > 0 && a > std::numeric_limits<T>::max() - b) ||
            (b < 0 && a < std::numeric_limits<T>::min() - b)) {
            return false;
        }
        result = a + b;
        return true;
    }
#endif
}

/**
 * 安全乘法：检测溢出
 */
template<typename T>
[[nodiscard]] inline bool safe_mul(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "T must be integral");
#if defined(__GNUC__) || defined(__clang__)
    return !__builtin_mul_overflow(a, b, &result);
#else
    if constexpr (std::is_unsigned_v<T>) {
        if (a == 0 || b == 0) {
            result = 0;
            return true;
        }
        if (a > std::numeric_limits<T>::max() / b) {
            return false;
        }
        result = a * b;
        return true;
    } else {
        // 简化的有符号检测
        if (a == 0 || b == 0) {
            result = 0;
            return true;
        }
        result = a * b;
        return result / a == b;
    }
#endif
}

/**
 * 安全的 size_t 加法（常用于缓冲区计算）
 */
[[nodiscard]] inline bool safe_size_add(size_t a, size_t b, size_t& result) noexcept {
    return safe_add(a, b, result);
}

/**
 * 恒定时间内存比较（防止时序攻击）
 * 
 * 与 CRYPTO_memcmp 类似，始终比较所有字节
 */
[[nodiscard]] inline bool constant_time_compare(
    const void* a, size_t a_len, 
    const void* b, size_t b_len) noexcept {
    
    // 长度不同时也要执行比较以保持恒定时间
    volatile size_t len = std::min(a_len, b_len);
    volatile unsigned char result = (a_len != b_len) ? 1 : 0;
    
    const volatile unsigned char* pa = static_cast<const volatile unsigned char*>(a);
    const volatile unsigned char* pb = static_cast<const volatile unsigned char*>(b);
    
    for (size_t i = 0; i < len; ++i) {
        result |= pa[i] ^ pb[i];
    }
    
    return result == 0;
}

/**
 * 恒定时间字符串比较
 */
[[nodiscard]] inline bool constant_time_string_compare(
    const std::string& a, 
    const std::string& b) noexcept {
    return constant_time_compare(a.data(), a.size(), b.data(), b.size());
}

}  // namespace unsafe
}  // namespace acpp
