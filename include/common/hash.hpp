#pragma once

#include <cstdint>
#include <span>
#include <string_view>

// 非加密散列原语：FNV-1a（32/64 位）与 SplitMix64 终混函数。
// 仅用于进程内分桶与协议校验和，不可用于任何安全目的。

inline constexpr uint64_t kFnv1aOffset64 = 0xcbf29ce484222325ULL;
inline constexpr uint64_t kFnv1aPrime64 = 0x100000001b3ULL;
inline constexpr uint32_t kFnv1aOffset32 = 0x811c9dc5U;
inline constexpr uint32_t kFnv1aPrime32 = 0x01000193U;

// 向 64 位 FNV-1a 状态追加单个字节。
[[nodiscard]] inline constexpr uint64_t Fnv1a64Step(uint64_t hash, uint8_t byte) noexcept {
    return (hash ^ byte) * kFnv1aPrime64;
}

// 以 hash 为初始状态继续累积；默认从标准偏移基开始。
[[nodiscard]] inline constexpr uint64_t Fnv1a64(
    std::span<const uint8_t> bytes, uint64_t hash = kFnv1aOffset64) noexcept {
    for (const uint8_t byte : bytes) hash = Fnv1a64Step(hash, byte);
    return hash;
}

[[nodiscard]] inline constexpr uint64_t Fnv1a64(
    std::string_view bytes, uint64_t hash = kFnv1aOffset64) noexcept {
    for (const char byte : bytes) hash = Fnv1a64Step(hash, static_cast<uint8_t>(byte));
    return hash;
}

[[nodiscard]] inline constexpr uint32_t Fnv1a32(
    std::span<const uint8_t> bytes, uint32_t hash = kFnv1aOffset32) noexcept {
    for (const uint8_t byte : bytes) hash = (hash ^ byte) * kFnv1aPrime32;
    return hash;
}

// SplitMix64 终混：把弱散列值扩散到全部 64 位。
[[nodiscard]] inline constexpr uint64_t Mix64(uint64_t value) noexcept {
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}
