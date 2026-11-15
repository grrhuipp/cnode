#pragma once

#include <blake3.h>
#include <openssl/mem.h>

#include <cstdint>
#include <initializer_list>
#include <span>
#include <string_view>

namespace proxy {

// 两个入口都在返回前擦除 hasher：其内部状态含全部输入（密钥材料）的压缩结果。

inline void Blake3Digest(std::span<const uint8_t> input, std::span<uint8_t> out) noexcept {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (!input.empty()) {
        blake3_hasher_update(&hasher, input.data(), input.size());
    }
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    OPENSSL_cleanse(&hasher, sizeof(hasher));
}

// BLAKE3 derive_key 模式：`parts` 按给定顺序连续吸收，等价于对其拼接结果派生。
inline void Blake3DeriveKey(std::string_view context,
                            std::initializer_list<std::span<const uint8_t>> parts,
                            std::span<uint8_t> out) noexcept {
    blake3_hasher hasher;
    blake3_hasher_init_derive_key_raw(&hasher, context.data(), context.size());
    for (const std::span<const uint8_t> part : parts) {
        if (!part.empty()) {
            blake3_hasher_update(&hasher, part.data(), part.size());
        }
    }
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    OPENSSL_cleanse(&hasher, sizeof(hasher));
}

}  // namespace proxy
