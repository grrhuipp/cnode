#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace acpp::ss {

// ============================================================================
// 密码类型
// ============================================================================
enum class SsCipherType : uint8_t {
    AES_128_GCM                  = 0,
    AES_256_GCM                  = 1,
    CHACHA20_POLY1305            = 2,
    AES_128_GCM_2022             = 3,
    AES_256_GCM_2022             = 4,
    CHACHA20_POLY1305_2022       = 5,
};

struct SsCipherInfo {
    SsCipherType type;
    size_t key_size;   // bytes（主密钥长度 == 子密钥长度 == salt 长度）
    size_t salt_size;  // bytes
    static constexpr size_t tag_size = 16;
};

// 根据方法名获取密码参数（不区分大小写）
// 支持: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
[[nodiscard]] std::optional<SsCipherInfo> ParseCipherMethod(std::string_view method);
[[nodiscard]] bool Is2022Cipher(SsCipherType type) noexcept;
[[nodiscard]] bool Is2022Cipher(const SsCipherInfo& info) noexcept;
[[nodiscard]] bool Is2022AesCipher(SsCipherType type) noexcept;
[[nodiscard]] SsCipherType BaseCipherType(SsCipherType type) noexcept;

// ============================================================================
// 密钥派生
// ============================================================================

struct KeyBytes {
    static constexpr size_t kMaxSize = 32;

    std::array<uint8_t, kMaxSize> bytes{};
    size_t size = 0;

    [[nodiscard]] const uint8_t* data() const noexcept { return bytes.data(); }
    [[nodiscard]] uint8_t* data() noexcept { return bytes.data(); }
    [[nodiscard]] bool empty() const noexcept { return size == 0; }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept {
        return {bytes.data(), size};
    }

    bool assign(std::span<const uint8_t> src) noexcept {
        if (src.size() > bytes.size()) {
            size = 0;
            return false;
        }
        std::copy(src.begin(), src.end(), bytes.begin());
        size = src.size();
        return true;
    }
};

// 从密码派生主密钥（EVP_BytesToKey + MD5，Shadowsocks 标准）
[[nodiscard]] KeyBytes DeriveKey(const std::string& password, size_t key_size);
[[nodiscard]] KeyBytes Decode2022Psk(std::string_view password, size_t key_size);
[[nodiscard]] KeyBytes BuildMasterKey(std::string_view password, const SsCipherInfo& info);

[[nodiscard]] bool Derive2022Subkey(const uint8_t* key, size_t key_size,
                                    const uint8_t* salt, size_t salt_size,
                                    uint8_t* out_subkey);
[[nodiscard]] bool Derive2022IdentitySubkey(const uint8_t* key, size_t key_size,
                                            const uint8_t* salt, size_t salt_size,
                                            uint8_t* out_key);
[[nodiscard]] bool Hash2022Psk(std::span<const uint8_t> key,
                               std::span<uint8_t, 16> out_hash);

}  // namespace acpp::ss
