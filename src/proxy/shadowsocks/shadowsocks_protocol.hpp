#pragma once

#include "app/proxyman/inbound/prepared_config.hpp"
#include "common/byte_reader.hpp"
#include "common/unsafe.hpp"
#include "../aead.hpp"

#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
namespace ss {

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

// 根据方法名获取密码参数（不区分大小写），含 AEAD 与 2022-blake3 方法。
[[nodiscard]] std::optional<SsCipherInfo> ParseCipherMethod(std::string_view method);
[[nodiscard]] bool Is2022Cipher(SsCipherType type) noexcept;
[[nodiscard]] bool Is2022AesCipher(SsCipherType type) noexcept;
[[nodiscard]] SsCipherType BaseCipherType(SsCipherType type) noexcept;

// ============================================================================
// 密钥派生
// ============================================================================

using KeyBytes = ::proxyman::inbound::PreparedKeyBytes;

// 从密码派生主密钥（EVP_BytesToKey + MD5，Shadowsocks 标准）
[[nodiscard]] KeyBytes DeriveKey(std::string_view password, size_t key_size);
[[nodiscard]] KeyBytes Decode2022Psk(std::string_view password, size_t key_size);
[[nodiscard]] KeyBytes Build2022UserKeyFromUuid(
    std::string_view uuid,
    const SsCipherInfo& info);
[[nodiscard]] KeyBytes BuildMasterKey(std::string_view password, const SsCipherInfo& info);

[[nodiscard]] bool Derive2022Subkey(const uint8_t* key, size_t key_size,
                                    const uint8_t* salt, size_t salt_size,
                                    uint8_t* out_subkey);
[[nodiscard]] bool Derive2022IdentitySubkey(const uint8_t* key, size_t key_size,
                                            const uint8_t* salt, size_t salt_size,
                                            uint8_t* out_key);
[[nodiscard]] bool Hash2022Psk(std::span<const uint8_t> key,
                               std::span<uint8_t, 16> out_hash);

// 从主密钥 + 随机 salt 派生子密钥（HKDF-SHA1，ss-subkey）
[[nodiscard]] bool DeriveSubkey(const uint8_t* key, size_t key_size,
                                const uint8_t* salt, size_t salt_size,
                                uint8_t* out_subkey);

// 每次 Encrypt/Decrypt 后由调用方自增 nonce 计数器。
class SsAeadCipher {
public:
    // Authentication trials bind the first candidate key through ResetKey.
    SsAeadCipher(SsCipherType type, proxy::AeadDirection direction);
    SsAeadCipher(SsCipherType type, const uint8_t* key, size_t key_size,
                 proxy::AeadDirection direction);
    ~SsAeadCipher() = default;

    SsAeadCipher(const SsAeadCipher&) = delete;
    SsAeadCipher& operator=(const SsAeadCipher&) = delete;
    SsAeadCipher(SsAeadCipher&& other) noexcept = default;
    SsAeadCipher& operator=(SsAeadCipher&& other) noexcept = default;

    [[nodiscard]] bool Encrypt(const uint8_t* nonce,
                               const uint8_t* plaintext,
                               size_t plaintext_len,
                               uint8_t* output) noexcept;

    [[nodiscard]] bool Decrypt(const uint8_t* nonce,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len,
                               uint8_t* output) noexcept;

    [[nodiscard]] bool ResetKey(const uint8_t* key, size_t key_size);

    static constexpr size_t kTagSize = 16;

private:
    SsCipherType type_;
    std::variant<proxy::AeadEncryptor, proxy::AeadDecryptor> context_;
};

static constexpr size_t kMaxChunkPayload = 0x3FFF;

// ============================================================================
// SS2022 (AEAD-2022) 共享原语
//
// Unix 时间戳、AES-ECB 头块等握手辅助逻辑，
// 客户端（client.cpp）与服务端（server.cpp）完全一致，集中在协议私有头里避免
// 两份逐字复制。仅服务握手语义，不对外暴露为请求链路对象。
// ============================================================================
static constexpr size_t kSs2022MaxChunkPayload = 0xFFFF;
static constexpr size_t kSs2022RequestFixedHeaderSize = 1 + 8 + 2;

inline uint64_t UnixSecondsNow() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

inline bool TimestampFresh(uint64_t remote, uint64_t now) noexcept {
    constexpr uint64_t kMaxSkew = 30;
    return remote <= now + kMaxSkew && remote + kMaxSkew >= now;
}

template<size_t Size>
    requires (Size == 16 || Size == 32)
inline bool AesBlocksCrypt(std::span<const uint8_t> key,
                           std::span<const uint8_t, Size> input,
                           std::span<uint8_t, Size> output,
                           bool encrypt) {
    if (key.size() != 16 && key.size() != 32) return false;
    // BoringSSL 保证单块可重叠；双块只能原地或不重叠，防止覆盖尚未读取的块。
    if constexpr (Size == 32) {
        const auto source = reinterpret_cast<uintptr_t>(input.data());
        const auto destination = reinterpret_cast<uintptr_t>(output.data());
        if (source != destination &&
            (source < destination ? destination - source : source - destination) < Size)
            return false;
    }

    // 同一同步操作内的同密钥头块只展开一次；密钥表用毕擦除，不进入连接或用户快照。
    // BoringSSL 保留软硬件分派。
    AES_KEY schedule;
    const auto bits = static_cast<unsigned>(key.size() * 8);
    const int status = encrypt
        ? AES_set_encrypt_key(key.data(), bits, &schedule)
        : AES_set_decrypt_key(key.data(), bits, &schedule);
    if (status == 0) {
        for (size_t offset = 0; offset < Size; offset += AES_BLOCK_SIZE) {
            if (encrypt) AES_encrypt(input.data() + offset, output.data() + offset, &schedule);
            else AES_decrypt(input.data() + offset, output.data() + offset, &schedule);
        }
    }
    OPENSSL_cleanse(&schedule, sizeof(schedule));
    return status == 0;
}

}  // namespace ss
