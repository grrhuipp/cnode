#pragma once

#include <openssl/base.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <tl/expected.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

// VLESS Encryption 配置：线上字符串到只读配置聚合的唯一解析入口，
// 只在冷路径（入站/出站准备期）调用。
namespace vless {

enum class VlessEncryptionMode : uint8_t {
    Native,
    XorPub,
    Random,
};

enum class VlessEncryptionRole : uint8_t {
    Client,
    Server,
};

enum class VlessEncryptionParseError : uint8_t {
    UnsupportedName,
    TooFewParts,
    InvalidMode,
    InvalidRtt,
    InvalidSeconds,
    InvalidBase64,
    InvalidKeyLength,
    InvalidKeyMaterial,
    EmptyKeys,
    InvalidPadding,
    PaddingTooLarge,
};

struct VlessEncryptionPadding {
    int probability = 0;
    int from = 0;
    int to = 0;
};

struct VlessClientPfsKey {
    std::vector<uint8_t> public_key;
    std::shared_ptr<EVP_PKEY> mlkem_key;
};

struct VlessServerPfsKey {
    std::vector<uint8_t> private_key;
    std::vector<uint8_t> public_key;
    std::shared_ptr<EVP_PKEY> mlkem_key;

    VlessServerPfsKey() = default;
    VlessServerPfsKey(std::vector<uint8_t> priv,
                      std::vector<uint8_t> pub,
                      std::shared_ptr<EVP_PKEY> mlkem) noexcept
        : private_key(std::move(priv))
        , public_key(std::move(pub))
        , mlkem_key(std::move(mlkem)) {}
    VlessServerPfsKey(const VlessServerPfsKey&) = default;
    VlessServerPfsKey& operator=(const VlessServerPfsKey&) = default;
    VlessServerPfsKey(VlessServerPfsKey&&) noexcept = default;
    VlessServerPfsKey& operator=(VlessServerPfsKey&&) noexcept = default;
    ~VlessServerPfsKey() noexcept {
        if (!private_key.empty()) {
            OPENSSL_cleanse(private_key.data(), private_key.size());
        }
    }
};

struct VlessEncryptionConfig {
    VlessEncryptionRole role = VlessEncryptionRole::Client;
    VlessEncryptionMode mode = VlessEncryptionMode::Native;
    bool zero_rtt = false;
    int64_t seconds_from = 0;
    int64_t seconds_to = 0;
    std::vector<VlessClientPfsKey> client_keys;
    std::vector<VlessServerPfsKey> server_keys;
    std::vector<VlessEncryptionPadding> padding_lens;
};

// 空串或 "none"（不区分大小写）表示未启用加密 → nullopt；其余必须是合法配置。
using VlessEncryptionParseResult =
    tl::expected<std::optional<VlessEncryptionConfig>, VlessEncryptionParseError>;

[[nodiscard]] VlessEncryptionParseResult ParseVlessClientEncryption(
    std::string_view encryption);

[[nodiscard]] VlessEncryptionParseResult ParseVlessServerDecryption(
    std::string_view decryption);

[[nodiscard]] std::string_view VlessEncryptionParseErrorMessage(
    VlessEncryptionParseError error) noexcept;

}  // namespace vless
