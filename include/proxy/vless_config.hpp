#pragma once

#include <openssl/base.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <tl/expected.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// VLESS Encryption 配置：线上字符串到只读配置聚合的唯一解析入口，
// 只在冷路径（入站/出站准备期）调用。
namespace proxy {

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

struct SharedEvpPkey {
    bssl::UniquePtr<EVP_PKEY> ptr;

    SharedEvpPkey() noexcept = default;
    SharedEvpPkey(std::nullptr_t) noexcept {}
    explicit SharedEvpPkey(bssl::UniquePtr<EVP_PKEY> p) noexcept : ptr(std::move(p)) {}
    SharedEvpPkey(const SharedEvpPkey& other) noexcept
        : ptr(other.ptr ? bssl::UpRef(other.ptr) : nullptr) {}
    SharedEvpPkey& operator=(const SharedEvpPkey& other) noexcept {
        if (this != &other) {
            ptr = other.ptr ? bssl::UpRef(other.ptr) : nullptr;
        }
        return *this;
    }
    SharedEvpPkey(SharedEvpPkey&&) noexcept = default;
    SharedEvpPkey& operator=(SharedEvpPkey&&) noexcept = default;

    [[nodiscard]] EVP_PKEY* get() const noexcept { return ptr.get(); }
    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(ptr); }
    friend bool operator==(const SharedEvpPkey& k, std::nullptr_t) noexcept { return !k.ptr; }
    friend bool operator!=(const SharedEvpPkey& k, std::nullptr_t) noexcept { return static_cast<bool>(k.ptr); }
};

struct VlessClientPfsKey {
    std::vector<uint8_t> public_key;
    SharedEvpPkey mlkem_key;
};

struct VlessServerPfsKey {
    std::vector<uint8_t> private_key;
    std::vector<uint8_t> public_key;
    SharedEvpPkey mlkem_key;

    VlessServerPfsKey() = default;
    VlessServerPfsKey(std::vector<uint8_t> priv,
                      std::vector<uint8_t> pub,
                      SharedEvpPkey mlkem) noexcept
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

// Parses a UUID string, or maps a 1-30 byte VLESS custom id to UUIDv5.
[[nodiscard]] std::optional<std::array<uint8_t, 16>>
ParseUuidBytes(std::string_view uuid) noexcept;

[[nodiscard]] std::string NormalizeFlow(std::string_view flow);

}  // namespace proxy
