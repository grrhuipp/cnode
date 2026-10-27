#include "acppnode/transport/internet/reality_key.hpp"

#include <openssl/evp.h>
#include <openssl/nid.h>

#include <array>
#include <cctype>
#include <memory>

namespace acpp::transport::internet {
namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        EVP_PKEY_free(key);
    }
};
using UniquePkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

int Base64UrlValue(char value) noexcept {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '-' || value == '+') return 62;
    if (value == '_' || value == '/') return 63;
    return -1;
}

template <std::size_t N>
std::expected<std::array<uint8_t, N>, RealityKeyError>
DecodeFixedBase64Url(std::string_view value) noexcept {
    while (!value.empty() && value.back() == '=') {
        value.remove_suffix(1);
    }
    constexpr std::size_t kEncodedSize = (N * 8 + 5) / 6;
    if (value.size() != kEncodedSize) {
        return std::unexpected(RealityKeyError::InvalidFormat);
    }

    std::array<uint8_t, N> decoded{};
    std::size_t output = 0;
    uint32_t accumulator = 0;
    unsigned int bit_count = 0;
    for (const char character : value) {
        if (character == '+' || character == '/') {
            return std::unexpected(RealityKeyError::InvalidFormat);
        }
        const int digit = Base64UrlValue(character);
        if (digit < 0) {
            return std::unexpected(RealityKeyError::InvalidFormat);
        }
        accumulator = (accumulator << 6) | static_cast<uint32_t>(digit);
        bit_count += 6;
        if (bit_count >= 8) {
            bit_count -= 8;
            if (output >= decoded.size()) {
                return std::unexpected(RealityKeyError::InvalidFormat);
            }
            decoded[output++] = static_cast<uint8_t>(accumulator >> bit_count);
            accumulator &= bit_count == 0 ? 0u : (uint32_t{1} << bit_count) - 1;
        }
    }
    if (output != decoded.size() || accumulator != 0) {
        return std::unexpected(RealityKeyError::InvalidFormat);
    }
    return decoded;
}

}  // namespace

std::expected<RealityKey, RealityKeyError>
ParseRealityKey(std::string_view value) noexcept {
    if (!value.empty() && value.back() == '=') {
        return std::unexpected(RealityKeyError::InvalidFormat);
    }
    return DecodeFixedBase64Url<kRealityKeySize>(value);
}

std::expected<RealityKey, RealityKeyError>
ParseRealityMldsa65Seed(std::string_view value) noexcept {
    auto seed = ParseRealityKey(value);
    if (!seed) {
        return std::unexpected(seed.error());
    }
    UniquePkey pkey(EVP_PKEY_pqdsa_new_raw_private_key(
        NID_MLDSA65, seed->data(), seed->size()));
    if (!pkey) {
        return std::unexpected(RealityKeyError::InvalidFormat);
    }
    return *seed;
}

std::expected<RealityMldsa65PublicKey, RealityKeyError>
ParseRealityMldsa65PublicKey(std::string_view value) noexcept {
    if (!value.empty() && value.back() == '=') {
        return std::unexpected(RealityKeyError::InvalidFormat);
    }
    auto pub = DecodeFixedBase64Url<kRealityMldsa65PublicKeySize>(value);
    if (!pub) {
        return std::unexpected(pub.error());
    }
    UniquePkey pkey(EVP_PKEY_pqdsa_new_raw_public_key(
        NID_MLDSA65, pub->data(), pub->size()));
    if (!pkey) {
        return std::unexpected(RealityKeyError::InvalidFormat);
    }
    return *pub;
}

std::optional<RealityMldsa65PublicKey>
DeriveRealityMldsa65PublicKeyFromSeed(const RealityKey& seed) noexcept {
    UniquePkey pkey(EVP_PKEY_pqdsa_new_raw_private_key(
        NID_MLDSA65, seed.data(), seed.size()));
    if (!pkey) {
        return std::nullopt;
    }
    RealityMldsa65PublicKey pub{};
    std::size_t pub_len = pub.size();
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pub_len) != 1 ||
        pub_len != pub.size()) {
        return std::nullopt;
    }
    return pub;
}

std::string EncodeRealityBase64Url(std::span<const uint8_t> bytes) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((bytes.size() * 8 + 5) / 6);
    uint32_t accumulator = 0;
    unsigned int bit_count = 0;
    for (const uint8_t byte : bytes) {
        accumulator = (accumulator << 8) | byte;
        bit_count += 8;
        while (bit_count >= 6) {
            bit_count -= 6;
            out.push_back(kAlphabet[(accumulator >> bit_count) & 0x3f]);
        }
    }
    if (bit_count > 0) {
        out.push_back(kAlphabet[(accumulator << (6 - bit_count)) & 0x3f]);
    }
    return out;
}

std::optional<std::string>
NormalizeRealityFingerprint(std::string_view value) {
    std::string normalized(value);
    for (char& ch : normalized) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    if (normalized.empty() ||
        normalized == "chrome" ||
        normalized == "firefox" ||
        normalized == "safari" ||
        normalized == "ios" ||
        normalized == "android" ||
        normalized == "edge" ||
        normalized == "360" ||
        normalized == "qq" ||
        normalized == "random" ||
        normalized == "randomized" ||
        normalized == "auto") {
        return normalized;
    }
    return std::nullopt;
}

}  // namespace acpp::transport::internet
