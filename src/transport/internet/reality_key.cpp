#include "transport/internet/reality_key.hpp"
#include "core/naming.hpp"
#include "common/binary_text_codec.hpp"

#include <openssl/err.h>
#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>

#include <array>

namespace transport::internet {
namespace {

template <std::size_t N>
tl::expected<std::array<uint8_t, N>, RealityKeyError>
DecodeFixedBase64Url(std::string_view value) noexcept {
    constexpr std::size_t kEncodedSize = (N * 8 + 5) / 6;
    static_assert(Base64UrlDecodedSize(kEncodedSize) == N);
    std::array<uint8_t, N> decoded{};
    if (value.size() != kEncodedSize) {
        return tl::unexpected(RealityKeyError::InvalidFormat);
    }
    const auto result = DecodeBase64Url(value, decoded);
    if (!result || result->nonzero_pad_bits) {
        OPENSSL_cleanse(decoded.data(), decoded.size());
        return tl::unexpected(RealityKeyError::InvalidFormat);
    }
    return decoded;
}

}  // namespace

tl::expected<RealityKey, RealityKeyError>
ParseRealityKey(std::string_view value) noexcept {
    return DecodeFixedBase64Url<kRealityKeySize>(value);
}

tl::expected<RealityKey, RealityKeyError>
ParseRealityMldsa65Seed(std::string_view value) noexcept {
    auto seed = ParseRealityKey(value);
    if (!seed) {
        return tl::unexpected(seed.error());
    }
    MLDSA65_private_key key;
    const int valid = MLDSA65_private_key_from_seed(&key, seed->data(), seed->size());
    OPENSSL_cleanse(&key, sizeof(key));
    if (valid != 1) {
        OPENSSL_cleanse(seed->data(), seed->size());
        ERR_clear_error();
        return tl::unexpected(RealityKeyError::InvalidFormat);
    }
    return *seed;
}

tl::expected<RealityMldsa65PublicKey, RealityKeyError>
ParseRealityMldsa65PublicKey(std::string_view value) noexcept {
    auto pub = DecodeFixedBase64Url<kRealityMldsa65PublicKeySize>(value);
    if (!pub) {
        return tl::unexpected(pub.error());
    }
    MLDSA65_public_key key;
    CBS encoded;
    CBS_init(&encoded, pub->data(), pub->size());
    if (MLDSA65_parse_public_key(&key, &encoded) != 1) {
        ERR_clear_error();
        return tl::unexpected(RealityKeyError::InvalidFormat);
    }
    return *pub;
}

std::optional<std::string>
NormalizeRealityFingerprint(std::string_view value) {
    const std::string normalized = naming::LowerAscii(std::string(value));
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

}  // namespace transport::internet
