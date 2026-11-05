#include "acppnode/transport/internet/reality_key.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/common/binary_text_codec.hpp"

#include <openssl/evp.h>
#include <openssl/nid.h>

#include <array>
#include <memory>

namespace acpp::transport::internet {
namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        EVP_PKEY_free(key);
    }
};
using UniquePkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

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
    UniquePkey pkey(EVP_PKEY_pqdsa_new_raw_private_key(
        NID_MLDSA65, seed->data(), seed->size()));
    if (!pkey) {
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
    UniquePkey pkey(EVP_PKEY_pqdsa_new_raw_public_key(
        NID_MLDSA65, pub->data(), pub->size()));
    if (!pkey) {
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

}  // namespace acpp::transport::internet
