#include <gtest/gtest.h>

#include "transport/stream_settings.hpp"
#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>

#include <optional>
#include <span>
#include <string>
#include <utility>

namespace {

using ::transport::RealityKey;
using ::transport::RealityMldsa65PublicKey;

// The product parses configured keys; key derivation is only fixture setup.
std::optional<RealityMldsa65PublicKey> DeriveRealityMldsa65PublicKeyFromSeed(
    const RealityKey& seed) {
    MLDSA65_private_key private_key;
    MLDSA65_public_key public_key;
    const bool valid =
        MLDSA65_private_key_from_seed(&private_key, seed.data(), seed.size()) == 1 &&
        MLDSA65_public_from_private(&public_key, &private_key) == 1;
    OPENSSL_cleanse(&private_key, sizeof(private_key));
    if (!valid) return std::nullopt;
    RealityMldsa65PublicKey pub{};
    static_assert(pub.size() == MLDSA65_PUBLIC_KEY_BYTES);
    bssl::ScopedCBB encoded;
    CBB_init_fixed(encoded.get(), pub.data(), pub.size());
    if (MLDSA65_marshal_public_key(encoded.get(), &public_key) != 1 ||
        CBB_len(encoded.get()) != pub.size()) {
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

}  // namespace

TEST(RealityKey, DecodesCanonicalBase64UrlKey) {
    const auto parsed = ::transport::ParseRealityKey(std::string(43, 'A'));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, RealityKey{});
}

namespace {
class RealityInvalidKey : public testing::TestWithParam<std::string> {};
TEST_P(RealityInvalidKey, RejectsNoncanonicalOrMalformedKey) {
    EXPECT_FALSE(::transport::ParseRealityKey(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(Base64Url, RealityInvalidKey, testing::Values(
    std::string(42, 'A'), std::string(44, 'A'), std::string(42, 'A') + "=",
    std::string(42, 'A') + "B", std::string(42, 'A') + "!"));
}

TEST(RealityKey, ParsesMldsaSeedAndDerivedPublicKey) {
    const auto seed = ::transport::ParseRealityMldsa65Seed(std::string(43, 'A'));
    ASSERT_TRUE(seed.has_value());
    const auto public_key = DeriveRealityMldsa65PublicKeyFromSeed(*seed);
    ASSERT_TRUE(public_key.has_value());
    const auto parsed = ::transport::ParseRealityMldsa65PublicKey(EncodeRealityBase64Url(*public_key));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, *public_key);
}

TEST(RealityKey, RejectsMalformedMldsaPublicKey) {
    EXPECT_FALSE(::transport::ParseRealityMldsa65PublicKey("invalid-pub"));
}

namespace {
class RealityFingerprint : public testing::TestWithParam<std::pair<const char*, const char*>> {};
TEST_P(RealityFingerprint, NormalizesSupportedBrowserName) {
    EXPECT_EQ(::transport::NormalizeRealityFingerprint(GetParam().first), GetParam().second);
}
INSTANTIATE_TEST_SUITE_P(Browsers, RealityFingerprint, testing::Values(
    std::pair{"Chrome", "chrome"}, std::pair{"Firefox", "firefox"}, std::pair{"iOS", "ios"}));
}

TEST(RealityKey, RejectsUnsupportedFingerprint) {
    EXPECT_FALSE(::transport::NormalizeRealityFingerprint("unknown-browser"));
}
