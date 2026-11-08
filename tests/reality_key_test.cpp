#include <gtest/gtest.h>

#include "transport/internet/reality_key.hpp"

#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>

#include <cstdio>
#include <optional>
#include <span>
#include <string>

namespace {

using ::transport::internet::RealityKey;
using ::transport::internet::RealityMldsa65PublicKey;

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

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

TEST(RealityKey, Contract) {
    using ::transport::internet::NormalizeRealityFingerprint;
    using ::transport::internet::ParseRealityKey;
    using ::transport::internet::ParseRealityMldsa65PublicKey;
    using ::transport::internet::ParseRealityMldsa65Seed;

    const std::string zero_key(43, 'A');
    const auto parsed = ParseRealityKey(zero_key);
    ASSERT_FALSE((!Require(parsed && *parsed == RealityKey{},
                 "canonical 32-byte Base64URL key must decode")));

    std::string noncanonical = zero_key;
    noncanonical.back() = 'B';
    for (const std::string& invalid : {
             std::string(42, 'A'), std::string(44, 'A'),
             zero_key.substr(0, 42) + "=", noncanonical,
             zero_key.substr(0, 42) + "!"}) {
        ASSERT_FALSE((!Require(!ParseRealityKey(invalid),
                     "invalid REALITY key must be rejected")));
    }

    const auto mldsa_seed = ParseRealityMldsa65Seed(zero_key);
    ASSERT_FALSE((!Require(mldsa_seed.has_value(),
                 "valid 32-byte ML-DSA-65 seed must parse")));
    const auto mldsa_pub = DeriveRealityMldsa65PublicKeyFromSeed(*mldsa_seed);
    ASSERT_FALSE((!Require(mldsa_pub.has_value(),
                 "ML-DSA-65 public key derivation from seed failed")));
    const std::string encoded_pub = EncodeRealityBase64Url(*mldsa_pub);
    const auto parsed_pub = ParseRealityMldsa65PublicKey(encoded_pub);
    ASSERT_FALSE((!Require(parsed_pub && *parsed_pub == *mldsa_pub,
                 "ML-DSA-65 public key round-trip failed")));
    ASSERT_FALSE((!Require(!ParseRealityMldsa65PublicKey("invalid-pub"),
                 "invalid ML-DSA-65 public key must be rejected")));

    ASSERT_FALSE((!Require(NormalizeRealityFingerprint("Chrome") == "chrome" &&
                 NormalizeRealityFingerprint("Firefox") == "firefox" &&
                 NormalizeRealityFingerprint("iOS") == "ios" &&
                 !NormalizeRealityFingerprint("unknown-browser"),
                 "REALITY fingerprint normalization failed")));
}
