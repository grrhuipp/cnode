#include "acppnode/transport/internet/reality_key.hpp"

#include <openssl/evp.h>
#include <openssl/nid.h>

#include <cstdio>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace {

using acpp::transport::internet::RealityKey;
using acpp::transport::internet::RealityMldsa65PublicKey;

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

// Test fixture helper (also used by reality_integration.py): the product only
// parses configured keys, it never derives or encodes them.
std::optional<RealityMldsa65PublicKey> DeriveRealityMldsa65PublicKeyFromSeed(
    const RealityKey& seed) {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        EVP_PKEY_pqdsa_new_raw_private_key(NID_MLDSA65, seed.data(), seed.size()),
        EVP_PKEY_free);
    if (!pkey) return std::nullopt;
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

}  // namespace

int main(int argc, char** argv) {
    using acpp::transport::internet::NormalizeRealityFingerprint;
    using acpp::transport::internet::ParseRealityKey;
    using acpp::transport::internet::ParseRealityMldsa65PublicKey;
    using acpp::transport::internet::ParseRealityMldsa65Seed;

    if (argc == 3 && std::string(argv[1]) == "--derive-mldsa65") {
        const auto seed = ParseRealityMldsa65Seed(argv[2]);
        if (!seed) return 10;
        const auto pub = DeriveRealityMldsa65PublicKeyFromSeed(*seed);
        if (!pub) return 11;
        std::puts(EncodeRealityBase64Url(*pub).c_str());
        return 0;
    }
    const std::string zero_key(43, 'A');
    const auto parsed = ParseRealityKey(zero_key);
    if (!Require(parsed && *parsed == RealityKey{},
                 "canonical 32-byte Base64URL key must decode")) return 1;

    std::string noncanonical = zero_key;
    noncanonical.back() = 'B';
    for (const std::string& invalid : {
             std::string(42, 'A'), std::string(44, 'A'),
             zero_key.substr(0, 42) + "=", noncanonical,
             zero_key.substr(0, 42) + "!"}) {
        if (!Require(!ParseRealityKey(invalid),
                     "invalid REALITY key must be rejected")) return 2;
    }

    const auto mldsa_seed = ParseRealityMldsa65Seed(zero_key);
    if (!Require(mldsa_seed.has_value(),
                 "valid 32-byte ML-DSA-65 seed must parse")) return 3;
    const auto mldsa_pub = DeriveRealityMldsa65PublicKeyFromSeed(*mldsa_seed);
    if (!Require(mldsa_pub.has_value(),
                 "ML-DSA-65 public key derivation from seed failed")) return 4;
    const std::string encoded_pub = EncodeRealityBase64Url(*mldsa_pub);
    const auto parsed_pub = ParseRealityMldsa65PublicKey(encoded_pub);
    if (!Require(parsed_pub && *parsed_pub == *mldsa_pub,
                 "ML-DSA-65 public key round-trip failed")) return 5;
    if (!Require(!ParseRealityMldsa65PublicKey("invalid-pub"),
                 "invalid ML-DSA-65 public key must be rejected")) return 6;

    if (!Require(NormalizeRealityFingerprint("Chrome") == "chrome" &&
                 NormalizeRealityFingerprint("Firefox") == "firefox" &&
                 NormalizeRealityFingerprint("iOS") == "ios" &&
                 !NormalizeRealityFingerprint("unknown-browser"),
                 "REALITY fingerprint normalization failed")) return 7;
    return 0;
}
