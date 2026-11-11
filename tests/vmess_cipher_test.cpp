#include <gtest/gtest.h>

#include "proxy/vmess/vmess_crypto.hpp"

#include <algorithm>
#include <array>
#include <new>
#include <openssl/evp.h>

#ifdef CNODE_TEST_CRYPTO_FAULT
namespace {
bool fail_digest_allocation = false;
bool fail_mask_output = false;
int cipher_allocation_countdown = 0;
}
extern "C" EVP_MD_CTX* __real_EVP_MD_CTX_new();
extern "C" EVP_AEAD_CTX* __real_EVP_AEAD_CTX_new(const EVP_AEAD*, const uint8_t*, size_t, size_t);
extern "C" int __real_EVP_DigestSqueeze(EVP_MD_CTX*, uint8_t*, size_t);
extern "C" EVP_MD_CTX* __wrap_EVP_MD_CTX_new() {
    return fail_digest_allocation ? nullptr : __real_EVP_MD_CTX_new();
}
extern "C" EVP_AEAD_CTX* __wrap_EVP_AEAD_CTX_new(
    const EVP_AEAD* cipher, const uint8_t* key, size_t key_size, size_t tag_size) {
    if (cipher_allocation_countdown > 0 && --cipher_allocation_countdown == 0) return nullptr;
    return __real_EVP_AEAD_CTX_new(cipher, key, key_size, tag_size);
}
extern "C" int __wrap_EVP_DigestSqueeze(EVP_MD_CTX* ctx, uint8_t* out, size_t size) {
    return fail_mask_output ? 0 : __real_EVP_DigestSqueeze(ctx, out, size);
}
#endif

namespace {
using namespace ::proxy::vmess;
constexpr std::array<uint8_t, 16> key{}, iv{};

#ifdef CNODE_TEST_CRYPTO_FAULT
class CryptoFaultReset {
public:
    ~CryptoFaultReset() {
        fail_digest_allocation = false;
        fail_mask_output = false;
        cipher_allocation_countdown = 0;
    }
};

TEST(VmessCipher, DigestAllocationFailureRejectsMaskAndCipherConstruction) {
    bool mask_failed = false, key_failed = false;
    {
        CryptoFaultReset reset;
        fail_digest_allocation = true;
        try { ShakeMask mask(iv.data()); }
        catch (const std::bad_alloc&) { mask_failed = true; }
        try { VMessCipher cipher(Security::CHACHA20_POLY1305, key.data(), iv.data()); }
        catch (const std::bad_alloc&) { key_failed = true; }
    }
    EXPECT_TRUE(mask_failed);
    EXPECT_TRUE(key_failed);
}

TEST(VmessCipher, AeadAllocationFailureRejectsConstruction) {
    bool failed = false;
    {
        CryptoFaultReset reset;
        cipher_allocation_countdown = 1;
        try { VMessCipher cipher(Security::AES_128_GCM, key.data(), iv.data()); }
        catch (const std::bad_alloc&) { failed = true; }
    }
    EXPECT_TRUE(failed);
}

TEST(VmessCipher, FailedShakeOutputDoesNotSynthesizeMask) {
    ShakeMask mask(iv.data());
    bool failed = false;
    {
        CryptoFaultReset reset;
        fail_mask_output = true;
        try { (void)mask.NextMask(); }
        catch (const std::runtime_error&) { failed = true; }
    }
    EXPECT_TRUE(failed);
}
#endif

TEST(VmessCipher, EmptyAesGcmMatchesZeroKeyZeroNonceVector) {
    const std::array<uint8_t, 16> expected{
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
    VMessCipher encoder(Security::AES_128_GCM, key.data(), iv.data());
    std::array<uint8_t, 16> wire{};
    ASSERT_EQ(encoder.Encrypt(nullptr, 0, wire.data()), 16);
    EXPECT_EQ(wire, expected);
}

class VmessCipherRecords : public testing::TestWithParam<Security> {};
TEST_P(VmessCipherRecords, EmptyAndDataRecordsAdvanceMatchingNonces) {
    VMessCipher encoder(GetParam(), key.data(), iv.data());
    VMessCipher decoder(GetParam(), key.data(), iv.data());
    size_t frame = 0;
    for (const size_t size : {size_t{0}, size_t{1}, size_t{127}, size_t{0}, size_t{31}}) {
        SCOPED_TRACE(frame);
        std::array<uint8_t, 128> input{}, output{};
        std::array<uint8_t, 144> wire{};
        for (size_t i = 0; i < size; ++i) input[i] = static_cast<uint8_t>(i + frame);
        const auto encoded = encoder.Encrypt(size ? input.data() : nullptr, size, wire.data());
        ASSERT_EQ(encoded, static_cast<ssize_t>(size + encoder.Overhead()));
        ASSERT_EQ(decoder.Decrypt(wire.data(), static_cast<size_t>(encoded), output.data()),
                  static_cast<ssize_t>(size));
        EXPECT_TRUE(std::equal(input.begin(), input.begin() + size, output.begin()));
        ++frame;
    }
}
INSTANTIATE_TEST_SUITE_P(SecurityModes, VmessCipherRecords,
    testing::Values(Security::AES_128_GCM, Security::CHACHA20_POLY1305, Security::NONE, Security::ZERO));

class VmessAuthenticatedCipher : public testing::TestWithParam<Security> {};
TEST_P(VmessAuthenticatedCipher, RejectsTamperedEmptyRecordTag) {
    VMessCipher encoder(GetParam(), key.data(), iv.data());
    VMessCipher decoder(GetParam(), key.data(), iv.data());
    std::array<uint8_t, 16> tag{};
    uint8_t unused = 0;
    ASSERT_EQ(encoder.Encrypt(nullptr, 0, tag.data()), 16);
    tag.back() ^= 1;
    EXPECT_LT(decoder.Decrypt(tag.data(), tag.size(), &unused), 0);
}
INSTANTIATE_TEST_SUITE_P(AeadModes, VmessAuthenticatedCipher,
    testing::Values(Security::AES_128_GCM, Security::CHACHA20_POLY1305));
}  // namespace
