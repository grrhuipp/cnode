#include <stdexcept>
#include <gtest/gtest.h>

#include "vmess_cipher.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string_view>
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
using namespace ::vmess;
using ::proxy::AeadDirection;

void Check(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << message << '\n';
        ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
    }
}
}  // namespace

TEST(VmessCipher, Contract) {
    const std::array<uint8_t, 16> key{}, iv{};
#ifdef CNODE_TEST_CRYPTO_FAULT
    fail_digest_allocation = true;
    bool mask_failed = false, key_failed = false;
    try { ShakeMask mask(iv.data()); }
    catch (const std::bad_alloc&) { mask_failed = true; }
    try { VMessCipher cipher(Security::CHACHA20_POLY1305, key.data(), iv.data(), AeadDirection::Encrypt); }
    catch (const std::bad_alloc&) { key_failed = true; }
    fail_digest_allocation = false;
    Check(mask_failed && key_failed, "crypto allocation failure produced usable protocol state");
    for (const AeadDirection direction : {AeadDirection::Encrypt, AeadDirection::Decrypt}) {
        cipher_allocation_countdown = 1;
        bool failed = false;
        try { VMessCipher cipher(Security::AES_128_GCM, key.data(), iv.data(), direction); }
        catch (const std::bad_alloc&) { failed = true; }
        cipher_allocation_countdown = 0;
        Check(failed, "AEAD context allocation failure did not fail construction");
    }
    ShakeMask mask(iv.data());
    fail_mask_output = true;
    bool squeeze_failed = false;
    try { (void)mask.NextMask(); }
    catch (const std::runtime_error&) { squeeze_failed = true; }
    fail_mask_output = false;
    Check(squeeze_failed, "failed SHAKE output was replaced by synthetic mask bytes");
#endif
    const std::array<uint8_t, 16> empty_gcm_tag{
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
    size_t frames = 0;
    for (const Security security : {Security::AES_128_GCM,
                                   Security::CHACHA20_POLY1305,
                                   Security::NONE, Security::ZERO}) {
        VMessCipher encoder(security, key.data(), iv.data(), AeadDirection::Encrypt);
        VMessCipher decoder(security, key.data(), iv.data(), AeadDirection::Decrypt);
        for (const size_t size : {size_t{0}, size_t{1}, size_t{127}, size_t{0}, size_t{31}}) {
            std::array<uint8_t, 128> input{}, output{};
            std::array<uint8_t, 144> wire{};
            for (size_t i = 0; i < size; ++i) input[i] = static_cast<uint8_t>(i + frames);
            const auto encoded = encoder.Encrypt(size ? input.data() : nullptr, size, wire.data());
            Check(encoded == static_cast<ssize_t>(size + encoder.Overhead()),
                  "empty/data chunk encryption failed");
            if (security == Security::AES_128_GCM && frames == 0) {
                Check(std::equal(empty_gcm_tag.begin(), empty_gcm_tag.end(), wire.begin()),
                      "empty AES-GCM tag differs from the zero-key/zero-nonce vector");
            }
            Check(decoder.Decrypt(wire.data(), static_cast<size_t>(encoded), output.data()) ==
                      static_cast<ssize_t>(size), "empty/data chunk authentication failed");
            Check(std::equal(input.begin(), input.begin() + size, output.begin()),
                  "chunk plaintext changed");
            ++frames;
        }
        if (encoder.Overhead()) {
            VMessCipher fresh_encoder(security, key.data(), iv.data(), AeadDirection::Encrypt);
            VMessCipher fresh_decoder(security, key.data(), iv.data(), AeadDirection::Decrypt);
            std::array<uint8_t, 16> tag{};
            uint8_t unused = 0;
            Check(fresh_encoder.Encrypt(nullptr, 0, tag.data()) == 16,
                  "empty authentication tag was not generated");
            tag.back() ^= 1;
            Check(fresh_decoder.Decrypt(tag.data(), tag.size(), &unused) < 0,
                  "corrupted empty authentication tag was accepted");
        }
    }
    std::cout << "vmess-cipher frames=" << frames << " empty-tag-tamper=2: PASS\n";
}
