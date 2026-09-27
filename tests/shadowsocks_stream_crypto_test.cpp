#include "stream_crypto.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
thread_local volatile size_t system_allocations = 0;
}
#if defined(CNODE_WRAP_MALLOC)
extern "C" void* __real_malloc(size_t);
extern "C" void* __wrap_malloc(size_t size) {
    system_allocations = system_allocations + 1;
    return __real_malloc(size);
}
#endif

namespace {

using namespace acpp;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

void TestAesBlock() {
    // FIPS 197 single-block AES-128/AES-256 known-answer vectors.
    const std::array<uint8_t, 16> plain{
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const std::array<std::array<uint8_t, 16>, 2> expected{{
        {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a},
        {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89}}};
    std::array<uint8_t, 34> keys{};
    for (size_t i = 0; i < 32; ++i) keys[i + 1] = static_cast<uint8_t>(i);
#if defined(CNODE_WRAP_MALLOC)
    const auto cold = system_allocations;
    auto* ctx = EVP_CIPHER_CTX_new();
    Check(ctx != nullptr && system_allocations > cold, "malloc instrumentation is inactive");
    EVP_CIPHER_CTX_free(ctx);
#endif
    const auto before = system_allocations;
    for (size_t index = 0; index < 2; ++index) {
        const auto key = std::span<const uint8_t>(keys).subspan(1, index ? 32 : 16);
        for (int round = 0; round < 64; ++round) {
            std::array<uint8_t, 18> guarded;
            guarded.fill(0xa5);
            auto output = std::span<uint8_t>(guarded).subspan<1, 16>();
            Check(ss::AesBlockCrypt(key, plain, output, true), "AES block encrypt failed");
            Check(std::equal(output.begin(), output.end(), expected[index].begin()), "AES known answer mismatch");
            Check(ss::AesBlockCrypt(key, output, output, false), "AES in-place decrypt failed");
            Check(std::equal(output.begin(), output.end(), plain.begin()), "AES plaintext mismatch");
            Check(ss::AesBlockCrypt(key, output, output, true), "AES in-place encrypt failed");
            Check(std::equal(output.begin(), output.end(), expected[index].begin()), "AES in-place ciphertext mismatch");
            Check(guarded.front() == 0xa5 && guarded.back() == 0xa5, "AES wrote outside output block");
        }
    }
#if defined(CNODE_WRAP_MALLOC)
    Check(system_allocations == before, "AES block operation allocated heap memory");
#else
    (void)before;
#endif
    for (size_t size : {size_t(0),size_t(1),size_t(15),size_t(17),size_t(24),size_t(31),size_t(33)}) {
        auto output = plain;
        for (bool encrypt : {false, true}) {
            Check(!ss::AesBlockCrypt(std::span<const uint8_t>(keys).first(size), plain, output, encrypt),
                  "AES accepted unsupported key size");
            Check(output == plain, "AES invalid key modified output");
        }
    }
}

std::vector<uint8_t> Flatten(const buf::MultiBuffer& mb) {
    std::vector<uint8_t> out;
    out.reserve(buf::TotalLen(mb));
    for (const buf::Buffer* buffer : mb) {
        Check(buffer != nullptr, "decoded MultiBuffer contains a null slot");
        Check(buffer->start <= buffer->end && buffer->end <= buf::Buffer::kSize,
              "decoded Buffer cursor escaped the 8KB payload");
        const auto bytes = buffer->Bytes();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

void TestLargeRecord(size_t payload_size, ss::SsCipherType cipher_type) {
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    std::array<uint8_t, 12> nonce{};
    for (size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<uint8_t>(i * 11 + 1);
    }

    std::vector<uint8_t> plaintext(payload_size);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>((i * 131 + i / 17) & 0xff);
    }

    ss::SsAeadCipher cipher(
        cipher_type,
        key.data(),
        key.size());
    std::vector<uint8_t> ciphertext(
        payload_size + ss::SsAeadCipher::kTagSize);
    Check(cipher.Encrypt(
              nonce.data(),
              plaintext.data(),
              plaintext.size(),
              ciphertext.data()),
          "large Shadowsocks record encryption failed");

    ss::detail::StreamAeadDecryptor decryptor(cipher);
    Check(decryptor.Init(nonce.data()),
          "large Shadowsocks record decrypt init failed");
    buf::MultiBuffer decoded;
    Check(ss::detail::DecryptStreamPayload(
              decryptor,
              ciphertext.data(),
              payload_size,
              ciphertext.data() + payload_size,
              decoded),
          "large Shadowsocks record decrypt failed");

    const size_t expected_buffers =
        (payload_size + buf::Buffer::kSize - 1) / buf::Buffer::kSize;
    Check(decoded.size() == expected_buffers,
          "large Shadowsocks record was not split at 8KB boundaries");
    Check(buf::TotalLen(decoded) == payload_size,
          "large Shadowsocks record decoded byte count mismatch");
    Check(Flatten(decoded) == plaintext,
          "large Shadowsocks record plaintext mismatch");
}

void TestInvalidTagDoesNotPublishPartialPlaintext() {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    std::vector<uint8_t> plaintext(buf::Buffer::kSize + 257, 0x5a);
    std::vector<uint8_t> ciphertext(
        plaintext.size() + ss::SsAeadCipher::kTagSize);

    ss::SsAeadCipher cipher(
        ss::SsCipherType::AES_256_GCM,
        key.data(),
        key.size());
    Check(cipher.Encrypt(
              nonce.data(),
              plaintext.data(),
              plaintext.size(),
              ciphertext.data()),
          "invalid-tag fixture encryption failed");
    ciphertext.back() ^= 0x80;

    ss::detail::StreamAeadDecryptor decryptor(cipher);
    Check(decryptor.Init(nonce.data()),
          "invalid-tag decrypt init failed");
    buf::MultiBuffer decoded;
    Check(!ss::detail::DecryptStreamPayload(
               decryptor,
               ciphertext.data(),
               plaintext.size(),
               ciphertext.data() + plaintext.size(),
               decoded),
          "invalid Shadowsocks record tag was accepted");
    Check(decoded.empty() && buf::TotalLen(decoded) == 0,
          "unauthenticated plaintext escaped into the output");
}

}  // namespace

int main() {
    TestAesBlock();
    TestLargeRecord(buf::Buffer::kSize, ss::SsCipherType::AES_256_GCM);
    TestLargeRecord(buf::Buffer::kSize + 1, ss::SsCipherType::AES_256_GCM);
    TestLargeRecord(ss::kMaxChunkPayload, ss::SsCipherType::AES_256_GCM);
    for (size_t i = 0; i < 16; ++i) {
        TestLargeRecord(
            ss::kSs2022MaxChunkPayload,
            ss::SsCipherType::AES_256_GCM_2022);
    }
    TestInvalidTagDoesNotPublishPartialPlaintext();
    std::cout << "shadowsocks_stream_crypto_test: ok\n";
    return 0;
}
