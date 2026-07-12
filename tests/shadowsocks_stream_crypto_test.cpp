#include "stream_crypto.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

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
