#include "vmess_cipher.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
using namespace acpp::vmess;

void Check(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}
}  // namespace

int main() {
    const std::array<uint8_t, 16> key{}, iv{};
    const std::array<uint8_t, 16> empty_gcm_tag{
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
    size_t frames = 0;
    for (const Security security : {Security::AES_128_GCM,
                                   Security::CHACHA20_POLY1305,
                                   Security::NONE, Security::ZERO}) {
        VMessCipher encoder(security, key.data(), iv.data());
        VMessCipher decoder(security, key.data(), iv.data());
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
            VMessCipher fresh_encoder(security, key.data(), iv.data());
            VMessCipher fresh_decoder(security, key.data(), iv.data());
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
