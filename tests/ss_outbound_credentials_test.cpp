#include "outbound/ss_outbound_credentials.hpp"

#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace {
using acpp::proxy::shadowsocks::outbound::Credentials;
using acpp::ss::SsCipherType;

static_assert(!std::is_default_constructible_v<Credentials>);
constexpr std::string_view kKey16 = "AAECAwQFBgcICQoLDA0ODw==";
constexpr std::string_view kKey32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
constexpr std::string_view kIdentity32 = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";

void Check(bool success, const char* message) {
    if (!success) throw std::runtime_error(message);
}

void CheckAscending(const acpp::ss::KeyBytes& key, size_t length) {
    Check(key.size == length, "wrong decoded key length");
    for (size_t i = 0; i < length; ++i) {
        Check(key.bytes[i] == i, "wrong decoded key bytes");
    }
}

void TestPasswords() {
    struct Case { std::string_view method; SsCipherType cipher; size_t length; };
    constexpr std::array cases{
        Case{"aes-128-gcm", SsCipherType::AES_128_GCM, 16},
        Case{"AES-256-GCM", SsCipherType::AES_256_GCM, 32},
        Case{"chacha20-ietf-poly1305", SsCipherType::CHACHA20_POLY1305, 32},
        Case{"chacha20-poly1305", SsCipherType::CHACHA20_POLY1305, 32},
    };
    // EVP_BytesToKey starts with MD5("secret"). This is independent of Prepare.
    constexpr std::array<uint8_t, 16> expected{
        0x5e,0xbe,0x22,0x94,0xec,0xd0,0xe0,0xf0,0x8e,0xab,0x76,0x90,0xd2,0xa6,0xee,0x69};
    for (const auto& item : cases) {
        const auto credentials = Credentials::Prepare(item.method, "secret");
        Check(credentials.has_value(), "valid password rejected");
        Check(credentials->Cipher().type == item.cipher, "cipher was substituted");
        Check(credentials->MasterKey().size == item.length, "password key length mismatch");
        Check(std::memcmp(credentials->MasterKey().data(), expected.data(), expected.size()) == 0,
              "password derivation changed");
        Check(credentials->PskChain().empty(), "ordinary password acquired an identity chain");
    }
    Check(Credentials::Prepare("aes-256-gcm", "a:b").has_value(),
          "colon in an ordinary password was treated as a PSK chain");
}

void TestPskValues() {
    struct Case { std::string_view method; SsCipherType cipher; std::string_view key; size_t length; };
    constexpr std::array cases{
        Case{"2022-blake3-aes-128-gcm", SsCipherType::AES_128_GCM_2022, kKey16, 16},
        Case{"2022-blake3-aes-256-gcm", SsCipherType::AES_256_GCM_2022, kKey32, 32},
        Case{"2022-blake3-chacha20-poly1305", SsCipherType::CHACHA20_POLY1305_2022, kKey32, 32},
    };
    for (const auto& item : cases) {
        const auto credentials = Credentials::Prepare(item.method, item.key);
        Check(credentials.has_value(), "valid single PSK rejected");
        Check(credentials->Cipher().type == item.cipher, "2022 cipher was substituted");
        CheckAscending(credentials->MasterKey(), item.length);
        Check(credentials->PskChain().size() == 1, "single PSK chain was lost");
        CheckAscending(credentials->PskChain().front(), item.length);
    }
    std::string password = std::string(kIdentity32) + ':' + std::string(kKey32);
    auto credentials = Credentials::Prepare("2022-blake3-aes-256-gcm", password);
    Check(credentials.has_value(), "valid AES identity chain rejected");
    password.assign(password.size(), 'x');
    const auto copy = *credentials;
    credentials.reset();
    Check(copy.PskChain().size() == 2, "identity chain length changed");
    Check(std::memcmp(copy.PskChain().front().data(), "fedcba9876543210fedcba9876543210", 32) == 0,
          "identity PSK was lost, reordered or borrowed from input");
    CheckAscending(copy.PskChain().back(), 32);
    CheckAscending(copy.MasterKey(), 32);
    const auto longer = Credentials::Prepare("2022-blake3-aes-128-gcm",
        std::string(kKey16) + ':' + std::string(kKey16) + ':' + std::string(kKey16));
    Check(longer && longer->PskChain().size() == 3, "multi-identity AES chain was truncated");
}

void TestInvalidCredentials() {
    Check(!Credentials::Prepare("unknown-cipher", "secret"), "unknown cipher silently fell back");
    Check(!Credentials::Prepare("aes-256-gcm", ""), "empty password accepted");
    for (const auto method : {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}) {
        const auto key = std::string(method == std::string_view("2022-blake3-aes-128-gcm") ? kKey16 : kKey32);
        for (const auto& password : {
                std::string{}, std::string("invalid"), ':' + key, key + ':', key + "::" + key,
                "invalid:" + key, key + ":invalid", key + ":invalid:" + key}) {
            Check(!Credentials::Prepare(method, password), "invalid or empty chain link was silently dropped");
        }
    }
    Check(!Credentials::Prepare("2022-blake3-aes-128-gcm", kKey32), "32-byte key accepted for AES128");
    Check(!Credentials::Prepare("2022-blake3-aes-256-gcm", kKey16), "16-byte key accepted for AES256");
    Check(!Credentials::Prepare("2022-blake3-chacha20-poly1305",
        std::string(kKey32) + ':' + std::string(kKey32)), "unsupported ChaCha identity chain accepted");
}
}  // namespace

int main() {
    try {
        TestPasswords();
        TestPskValues();
        TestInvalidCredentials();
        std::cout << "SS outbound credential vectors, complete chains, owned values and rejection passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
