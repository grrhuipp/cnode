#include <gtest/gtest.h>

#include "proxy/shadowsocks/ss_outbound.hpp"

#include <array>
#include <cstring>
#include <string>
#include <string_view>

namespace {
using proxy::shadowsocks::outbound::Credentials;
using proxy::shadowsocks::SsCipherInfo;
using proxy::shadowsocks::SsCipherType;

constexpr SsCipherInfo kAes128{SsCipherType::AES_128_GCM, 16, 16};
constexpr SsCipherInfo kAes256{SsCipherType::AES_256_GCM, 32, 32};
constexpr SsCipherInfo kChaCha{SsCipherType::CHACHA20_POLY1305, 32, 32};
constexpr SsCipherInfo kAes128Psk{SsCipherType::AES_128_GCM_2022, 16, 16};
constexpr SsCipherInfo kAes256Psk{SsCipherType::AES_256_GCM_2022, 32, 32};
constexpr SsCipherInfo kChaChaPsk{SsCipherType::CHACHA20_POLY1305_2022, 32, 32};
constexpr std::string_view kKey16 = "AAECAwQFBgcICQoLDA0ODw==";
constexpr std::string_view kKey32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
constexpr std::string_view kIdentity32 = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";

TEST(SsOutboundCredentials, PasswordDerivationPreservesOrdinaryColons) {
    // EVP_BytesToKey 的首块为 MD5("secret")，不经被测 Prepare 生成期望值。
    constexpr std::array<uint8_t, 16> expected{
        0x5e,0xbe,0x22,0x94,0xec,0xd0,0xe0,0xf0,0x8e,0xab,0x76,0x90,0xd2,0xa6,0xee,0x69};
    for (const auto cipher : {kAes128, kAes256, kChaCha}) {
        const auto credentials = Credentials::Prepare(cipher, "secret");
        ASSERT_TRUE(credentials);
        EXPECT_EQ(credentials->MasterKey().size, cipher.key_size);
        EXPECT_EQ(std::memcmp(credentials->MasterKey().data(), expected.data(), expected.size()), 0);
        EXPECT_TRUE(credentials->PskChain().empty());
    }
    EXPECT_TRUE(Credentials::Prepare(kAes256, "a:b"));
}

TEST(SsOutboundCredentials, PskBytesAndIdentityOrderArePreserved) {
    for (const auto cipher : {kAes128Psk, kAes256Psk, kChaChaPsk}) {
        const auto credentials = Credentials::Prepare(cipher, cipher.key_size == 16 ? kKey16 : kKey32);
        ASSERT_TRUE(credentials);
        ASSERT_EQ(credentials->PskChain().size(), 1u);
        ASSERT_EQ(credentials->MasterKey().size, cipher.key_size);
        for (size_t i = 0; i < cipher.key_size; ++i) EXPECT_EQ(credentials->MasterKey().bytes[i], i);
    }
    const auto credentials = Credentials::Prepare(kAes256Psk,
        std::string(kIdentity32) + ':' + std::string(kKey32));
    ASSERT_TRUE(credentials);
    ASSERT_EQ(credentials->PskChain().size(), 2u);
    EXPECT_EQ(std::memcmp(credentials->PskChain().front().data(), "fedcba9876543210fedcba9876543210", 32), 0);
    for (size_t i = 0; i < 32; ++i) EXPECT_EQ(credentials->PskChain().back().bytes[i], i);
    const auto longer = Credentials::Prepare(kAes128Psk,
        std::string(kKey16) + ':' + std::string(kKey16) + ':' + std::string(kKey16));
    ASSERT_TRUE(longer);
    EXPECT_EQ(longer->PskChain().size(), 3u);
}

TEST(SsOutboundCredentials, InvalidPskLinksNeverDisappearFromChain) {
    EXPECT_FALSE(Credentials::Prepare(kAes256, ""));
    for (const auto cipher : {kAes128Psk, kAes256Psk}) {
        const auto key = std::string(cipher.key_size == 16 ? kKey16 : kKey32);
        for (const auto& password : {
            std::string{}, std::string("invalid"), ':' + key, key + ':', key + "::" + key,
            "invalid:" + key, key + ":invalid", key + ":invalid:" + key}) {
            EXPECT_FALSE(Credentials::Prepare(cipher, password));
        }
    }
    EXPECT_FALSE(Credentials::Prepare(kAes128Psk, kKey32));
    EXPECT_FALSE(Credentials::Prepare(kAes256Psk, kKey16));
    EXPECT_FALSE(Credentials::Prepare(kChaChaPsk, std::string(kKey32) + ':' + std::string(kKey32)));
    EXPECT_FALSE(Credentials::Prepare(kAes128Psk, "===="));
    EXPECT_FALSE(Credentials::Prepare(kAes128Psk, "AAAAAAAAAAAAAAAAAAAAAAA==="));
}

}  // namespace
