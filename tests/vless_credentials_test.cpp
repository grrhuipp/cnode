#include <gtest/gtest.h>
#include "proxy/vless/vless_codec.hpp"
#include "proxy/vless/vless_encryption_config.hpp"
#include <string>
#include <string_view>

namespace {
struct IdentityCase { std::string_view id; std::string_view expected; };
class VlessIdentity : public testing::TestWithParam<IdentityCase> {};
TEST_P(VlessIdentity, MapsUuidOrCustomIdToProtocolIdentity) {
    const auto& item = GetParam();
    const auto bytes = ::proxy::ParseUuidBytes(item.id);
    ASSERT_TRUE(bytes);
    constexpr std::string_view hex = "0123456789abcdef";
    std::string actual;
    for (const auto byte : *bytes) {
        actual += hex[byte >> 4];
        actual += hex[byte & 0x0f];
    }
    EXPECT_EQ(actual, item.expected);
}
INSTANTIATE_TEST_SUITE_P(Vectors, VlessIdentity, testing::Values(
    IdentityCase{"b831381d-6324-4d53-ad4f-8cda48b30811", "b831381d63244d53ad4f8cda48b30811"},
    IdentityCase{"B831381D63244D53AD4F8CDA48B30811", "b831381d63244d53ad4f8cda48b30811"},
    IdentityCase{"not-a-uuid", "9b70e619d7b355b1b743756ebd573b4e"},
    IdentityCase{"a", "35b65f33a6795e76af3c273ea349ede4"},
    IdentityCase{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "d20a3bd49d5852e08caa820ca42d1ad0"},
    IdentityCase{std::string_view("abc\0def", 7), "dc7cb0d5f28d517b9fda4afd2126242f"}));

class InvalidVlessIdentity : public testing::TestWithParam<const char*> {};
TEST_P(InvalidVlessIdentity, RejectsInvalidLengthOrMalformedUuid) {
    EXPECT_FALSE(::proxy::ParseUuidBytes(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(Inputs, InvalidVlessIdentity, testing::Values(
    "", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "b831381d-6324-4d53-ad4f-8cda48b3081Z"));

class VlessEncryptionAbsent : public testing::TestWithParam<const char*> {};
TEST_P(VlessEncryptionAbsent, NoneIsSuccessfulAbsence) {
    auto client = proxy::ParseVlessClientEncryption(GetParam());
    auto server = proxy::ParseVlessServerDecryption(GetParam());
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    EXPECT_FALSE(client->has_value());
    EXPECT_FALSE(server->has_value());
}
INSTANTIATE_TEST_SUITE_P(Spellings, VlessEncryptionAbsent, testing::Values("", "none", "NONE"));
}  // namespace

TEST(VlessCredentials, NormalizesFlowCase) {
    EXPECT_EQ(::proxy::NormalizeFlow("XTLS-rprx-VISION"), "xtls-rprx-vision");
}

TEST(VlessCredentials, RejectsUnknownEncryption) {
    EXPECT_FALSE(proxy::ParseVlessClientEncryption("invalid"));
    EXPECT_FALSE(proxy::ParseVlessServerDecryption("invalid"));
}
