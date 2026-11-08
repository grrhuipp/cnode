#include <gtest/gtest.h>

#include "credentials.hpp"

#include <array>
#include <iostream>
#include <string>
#include <string_view>

TEST(VlessCredentials, Contract) {
    struct Case { std::string_view id; std::string_view expected; };
    constexpr std::array cases{
        Case{"b831381d-6324-4d53-ad4f-8cda48b30811", "b831381d63244d53ad4f8cda48b30811"},
        Case{"B831381D63244D53AD4F8CDA48B30811", "b831381d63244d53ad4f8cda48b30811"},
        Case{"not-a-uuid", "9b70e619d7b355b1b743756ebd573b4e"},
        Case{"a", "35b65f33a6795e76af3c273ea349ede4"},
        Case{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "d20a3bd49d5852e08caa820ca42d1ad0"},
        Case{std::string_view("abc\0def", 7), "dc7cb0d5f28d517b9fda4afd2126242f"},
    };
    constexpr std::string_view hex = "0123456789abcdef";
    for (const auto& item : cases) {
        const auto bytes = ::vless::ParseUuidBytes(item.id);
        if (!bytes) { std::cerr << "valid VLESS id rejected\n"; FAIL() << "valid VLESS id rejected"; }
        std::string actual;
        for (const auto byte : *bytes) {
            actual += hex[byte >> 4];
            actual += hex[byte & 0x0f];
        }
        ASSERT_EQ(actual, item.expected) << "VLESS identity vector changed";
    }
    for (const auto invalid : {"", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "b831381d-6324-4d53-ad4f-8cda48b3081Z"}) {
        if (::vless::ParseUuidBytes(invalid)) { std::cerr << "invalid VLESS id accepted\n"; FAIL() << "invalid VLESS id accepted"; }
    }
    if (::vless::NormalizeFlow("XTLS-rprx-VISION") != "xtls-rprx-vision" ||
        !::vless::NormalizeFlow("").empty()) {
        std::cerr << "flow normalization changed\n";
        FAIL() << "flow normalization changed";
    }
    std::cout << "VLESS UUID/custom identity vectors, byte-length limits and flow normalization passed\n";
}
