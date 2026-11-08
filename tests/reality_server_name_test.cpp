#include <gtest/gtest.h>

#include "transport/internet/reality_server_name.hpp"
#include "transport/internet/tls_server_name.hpp"

#include <array>
#include <cstdio>
#include <string>
#include <vector>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

TEST(RealityServerName, Contract) {
    using ::transport::internet::IsRealityServerNameAllowed;
    using ::transport::internet::ParseTlsServerNameExtension;

    constexpr std::array<uint8_t, 16> valid_extension{
        0x00, 0x0e, 0x00, 0x00, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    const auto parsed = ParseTlsServerNameExtension(valid_extension);
    ASSERT_FALSE((!Require(parsed && *parsed == "example.com",
                 "a canonical host_name entry must parse")));

    constexpr std::array<uint8_t, 17> trailing_byte{
        0x00, 0x0f, 0x00, 0x00, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0xff};
    ASSERT_FALSE((!Require(!ParseTlsServerNameExtension(trailing_byte),
                 "bytes after host_name must not be ignored")));

    constexpr std::array<uint8_t, 10> duplicate_host_name{
        0x00, 0x08, 0x00, 0x00, 0x01, 'a',
        0x00, 0x00, 0x01, 'b'};
    ASSERT_FALSE((!Require(!ParseTlsServerNameExtension(duplicate_host_name),
                 "duplicate host_name entries must be rejected")));

    constexpr std::array<uint8_t, 5> empty_host_name{
        0x00, 0x03, 0x00, 0x00, 0x00};
    ASSERT_FALSE((!Require(!ParseTlsServerNameExtension(empty_host_name),
                 "an empty host_name entry must be rejected")));

    constexpr std::array<uint8_t, 10> unknown_then_host{
        0x00, 0x08, 0x01, 0x00, 0x01, 'x',
        0x00, 0x00, 0x01, 'a'};
    const auto parsed_after_unknown =
        ParseTlsServerNameExtension(unknown_then_host);
    ASSERT_FALSE((!Require(parsed_after_unknown && *parsed_after_unknown == "a",
                 "well-formed unknown name types must be skipped")));

    constexpr std::array<uint8_t, 14> duplicate_unknown_type{
        0x00, 0x0c, 0x01, 0x00, 0x01, 'x',
        0x01, 0x00, 0x01, 'y', 0x00, 0x00, 0x01, 'a'};
    ASSERT_FALSE((!Require(!ParseTlsServerNameExtension(duplicate_unknown_type),
                 "duplicate server name types must be rejected")));

    const std::vector<std::string> names{"Example.COM", ""};
    ASSERT_FALSE((!Require(IsRealityServerNameAllowed(names, "example.com"),
                 "DNS server names must compare case-insensitively")));
    ASSERT_FALSE((!Require(IsRealityServerNameAllowed(names, ""),
                 "an empty configured name must allow missing SNI")));
    ASSERT_FALSE((!Require(!IsRealityServerNameAllowed(names, "other.example"),
                 "an unconfigured server name must be rejected")));
    ASSERT_FALSE((!Require(!IsRealityServerNameAllowed(names, "sub.example.com"),
                 "server name matching must remain exact")));
    ASSERT_FALSE((!Require(IsRealityServerNameAllowed(names, "example.com."),
                 "one DNS root dot must retain the same identity")));
    ASSERT_FALSE((!Require(!IsRealityServerNameAllowed(names, "example.com.."),
                 "multiple trailing dots must not normalize to a valid name")));
    ASSERT_FALSE((!Require(!IsRealityServerNameAllowed(names, "."),
                 "a root name must not match missing SNI")));

    const std::vector<std::string> named_only{"example.com"};
    ASSERT_FALSE((!Require(!IsRealityServerNameAllowed(named_only, ""),
                 "missing SNI must require an explicit empty allow-list entry")));
}
