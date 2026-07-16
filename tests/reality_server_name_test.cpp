#include "acppnode/transport/internet/reality_server_name.hpp"

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

int main() {
    using acpp::transport::internet::IsRealityServerNameAllowed;
    using acpp::transport::internet::ParseRealityServerNameExtension;

    constexpr std::array<uint8_t, 16> valid_extension{
        0x00, 0x0e, 0x00, 0x00, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    const auto parsed = ParseRealityServerNameExtension(valid_extension);
    if (!Require(parsed && *parsed == "example.com",
                 "a canonical host_name entry must parse")) return 1;

    constexpr std::array<uint8_t, 17> trailing_byte{
        0x00, 0x0f, 0x00, 0x00, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0xff};
    if (!Require(!ParseRealityServerNameExtension(trailing_byte),
                 "bytes after host_name must not be ignored")) return 2;

    constexpr std::array<uint8_t, 10> duplicate_host_name{
        0x00, 0x08, 0x00, 0x00, 0x01, 'a',
        0x00, 0x00, 0x01, 'b'};
    if (!Require(!ParseRealityServerNameExtension(duplicate_host_name),
                 "duplicate host_name entries must be rejected")) return 3;

    constexpr std::array<uint8_t, 5> empty_host_name{
        0x00, 0x03, 0x00, 0x00, 0x00};
    if (!Require(!ParseRealityServerNameExtension(empty_host_name),
                 "an empty host_name entry must be rejected")) return 4;

    constexpr std::array<uint8_t, 10> unknown_then_host{
        0x00, 0x08, 0x01, 0x00, 0x01, 'x',
        0x00, 0x00, 0x01, 'a'};
    const auto parsed_after_unknown =
        ParseRealityServerNameExtension(unknown_then_host);
    if (!Require(parsed_after_unknown && *parsed_after_unknown == "a",
                 "well-formed unknown name types must be skipped")) return 5;

    constexpr std::array<uint8_t, 14> duplicate_unknown_type{
        0x00, 0x0c, 0x01, 0x00, 0x01, 'x',
        0x01, 0x00, 0x01, 'y', 0x00, 0x00, 0x01, 'a'};
    if (!Require(!ParseRealityServerNameExtension(duplicate_unknown_type),
                 "duplicate server name types must be rejected")) return 6;

    const std::vector<std::string> names{"Example.COM", ""};
    if (!Require(IsRealityServerNameAllowed(names, "example.com"),
                 "DNS server names must compare case-insensitively")) return 7;
    if (!Require(IsRealityServerNameAllowed(names, ""),
                 "an empty configured name must allow missing SNI")) return 8;
    if (!Require(!IsRealityServerNameAllowed(names, "other.example"),
                 "an unconfigured server name must be rejected")) return 9;
    if (!Require(!IsRealityServerNameAllowed(names, "sub.example.com"),
                 "server name matching must remain exact")) return 10;

    const std::vector<std::string> named_only{"example.com"};
    if (!Require(!IsRealityServerNameAllowed(named_only, ""),
                 "missing SNI must require an explicit empty allow-list entry")) {
        return 11;
    }
    return 0;
}
