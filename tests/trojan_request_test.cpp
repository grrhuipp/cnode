#include "trojan_codec.hpp"
#include "credentials.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

namespace { thread_local bool reject_allocation = false; }
void* operator new(std::size_t size) {
    if (reject_allocation) throw std::bad_alloc();
    if (auto* p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

namespace {
void Check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

void TestHashes() {
    struct Case { std::string_view password; std::string_view expected; };
    constexpr std::array cases{
        Case{"", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
        Case{"secret", "95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12"},
        Case{std::string_view("abc\0def", 7), "9b3030a75bfb2320856e6771506932143aa261104c0eaa982f0f6d12"},
    };
    for (const auto& item : cases) {
        const auto hash = acpp::trojan::HashPassword(item.password);
        Check(std::string_view(hash.data(), hash.size()) == item.expected, "SHA224 credential vector mismatch");
    }
}

void TestRequest(acpp::trojan::TrojanCommand command, const acpp::TargetAddress& target,
                 std::span<const uint8_t> encoded_address) {
    constexpr std::string_view expected_hash = "95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12";
    std::string password = "secret";
    const auto hash = acpp::trojan::HashPassword(password);
    password.assign("different password after preparation");
    constexpr std::array<uint8_t, 3> payload{0, 0xff, 0x31};
    std::vector<uint8_t> expected(expected_hash.begin(), expected_hash.end());
    expected.insert(expected.end(), {0x0d, 0x0a, static_cast<uint8_t>(command)});
    expected.insert(expected.end(), encoded_address.begin(), encoded_address.end());
    expected.insert(expected.end(), {static_cast<uint8_t>(target.port >> 8),
                                   static_cast<uint8_t>(target.port), 0x0d, 0x0a});
    const auto header_size = expected.size();
    expected.insert(expected.end(), payload.begin(), payload.end());
    std::array<uint8_t, 512> output{};
    reject_allocation = true;
    const auto length = acpp::trojan::TrojanCodec::EncodeRequestTo(
        hash, command, target, output.data(), output.size(), payload.data(), payload.size());
    reject_allocation = false;
    Check(length == expected.size(), "request size mismatch");
    Check(std::equal(expected.begin(), expected.end(), output.begin()), "Trojan wire bytes changed");

    size_t consumed = 0;
    const auto parsed = acpp::trojan::TrojanCodec::ParseRequest(output.data(), length, consumed);
    Check(parsed && consumed == header_size, "request parser did not preserve trailing payload");
    Check(parsed->command == command && parsed->target.ToString() == target.ToString(), "request metadata changed");
    Check(std::string_view(parsed->password_hash.data(), parsed->password_hash.size()) == expected_hash,
          "authentication digest changed");

    output.fill(0x5a);
    reject_allocation = true;
    const auto short_length = acpp::trojan::TrojanCodec::EncodeRequestTo(
        hash, command, target, output.data(), expected.size() - 1, payload.data(), payload.size());
    reject_allocation = false;
    Check(short_length == 0 && std::all_of(output.begin(), output.end(), [](auto b) { return b == 0x5a; }),
          "short output buffer was partially modified");
}
}  // namespace

int main() {
    try {
        TestHashes();
        constexpr std::array<uint8_t, 5> ipv4{1, 127, 0, 0, 1};
        constexpr std::array<uint8_t, 17> ipv6{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        constexpr std::array<uint8_t, 13> domain{3, 11, 'e','x','a','m','p','l','e','.','c','o','m'};
        for (const auto command : {acpp::trojan::TrojanCommand::CONNECT, acpp::trojan::TrojanCommand::UDP_ASSOCIATE}) {
            TestRequest(command, acpp::TargetAddress(acpp::net::ip::make_address("127.0.0.1"), 443), ipv4);
            TestRequest(command, acpp::TargetAddress(acpp::net::ip::make_address("::1"), 53), ipv6);
            TestRequest(command, acpp::TargetAddress(std::string_view("example.com"), 443), domain);
        }
        std::cout << "Trojan SHA224 vectors and TCP/UDP IPv4/IPv6/domain wire bytes passed without C++ encoding allocations\n";
    } catch (const std::exception& error) {
        reject_allocation = false;
        std::cerr << "Trojan request encoding failed with C++ allocations disabled: " << error.what() << '\n';
        return 1;
    }
}
