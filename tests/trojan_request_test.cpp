#include <gtest/gtest.h>

#include "proxy/trojan/trojan_codec.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <tuple>
#include <vector>

namespace {

TEST(TrojanRequest, PasswordHashesMatchSha224Vectors) {
    struct Case { std::string_view password; std::string_view expected; };
    constexpr std::array cases{
        Case{"", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
        Case{"secret", "95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12"},
        Case{std::string_view("abc\0def", 7), "9b3030a75bfb2320856e6771506932143aa261104c0eaa982f0f6d12"},
    };
    for (const auto& item : cases) {
        const auto hash = ::proxy::trojan::HashPassword(item.password);
        EXPECT_EQ((std::string_view(hash.data(), hash.size())), (item.expected)) << "SHA224 credential vector mismatch";
    }
}

void TestRequest(::proxy::trojan::TrojanCommand command, const ::common::TargetAddress& target,
                 std::span<const uint8_t> encoded_address) {
    constexpr std::string_view expected_hash = "95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12";
    std::string password = "secret";
    const auto hash = ::proxy::trojan::HashPassword(password);
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
    const auto length = ::proxy::trojan::EncodeRequestTo(
        hash, command, target, output.data(), output.size());
    ASSERT_EQ(length, header_size);
    std::copy(payload.begin(), payload.end(), output.begin() + static_cast<std::ptrdiff_t>(length));
    EXPECT_TRUE((std::equal(expected.begin(), expected.end(), output.begin()))) << "Trojan wire bytes changed";

    using ::proxy::trojan::RequestDecodeStatus;
    const auto decoded = ::proxy::trojan::DecodeRequest(
        std::span<const uint8_t>(output.data(), expected.size()));
    EXPECT_TRUE((decoded.status == RequestDecodeStatus::Complete && decoded.consumed == header_size)) << "request parser did not preserve trailing payload";
    EXPECT_TRUE((decoded.request.command == command && decoded.request.target.SameEndpoint(target))) << "request metadata changed";
    EXPECT_EQ((decoded.request.PasswordHashView()), (expected_hash)) << "authentication digest changed";

    // 增量解析的下一边界不得越过头部，避免读端误吞随后的 payload。
    size_t available = 0;
    for (;;) {
        const auto step = ::proxy::trojan::DecodeRequest(std::span<const uint8_t>(output.data(), available));
        if (step.status == RequestDecodeStatus::Complete) {
            EXPECT_EQ((step.consumed), (header_size)) << "incremental Trojan decode consumed a different header";
            break;
        }
        ASSERT_EQ(step.status, RequestDecodeStatus::Incomplete);
        ASSERT_GT(step.required, available);
        ASSERT_LE(step.required, header_size);
        available = step.required;
    }

    output.fill(0x5a);
    const auto short_length = ::proxy::trojan::EncodeRequestTo(
        hash, command, target, output.data(), header_size - 1);
    EXPECT_TRUE((short_length == 0 && std::all_of(output.begin(), output.end(), [](auto b) { return b == 0x5a; }))) << "short output buffer was partially modified";
}
}  // namespace

class TrojanRequestWire : public testing::TestWithParam<
    std::tuple<::proxy::trojan::TrojanCommand, int>> {};

TEST_P(TrojanRequestWire, PreservesHeaderPayloadAndIncrementalBoundaries) {
    const auto [command, family] = GetParam();
    if (family == 0) {
        constexpr std::array<uint8_t, 5> address{1, 127, 0, 0, 1};
        TestRequest(command, common::TargetAddress(net::ip::make_address("127.0.0.1"), 443), address);
    } else if (family == 1) {
        constexpr std::array<uint8_t, 17> address{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        TestRequest(command, common::TargetAddress(net::ip::make_address("::1"), 53), address);
    } else {
        constexpr std::array<uint8_t, 13> address{3, 11, 'e','x','a','m','p','l','e','.','c','o','m'};
        TestRequest(command, common::TargetAddress(std::string_view("example.com"), 443), address);
    }
}

INSTANTIATE_TEST_SUITE_P(AddressFamilies, TrojanRequestWire,
    testing::Combine(testing::Values(::proxy::trojan::TrojanCommand::CONNECT,
                                    ::proxy::trojan::TrojanCommand::UDP_ASSOCIATE),
                     testing::Values(0, 1, 2)));
