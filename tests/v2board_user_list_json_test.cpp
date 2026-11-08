#include <stdexcept>
#include <gtest/gtest.h>

#include "user_list_json.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void Check(bool condition, std::string_view message) {
    if (!condition) Fail(message);
}

auto Parse(std::string_view body) {
    const auto parsed = ::json::parse(body);
    return ::api::v2board::ParseUserList(parsed.as_object());
}

void CheckInvalid(std::string_view body) {
    auto result = Parse(body);
    Check(!result, "invalid user list was accepted");
}

TEST(V2BoardUserListJson, ValidUsersAreNormalized) {
    auto result = Parse(
        R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision","speed_limit":8,"device_limit":3,"email":"user@example.com"},{"id":8,"uuid":"11111111-1111-1111-1111-111111111111","speed_limit":null,"device_limit":null},{"id":9,"uuid":"22222222-2222-2222-2222-222222222222","speed_limit":140737488355327,"device_limit":4294967295}]})");
    Check(result.has_value(), "valid users were rejected");
    Check(result->size() == 3, "valid user count mismatch");
    Check((*result)[0].UUID == "b831381d-6324-4d53-ad4f-8cda48b30811",
          "UUID credential was not preserved");
    Check((*result)[1].UUID == "11111111-1111-1111-1111-111111111111",
          "UUID credential changed for a user without optional fields");
    Check((*result)[0].SpeedLimit == 1024ULL * 1024ULL,
          "speed limit was not converted from Mbps to Bps");
    Check((*result)[0].DeviceLimit == 3, "device limit mismatch");
    Check((*result)[0].Flow == "xtls-rprx-vision", "flow mismatch");
    Check((*result)[0].Email == "user@example.com", "email mismatch");
    Check((*result)[1].SpeedLimit == 0, "null speed limit was not unlimited");
    Check((*result)[1].DeviceLimit == 0, "null device limit was not unlimited");
    Check((*result)[1].Email.empty(), "missing email should remain empty");
    Check((*result)[2].SpeedLimit ==
              std::numeric_limits<uint64_t>::max() - 131071,
          "maximum speed limit was not preserved");
    Check((*result)[2].DeviceLimit == std::numeric_limits<uint32_t>::max(),
          "maximum device limit was not preserved");

    auto empty = Parse(R"({"users":[]})");
    Check(empty.has_value() && empty->empty(), "empty user list was rejected");
}

TEST(V2BoardUserListJson, InvalidLimitsAreRejected) {
    CheckInvalid(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","speed_limit":140737488355328}]})");
    CheckInvalid(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","device_limit":4294967296}]})");
    CheckInvalid(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","speed_limit":-1}]})");
    CheckInvalid(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","device_limit":"+1"}]})");
    CheckInvalid(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","speed_limit":"1.5"}]})");
}

TEST(V2BoardUserListJson, Xv2BoardUserTypesAreCompatible) {
    auto result = Parse(
        R"({"users":[{"id":"7","uuid":"B831381D-6324-4D53-AD4F-8CDA48B30811","flow":"XTLS-RPRX-VISION","speed_limit":"8","device_limit":"3"}]})");
    Check(result && result->size() == 1, "xv2board string user integers were rejected");
    Check((*result)[0].UID == 7 && (*result)[0].SpeedLimit == 1024ULL * 1024ULL &&
              (*result)[0].DeviceLimit == 3 &&
              (*result)[0].Flow == "xtls-rprx-vision" &&
              (*result)[0].UUID == "B831381D-6324-4D53-AD4F-8CDA48B30811",
          "user field compatibility mismatch");
}

TEST(V2BoardUserListJson, MalformedUsersAreRejected) {
    CheckInvalid(R"({})");
    CheckInvalid(R"({"users":null})");
    CheckInvalid(R"({"users":[1]})");
    CheckInvalid(R"({"users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]})");
    CheckInvalid(R"({"users":[{"id":7}]})");
    CheckInvalid(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"},{"id":7,"uuid":"11111111-1111-1111-1111-111111111111"}]})");
    CheckInvalid(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","email":"bad\n@example.com"}]})");
    CheckInvalid(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls\r\n"}]})");
}

}  // namespace

