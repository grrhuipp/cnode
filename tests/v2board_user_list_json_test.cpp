#include "user_list_json.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) Fail(message);
}

auto Parse(std::string_view body) {
    const auto parsed = acpp::json::parse(body);
    return acpp::api::v2board::ParseUserList(parsed.as_object());
}

void CheckInvalid(std::string_view body, std::string_view cause) {
    auto result = Parse(body);
    Check(!result, "invalid user list was accepted");
    Check(result.error().find(cause) != std::string::npos,
          "invalid user list error lost its cause");
}

void TestValidUsersAreNormalized() {
    auto result = Parse(
        R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision","speed_limit":8,"device_limit":3,"email":"user@example.com"},{"id":8,"uuid":"11111111-1111-1111-1111-111111111111","speed_limit":null,"device_limit":null},{"id":9,"uuid":"22222222-2222-2222-2222-222222222222","speed_limit":140737488355327,"device_limit":4294967295}]})");
    Check(result.has_value(), "valid users were rejected");
    Check(result->size() == 3, "valid user count mismatch");
    Check((*result)[0].SpeedLimit == 1024ULL * 1024ULL,
          "speed limit was not converted from Mbps to Bps");
    Check((*result)[0].DeviceLimit == 3, "device limit mismatch");
    Check((*result)[0].Flow == "xtls-rprx-vision", "flow mismatch");
    Check((*result)[0].Email == "user@example.com", "email mismatch");
    Check((*result)[1].SpeedLimit == 0, "null speed limit was not unlimited");
    Check((*result)[1].DeviceLimit == 0, "null device limit was not unlimited");
    Check((*result)[1].Email == "8", "missing email did not use user id");
    Check((*result)[2].SpeedLimit ==
              std::numeric_limits<uint64_t>::max() - 131071,
          "maximum speed limit was not preserved");
    Check((*result)[2].DeviceLimit == std::numeric_limits<uint32_t>::max(),
          "maximum device limit was not preserved");

    auto empty = Parse(R"({"users":[]})");
    Check(empty.has_value() && empty->empty(), "empty user list was rejected");
}

void TestInvalidLimitsAreRejected() {
    CheckInvalid(
        R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","speed_limit":140737488355328}]})",
        "speed_limit exceeds");
    CheckInvalid(
        R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","device_limit":4294967296}]})",
        "device_limit exceeds");
    CheckInvalid(
        R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","speed_limit":-1}]})",
        "speed_limit must not be negative");
    CheckInvalid(
        R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","device_limit":"1"}]})",
        "device_limit must be an integer or null");
}

void TestMalformedUsersAreRejected() {
    CheckInvalid(R"({})", "users is required");
    CheckInvalid(R"({"users":null})", "users must be an array");
    CheckInvalid(R"({"users":[1]})", "must be an object");
    CheckInvalid(
        R"({"users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]})",
        "id must be a positive int64");
    CheckInvalid(R"({"users":[{"id":7}]})", "uuid must be a non-empty string");
}

}  // namespace

int main() {
    TestValidUsersAreNormalized();
    TestInvalidLimitsAreRejected();
    TestMalformedUsersAreRejected();
    std::cout << "v2board_user_list_json_test: ok\n";
    return 0;
}
