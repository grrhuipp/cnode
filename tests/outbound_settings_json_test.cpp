#include "settings_json.hpp"

#include <cstdint>
#include <limits>

int main() {
    using acpp::json::object;
    using acpp::proxyman::outbound::ParsePort;

    auto result = ParsePort(object{}, {"server_port", "port"});
    if (result.present || !result.valid || result.value != 0) return 1;

    result = ParsePort(object{{"port", int64_t{1}}}, {"port"});
    if (!result.present || !result.valid || result.value != 1) return 2;

    result = ParsePort(object{{"port", uint64_t{65535}}}, {"port"});
    if (!result.present || !result.valid || result.value != 65535) return 3;

    result = ParsePort(object{{"port", int64_t{0}}}, {"port"});
    if (!result.present || result.valid) return 4;

    result = ParsePort(object{{"port", int64_t{-1}}}, {"port"});
    if (!result.present || result.valid) return 5;

    result = ParsePort(object{{"port", uint64_t{65536}}}, {"port"});
    if (!result.present || result.valid) return 6;

    result = ParsePort(
        object{{"port", std::numeric_limits<uint64_t>::max()}}, {"port"});
    if (!result.present || result.valid) return 7;

    result = ParsePort(object{{"port", 443.0}}, {"port"});
    if (!result.present || result.valid) return 8;

    result = ParsePort(object{{"port", "443"}}, {"port"});
    if (!result.present || result.valid) return 9;

    result = ParsePort(
        object{{"server_port", "bad"}, {"port", int64_t{443}}},
        {"server_port", "port"});
    if (!result.present || result.valid) return 10;

    result = ParsePort(
        object{{"port", int64_t{443}}}, {"server_port", "port"});
    if (!result.present || !result.valid || result.value != 443) return 11;

    result = ParsePort(
        object{{"server_port", int64_t{8443}}, {"port", int64_t{443}}},
        {"server_port", "port"});
    if (!result.present || !result.valid || result.value != 8443) return 12;

    return 0;
}
