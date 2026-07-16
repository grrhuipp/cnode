#include "acppnode/infra/json_port.hpp"

#include <cstdint>
#include <limits>

int main() {
    using acpp::JsonPortError;
    using acpp::ReadJsonPort;
    using acpp::json::object;

    auto result = ReadJsonPort(object{}, {"server_port", "port"});
    if (result.error != JsonPortError::Missing || result.value != 0) return 1;

    result = ReadJsonPort(object{{"port", int64_t{1}}}, {"port"});
    if (!result.Valid() || result.value != 1) return 2;

    result = ReadJsonPort(object{{"port", uint64_t{65535}}}, {"port"});
    if (!result.Valid() || result.value != 65535) return 3;

    result = ReadJsonPort(object{{"port", int64_t{0}}}, {"port"});
    if (result.error != JsonPortError::OutOfRange) return 4;

    result = ReadJsonPort(object{{"port", int64_t{-1}}}, {"port"});
    if (result.error != JsonPortError::OutOfRange) return 5;

    result = ReadJsonPort(object{{"port", uint64_t{65536}}}, {"port"});
    if (result.error != JsonPortError::OutOfRange) return 6;

    result = ReadJsonPort(
        object{{"port", std::numeric_limits<uint64_t>::max()}}, {"port"});
    if (result.error != JsonPortError::OutOfRange) return 7;

    result = ReadJsonPort(object{{"port", 443.0}}, {"port"});
    if (result.error != JsonPortError::InvalidType) return 8;

    result = ReadJsonPort(object{{"port", "443"}}, {"port"});
    if (result.error != JsonPortError::InvalidType) return 9;

    result = ReadJsonPort(
        object{{"server_port", "bad"}, {"port", int64_t{443}}},
        {"server_port", "port"});
    if (result.error != JsonPortError::InvalidType) return 10;

    result = ReadJsonPort(
        object{{"port", int64_t{443}}}, {"server_port", "port"});
    if (!result.Valid() || result.value != 443) return 11;

    result = ReadJsonPort(
        object{{"server_port", int64_t{8443}}, {"port", int64_t{443}}},
        {"server_port", "port"});
    if (!result.Valid() || result.value != 8443) return 12;

    return 0;
}
