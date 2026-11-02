#pragma once

#include <compare>
#include <cstdint>
#include <string>
#include <utility>

namespace acpp {

struct OnlineDevice {
    int64_t user_id = 0;
    std::string ip;

    OnlineDevice() = default;
    OnlineDevice(int64_t user_id_value, std::string ip_value)
        : user_id(user_id_value), ip(std::move(ip_value)) {}

    friend auto operator<=>(const OnlineDevice&, const OnlineDevice&) = default;
};

}  // namespace acpp
