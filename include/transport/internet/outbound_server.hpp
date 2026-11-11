#pragma once

#include "common/asio_types.hpp"

#include <cstdint>
#include <optional>
#include <string>

// 下一跳在加载期保留已解析的字面地址；域名由拨号器按连接解析。
namespace transport::internet {

struct OutboundServer {
    std::string address;
    std::optional<net::ip::address> literal_address;
    uint16_t port = 0;
};

}  // namespace transport::internet
