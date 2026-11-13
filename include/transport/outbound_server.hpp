#pragma once

#include "common/asio_types.hpp"
#include "common/domain_name.hpp"
#include "common/ip_address.hpp"

#include <tl/expected.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
// 下一跳在加载期保留已解析的字面地址；域名由拨号器按连接解析。
namespace transport {

struct OutboundServer {
    std::string address;
    std::optional<net::ip::address> literal_address;
    uint16_t port = 0;
};

// The one validator for a configured next hop: a non-empty IP literal or DNS
// hostname and a non-zero port.
[[nodiscard]] inline tl::expected<OutboundServer, std::string_view> MakeOutboundServer(
    std::string address, uint16_t port) {
    if (address.empty()) return tl::unexpected(std::string_view("server address is required"));
    if (port == 0) return tl::unexpected(std::string_view("server port is required"));
    auto literal = common::ParseLiteral(address);
    if (!literal && !common::IsValidDnsHostname(address, common::TrailingDotPolicy::Allow)) {
        return tl::unexpected(std::string_view(
            "server address must be an IP literal or DNS hostname"));
    }
    return OutboundServer{
        .address = std::move(address),
        .literal_address = literal,
        .port = port,
    };
}

}  // namespace transport
