#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/dns/dns_service.hpp"

#include <expected>
#include <string>

namespace acpp {

// ============================================================================
// 出站通用 DNS 解析
//
// 先尝试 make_address（已是 IP 则直接返回），失败则调用 dns_service 异步解析。
// 取首个地址返回，不处理 IPv4/IPv6 偏好（Freedom 有自己的 ResolveTarget）。
// ============================================================================
inline cobalt::task<std::expected<net::ip::address, ErrorCode>>
ResolveOutboundAddress(const std::string& host, IDnsService* dns_service) {
    boost::system::error_code ec;
    auto addr = net::ip::make_address(host, ec);
    if (!ec) {
        co_return addr;
    }

    if (!dns_service) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    auto result = co_await dns_service->Resolve(host);
    if (!result.Ok()) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    co_return result.addresses[0];
}

}  // namespace acpp
