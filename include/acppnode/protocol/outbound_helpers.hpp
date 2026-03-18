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
// 返回完整地址列表，顺序由 dns_service / 调用方的 IPv4/IPv6 偏好决定。
// ============================================================================
inline cobalt::task<std::expected<std::vector<net::ip::address>, ErrorCode>>
ResolveOutboundAddresses(const std::string& host,
                         IDnsService* dns_service,
                         bool prefer_ipv6 = false) {
    boost::system::error_code ec;
    auto addr = net::ip::make_address(host, ec);
    if (!ec) {
        co_return std::vector<net::ip::address>{addr};
    }

    if (!dns_service) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    auto result = co_await dns_service->Resolve(host, prefer_ipv6);
    if (!result.Ok()) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    co_return std::move(result.addresses);
}

// ============================================================================
// 兼容旧调用：返回首个地址
// ============================================================================
inline cobalt::task<std::expected<net::ip::address, ErrorCode>>
ResolveOutboundAddress(const std::string& host, IDnsService* dns_service) {
    auto result = co_await ResolveOutboundAddresses(host, dns_service, false);
    if (!result || result->empty()) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    co_return (*result)[0];
}

}  // namespace acpp
