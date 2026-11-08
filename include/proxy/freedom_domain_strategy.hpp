#pragma once

#include "transport/internet/http_headers.hpp"
#include <cstdint>
#include <optional>
#include <string_view>

namespace proxy::freedom::outbound {

enum class DomainStrategy : uint8_t {
    AsIs,
    UseIP,
    UseIPv6v4,
    UseIPv4,
    UseIPv4v6,
    UseIPv6,
    ForceIP,
    ForceIPv6v4,
    ForceIPv6,
    ForceIPv4v6,
    ForceIPv4,
};

[[nodiscard]] inline std::optional<DomainStrategy> ParseDomainStrategy(std::string_view value) {
    using transport::internet::EqualsAsciiCI;
    if (EqualsAsciiCI(value, "asis")) return DomainStrategy::AsIs;
    if (EqualsAsciiCI(value, "useip")) return DomainStrategy::UseIP;
    if (EqualsAsciiCI(value, "useipv6v4")) return DomainStrategy::UseIPv6v4;
    if (EqualsAsciiCI(value, "useipv4")) return DomainStrategy::UseIPv4;
    if (EqualsAsciiCI(value, "useipv4v6")) return DomainStrategy::UseIPv4v6;
    if (EqualsAsciiCI(value, "useipv6")) return DomainStrategy::UseIPv6;
    if (EqualsAsciiCI(value, "forceip")) return DomainStrategy::ForceIP;
    if (EqualsAsciiCI(value, "forceipv6v4")) return DomainStrategy::ForceIPv6v4;
    if (EqualsAsciiCI(value, "forceipv6")) return DomainStrategy::ForceIPv6;
    if (EqualsAsciiCI(value, "forceipv4v6")) return DomainStrategy::ForceIPv4v6;
    if (EqualsAsciiCI(value, "forceipv4")) return DomainStrategy::ForceIPv4;
    return std::nullopt;
}

}  // namespace proxy::freedom::outbound
