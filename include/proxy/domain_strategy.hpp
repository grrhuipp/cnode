#pragma once

#include "common/ascii.hpp"
#include <cstdint>
#include <optional>
#include <string_view>

namespace proxy {

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

[[nodiscard]] inline std::optional<DomainStrategy> ParseDomainStrategy(
    std::string_view value) noexcept {
    if (common::EqualsAsciiCI(value, "asis")) return DomainStrategy::AsIs;
    if (common::EqualsAsciiCI(value, "useip")) return DomainStrategy::UseIP;
    if (common::EqualsAsciiCI(value, "useipv6v4")) return DomainStrategy::UseIPv6v4;
    if (common::EqualsAsciiCI(value, "useipv4")) return DomainStrategy::UseIPv4;
    if (common::EqualsAsciiCI(value, "useipv4v6")) return DomainStrategy::UseIPv4v6;
    if (common::EqualsAsciiCI(value, "useipv6")) return DomainStrategy::UseIPv6;
    if (common::EqualsAsciiCI(value, "forceip")) return DomainStrategy::ForceIP;
    if (common::EqualsAsciiCI(value, "forceipv6v4")) return DomainStrategy::ForceIPv6v4;
    if (common::EqualsAsciiCI(value, "forceipv6")) return DomainStrategy::ForceIPv6;
    if (common::EqualsAsciiCI(value, "forceipv4v6")) return DomainStrategy::ForceIPv4v6;
    if (common::EqualsAsciiCI(value, "forceipv4")) return DomainStrategy::ForceIPv4;
    return std::nullopt;
}

}  // namespace proxy
