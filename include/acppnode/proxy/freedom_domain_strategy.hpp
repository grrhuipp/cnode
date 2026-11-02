#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace acpp::proxy::freedom::outbound {

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
    if (value == "AsIs") return DomainStrategy::AsIs;
    if (value == "UseIP") return DomainStrategy::UseIP;
    if (value == "UseIPv6v4") return DomainStrategy::UseIPv6v4;
    if (value == "UseIPv4") return DomainStrategy::UseIPv4;
    if (value == "UseIPv4v6") return DomainStrategy::UseIPv4v6;
    if (value == "UseIPv6") return DomainStrategy::UseIPv6;
    if (value == "ForceIP") return DomainStrategy::ForceIP;
    if (value == "ForceIPv6v4") return DomainStrategy::ForceIPv6v4;
    if (value == "ForceIPv6") return DomainStrategy::ForceIPv6;
    if (value == "ForceIPv4v6") return DomainStrategy::ForceIPv4v6;
    if (value == "ForceIPv4") return DomainStrategy::ForceIPv4;
    return std::nullopt;
}

}  // namespace acpp::proxy::freedom::outbound
