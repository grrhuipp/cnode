#pragma once

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

[[nodiscard]] std::optional<DomainStrategy> ParseDomainStrategy(std::string_view value);

}  // namespace proxy::freedom::outbound
