#pragma once

#include "acppnode/app/dns/dns.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace acpp::app::dns {

class GlobalDnsCache final {
public:
    static void Configure(size_t max_entries, uint32_t min_ttl, uint32_t max_ttl);

    [[nodiscard]] static std::optional<DnsResult> Lookup(std::string_view domain);
    static void PublishResult(std::string_view domain, const DnsResult& result);

    [[nodiscard]] static DnsCacheStats GetStats();
};

}  // namespace acpp::app::dns
