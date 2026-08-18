#pragma once

#include "acppnode/app/dns/dns.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp::app::dns {

struct GlobalDnsCacheUpdate {
    std::string domain;
    std::vector<net::ip::address> addresses;
    std::string error_msg;
    uint32_t ttl = 60;
    bool negative = false;
};

class GlobalDnsCache final {
public:
    static void Configure(size_t max_entries, uint32_t min_ttl, uint32_t max_ttl);

    [[nodiscard]] static std::optional<DnsResult> Lookup(std::string_view domain);
    static void PublishResult(std::string_view domain, const DnsResult& result);
    static void PublishBatch(std::span<const GlobalDnsCacheUpdate> updates);

    [[nodiscard]] static DnsCacheStats GetStats();
};

}  // namespace acpp::app::dns
