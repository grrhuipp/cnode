#pragma once

#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/clock.hpp"

#include <optional>
#include <string_view>

namespace acpp::app::dns {

struct DnsCacheEntry {
    memory::ThreadLocalVector<net::ip::address> addresses;
    time_point expire_time;
    uint32_t ttl;
    bool negative = false;
};

// One bounded cache owned by one Worker. Only the process-wide immutable
// result cache needs shards; local entries share the full local capacity.
class DnsCache {
public:
    explicit DnsCache(size_t max_size, uint32_t min_ttl, uint32_t max_ttl);
    DnsCache(const DnsCache&) = delete;
    DnsCache& operator=(const DnsCache&) = delete;

    std::optional<DnsCacheEntry> Get(std::string_view domain);
    void Store(std::string_view domain, const DnsResult& result);
    DnsCacheStats GetStats() const;

private:
    struct CacheNode {
        memory::ThreadLocalString domain;
        DnsCacheEntry entry;

        CacheNode(std::string_view name, DnsCacheEntry value)
            : domain(name), entry(std::move(value)) {}
    };
    using NodeList = memory::ThreadLocalList<CacheNode>;

    // New and replaced entries move to the front. Read hits do not reorder.
    NodeList order_;
    memory::ThreadLocalUnorderedMap<std::string_view, NodeList::iterator> entries_;
    size_t capacity_;
    uint32_t min_ttl_;
    uint32_t max_ttl_;
    uint64_t hits_ = 0;
    uint64_t misses_ = 0;
    uint64_t expired_ = 0;
};

}  // namespace acpp::app::dns
