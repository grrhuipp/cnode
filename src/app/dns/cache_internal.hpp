#pragma once

#include "app/dns/dns.hpp"
#include "app/dns/stats.hpp"
#include "common/allocator.hpp"
#include "common/clock.hpp"

#include <optional>
#include <string_view>
#include <variant>

namespace app::dns {


// One bounded cache owned by the main/control DNS executor.
class DnsCache {
public:
    using NegativeEvent = void (*)(std::string_view domain, std::string_view reason,
                                  uint64_t hits, std::string_view event);
    explicit DnsCache(size_t max_size, uint32_t min_ttl, uint32_t max_ttl,
                      NegativeEvent negative_event = nullptr);
    ~DnsCache();
    DnsCache(const DnsCache&) = delete;
    DnsCache& operator=(const DnsCache&) = delete;

    std::optional<DnsResult> GetResult(std::string_view domain);
    void Store(std::string_view domain, const DnsResult& result);
    DnsCacheStats GetStats() const;

private:
    struct DnsCacheEntry {
        std::variant<memory::ThreadLocalVector<net::ip::address>,
                     memory::ThreadLocalString> answer;
        time_point expire_time;
        uint64_t negative_hits = 0;
        bool expired_negative = false;
    };
    struct CacheNode {
        memory::ThreadLocalString domain;
        DnsCacheEntry entry;

        CacheNode(std::string_view name, DnsCacheEntry value)
            : domain(name), entry(std::move(value)) {}
    };
    using NodeList = memory::ThreadLocalList<CacheNode>;
    void Report(const CacheNode& node, std::string_view event) const noexcept;

    // New and replaced entries move to the front. Read hits do not reorder.
    NodeList order_;
    memory::ThreadLocalUnorderedMap<std::string_view, NodeList::iterator> entries_;
    size_t capacity_;
    uint32_t min_ttl_;
    uint32_t max_ttl_;
    NegativeEvent negative_event_;
    size_t expired_negatives_ = 0;
    uint64_t hits_ = 0;
    uint64_t misses_ = 0;
};

}  // namespace app::dns
