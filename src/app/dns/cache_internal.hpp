#pragma once

#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/clock.hpp"

#include <array>
#include <optional>
#include <span>
#include <string_view>

namespace acpp::app::dns {

struct DnsCacheEntry {
    memory::ThreadLocalVector<net::ip::address> addresses;
    time_point expire_time;
    time_point last_access;
    uint32_t ttl;
    bool negative = false;
};

// Worker-private DNS cache. Only DNS implementation files should see the
// Worker-local storage and sharded LRU layout.
class DnsCache {
public:
    explicit DnsCache(size_t max_size, uint32_t min_ttl, uint32_t max_ttl);

    std::optional<DnsCacheEntry> Get(std::string_view domain);
    void Put(std::string_view domain,
             std::span<const net::ip::address> addresses,
             uint32_t ttl);
    void PutNegative(std::string_view domain,
                     uint32_t ttl = 60);
    void Clear();
    DnsCacheStats GetStats() const;

private:
    static constexpr size_t kNumShards = 256;

    struct CacheKeyRef {
        std::string_view domain;
    };

    struct CacheKeyHash {
        [[nodiscard]] size_t operator()(CacheKeyRef key) const noexcept {
            return std::hash<std::string_view>{}(key.domain);
        }
    };

    struct CacheKeyEq {
        [[nodiscard]] bool operator()(CacheKeyRef a,
                                      CacheKeyRef b) const noexcept {
            return a.domain == b.domain;
        }
    };

    struct CacheNode {
        memory::ThreadLocalString domain;
        DnsCacheEntry entry;

        CacheNode(std::string_view d, DnsCacheEntry e)
            : domain(d), entry(std::move(e)) {}

        [[nodiscard]] CacheKeyRef Key() const noexcept {
            return CacheKeyRef{domain};
        }
    };

    struct alignas(64) Shard {
        using NodeList = memory::ThreadLocalList<CacheNode>;

        NodeList lru_list;
        memory::ThreadLocalUnorderedMap<CacheKeyRef, NodeList::iterator,
            CacheKeyHash, CacheKeyEq> cache;
        size_t max_entries = 0;

        size_t Evict();
    };

    Shard& GetShard(CacheKeyRef cache_key) const {
        size_t hash = CacheKeyHash{}(cache_key);
        return shards_[hash & (kNumShards - 1)];
    }

    mutable std::array<Shard, kNumShards> shards_;
    uint32_t min_ttl_;
    uint32_t max_ttl_;
    uint64_t capacity_ = 0;
    mutable uint64_t hits_ = 0;
    mutable uint64_t misses_ = 0;
    uint64_t expired_ = 0;
    uint64_t total_entries_ = 0;
};

}  // namespace acpp::app::dns
