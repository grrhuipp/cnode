#include "cache_internal.hpp"

namespace acpp::app::dns {

DnsCache::DnsCache(size_t max_size, uint32_t min_ttl, uint32_t max_ttl)
    : min_ttl_(min_ttl), max_ttl_(max_ttl) {
    // 将总容量均分到各分片
    size_t per_shard = (max_size + kNumShards - 1) / kNumShards;
    for (auto& shard : shards_) {
        shard.max_entries = per_shard;
        if (per_shard > 0) {
            shard.cache.reserve(per_shard);
        }
    }
}

std::optional<DnsCacheEntry> DnsCache::Get(std::string_view domain) {
    const CacheKeyRef cache_key{domain};
    auto& shard = GetShard(cache_key);
    const auto now = steady_clock::now();

    auto it = shard.cache.find(cache_key);
    if (it == shard.cache.end()) {
        ++misses_;
        return std::nullopt;
    }

    const auto node_it = it->second;
    const auto& entry = node_it->entry;

    // 检查是否过期
    if (now >= entry.expire_time) {
        auto erase_it = it->second;
        shard.cache.erase(it);
        shard.lru_list.erase(erase_it);
        ++expired_;
        --total_entries_;
        ++misses_;
        return std::nullopt;
    }

    // 复制结果；LRU 更新仅在写路径执行，Get 命中保持低成本。
    DnsCacheEntry result = entry;

    ++hits_;
    return result;
}

void DnsCache::Put(std::string_view domain,
                   std::span<const net::ip::address> addresses,
                   uint32_t ttl) {
    const CacheKeyRef cache_key{domain};
    auto& shard = GetShard(cache_key);

    // 限制 TTL 范围
    ttl = std::max(min_ttl_, std::min(max_ttl_, ttl));

    const auto now = steady_clock::now();

    // 检查是否已存在
    auto it = shard.cache.find(cache_key);
    if (it != shard.cache.end()) {
        // 更新现有条目并刷新 LRU 位置
        auto node_it = it->second;
        auto& entry = node_it->entry;
        entry.addresses.assign(addresses.begin(), addresses.end());
        entry.expire_time = now + std::chrono::seconds(ttl);
        entry.last_access = now;
        entry.ttl = ttl;
        entry.negative = false;

        shard.lru_list.splice(shard.lru_list.begin(), shard.lru_list, node_it);
        return;
    }

    // 分片满时淘汰
    size_t evicted = 0;
    if (shard.cache.size() >= shard.max_entries) {
        evicted = shard.Evict();
    }

    // 添加新条目
    DnsCacheEntry entry;
    entry.addresses.assign(addresses.begin(), addresses.end());
    entry.expire_time = now + std::chrono::seconds(ttl);
    entry.last_access = now;
    entry.ttl = ttl;
    entry.negative = false;

    shard.lru_list.emplace_front(domain, std::move(entry));
    auto node_it = shard.lru_list.begin();
    shard.cache.emplace(node_it->Key(), node_it);

    // 更新全局计数（新增1个，淘汰evicted个）
    if (evicted > 0) {
        total_entries_ -= evicted - 1;
    } else {
        ++total_entries_;
    }
}

void DnsCache::PutNegative(std::string_view domain,
                           uint32_t ttl) {
    const CacheKeyRef cache_key{domain};
    auto& shard = GetShard(cache_key);

    const auto now = steady_clock::now();

    auto it = shard.cache.find(cache_key);
    if (it != shard.cache.end()) {
        auto node_it = it->second;
        auto& entry = node_it->entry;
        entry.addresses.clear();
        entry.expire_time = now + std::chrono::seconds(ttl);
        entry.last_access = now;
        entry.ttl = ttl;
        entry.negative = true;

        shard.lru_list.splice(shard.lru_list.begin(), shard.lru_list, node_it);
        return;
    }

    size_t evicted = 0;
    if (shard.cache.size() >= shard.max_entries) {
        evicted = shard.Evict();
    }

    DnsCacheEntry entry;
    entry.expire_time = now + std::chrono::seconds(ttl);
    entry.last_access = now;
    entry.ttl = ttl;
    entry.negative = true;

    shard.lru_list.emplace_front(domain, std::move(entry));
    auto node_it = shard.lru_list.begin();
    shard.cache.emplace(node_it->Key(), node_it);

    // 更新全局计数
    if (evicted > 0) {
        total_entries_ -= evicted - 1;
    } else {
        ++total_entries_;
    }
}

void DnsCache::Clear() {
    for (auto& shard : shards_) {
        shard.cache.clear();
        shard.lru_list.clear();
    }
    total_entries_ = 0;
}

DnsCacheStats DnsCache::GetStats() const {
    DnsCacheStats stats;
    stats.hits = hits_;
    stats.misses = misses_;
    stats.expired = expired_;
    stats.entries = total_entries_;

    return stats;
}

size_t DnsCache::Shard::Evict() {
    auto now = steady_clock::now();
    size_t evicted = 0;

    // 先淘汰过期的
    for (auto it = cache.begin(); it != cache.end();) {
        auto node_it = it->second;
        if (now >= node_it->entry.expire_time) {
            it = cache.erase(it);
            lru_list.erase(node_it);
            ++evicted;
        } else {
            ++it;
        }
    }

    // 如果还是满了，淘汰 LRU（最后面的）
    while (cache.size() >= max_entries && !lru_list.empty()) {
        auto node_it = std::prev(lru_list.end());
        cache.erase(node_it->Key());
        lru_list.erase(node_it);
        ++evicted;
    }

    return evicted;
}

}  // namespace acpp::app::dns
