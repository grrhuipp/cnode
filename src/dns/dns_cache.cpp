#include "acppnode/dns/dns_service.hpp"

namespace acpp {

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

std::optional<DnsCacheEntry> DnsCache::Get(const std::string& domain) {
    const CacheKeyRef cache_key{domain};
    auto& shard = GetShard(cache_key);
    const auto now = steady_clock::now();

    // shared_lock：允许多个读者并发查询同一分片，不更新 LRU（接受近似 FIFO 淘汰）
    std::shared_lock read_lock(shard.lock);

    auto it = shard.cache.find(cache_key);
    if (it == shard.cache.end()) {
        misses_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    const auto node_it = it->second;
    const auto& entry = node_it->entry;

    // 检查是否过期
    if (now >= entry.expire_time) {
        read_lock.unlock();

        bool erased = false;
        {
            std::unique_lock write_lock(shard.lock);
            auto write_it = shard.cache.find(cache_key);
            if (write_it != shard.cache.end() &&
                now >= write_it->second->entry.expire_time) {
                auto erase_it = write_it->second;
                shard.cache.erase(write_it);
                shard.lru_list.erase(erase_it);
                erased = true;
            }
        }

        if (erased) {
            expired_.fetch_add(1, std::memory_order_relaxed);
            total_entries_.fetch_sub(1, std::memory_order_relaxed);
        }
        misses_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    // 复制结果后释放 shared_lock（LRU 更新仅在写路径执行）
    DnsCacheEntry result = entry;
    read_lock.unlock();

    hits_.fetch_add(1, std::memory_order_relaxed);
    return result;
}

void DnsCache::Put(const std::string& domain,
                   const std::vector<net::ip::address>& addresses,
                   uint32_t ttl) {
    const CacheKeyRef cache_key{domain};
    auto& shard = GetShard(cache_key);

    // 限制 TTL 范围
    ttl = std::max(min_ttl_, std::min(max_ttl_, ttl));

    const auto now = steady_clock::now();

    std::unique_lock write_lock(shard.lock);

    // 检查是否已存在
    auto it = shard.cache.find(cache_key);
    if (it != shard.cache.end()) {
        // 更新现有条目并刷新 LRU 位置
        auto node_it = it->second;
        auto& entry = node_it->entry;
        entry.addresses = addresses;
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
    entry.addresses = addresses;
    entry.expire_time = now + std::chrono::seconds(ttl);
    entry.last_access = now;
    entry.ttl = ttl;
    entry.negative = false;

    shard.lru_list.emplace_front(domain, std::move(entry));
    auto node_it = shard.lru_list.begin();
    shard.cache.emplace(node_it->Key(), node_it);
    write_lock.unlock();

    // 更新全局计数（新增1个，淘汰evicted个）
    if (evicted > 0) {
        total_entries_.fetch_sub(evicted - 1, std::memory_order_relaxed);
    } else {
        total_entries_.fetch_add(1, std::memory_order_relaxed);
    }
}

void DnsCache::PutNegative(const std::string& domain,
                           uint32_t ttl) {
    const CacheKeyRef cache_key{domain};
    auto& shard = GetShard(cache_key);

    const auto now = steady_clock::now();

    std::unique_lock write_lock(shard.lock);

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
    write_lock.unlock();

    // 更新全局计数
    if (evicted > 0) {
        total_entries_.fetch_sub(evicted - 1, std::memory_order_relaxed);
    } else {
        total_entries_.fetch_add(1, std::memory_order_relaxed);
    }
}

void DnsCache::Clear() {
    for (auto& shard : shards_) {
        std::unique_lock write_lock(shard.lock);
        shard.cache.clear();
        shard.lru_list.clear();
    }
    total_entries_.store(0, std::memory_order_relaxed);
}

DnsCacheStats DnsCache::GetStats() const {
    DnsCacheStats stats;
    stats.hits = hits_.load(std::memory_order_relaxed);
    stats.misses = misses_.load(std::memory_order_relaxed);
    stats.expired = expired_.load(std::memory_order_relaxed);
    stats.entries = total_entries_.load(std::memory_order_relaxed);
    
    return stats;
}

size_t DnsCache::Shard::Evict() {
    // 调用者已持有锁
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

}  // namespace acpp
