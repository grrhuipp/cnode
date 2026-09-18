#include "cache_internal.hpp"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <memory>

namespace acpp::app::dns {

DnsCache::DnsCache(size_t max_size, uint32_t min_ttl, uint32_t max_ttl)
    : capacity_(max_size)
    , min_ttl_(std::min(min_ttl, max_ttl))
    , max_ttl_(std::max(min_ttl, max_ttl)) {
    if (capacity_ > 0) entries_.reserve(capacity_);
}

std::optional<DnsCacheEntry> DnsCache::Get(std::string_view domain) {
    const auto found = entries_.find(domain);
    if (found == entries_.end()) {
        ++misses_;
        return std::nullopt;
    }
    const auto node = found->second;
    const auto now = steady_clock::now();
    if (now >= node->entry.expire_time) {
        entries_.erase(found);
        order_.erase(node);
        ++expired_;
        ++misses_;
        return std::nullopt;
    }

    DnsCacheEntry result = node->entry;
    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        result.expire_time - now);
    result.ttl = static_cast<uint32_t>(std::max<int64_t>(remaining.count(), 1));
    ++hits_;
    return result;
}

void DnsCache::Store(std::string_view domain, const DnsResult& result) {
    if (capacity_ == 0 || (!result.Ok() && result.error != ErrorCode::DNS_NO_RECORD)) {
        return;
    }

    DnsCacheEntry prepared;
    prepared.negative = !result.Ok();
    if (!prepared.negative) {
        prepared.addresses.assign(result.addresses.begin(), result.addresses.end());
    }
    // L2 hits carry a remaining TTL. Applying the minimum again would extend
    // their lifetime every time an answer is copied into a Worker's L1 cache.
    prepared.ttl = result.from_cache
        ? result.ttl
        : std::clamp(result.ttl, min_ttl_, max_ttl_);
    const auto now = steady_clock::now();
    prepared.expire_time = now + std::chrono::seconds(prepared.ttl);

    const auto existing = entries_.find(domain);
    if (existing != entries_.end()) {
        const auto node = existing->second;
        std::destroy_at(&node->entry);
        std::construct_at(&node->entry, std::move(prepared));
        order_.splice(order_.begin(), order_, node);
        return;
    }

    // Stage both owners before eviction. If hash-node allocation fails, remove
    // the unindexed list node while all old entries and their views are intact.
    order_.emplace_front(domain, std::move(prepared));
    const auto node = order_.begin();
    try {
        entries_.emplace(std::string_view(node->domain), node);
    } catch (...) {
        order_.erase(node);
        throw;
    }

    if (entries_.size() > capacity_) {
        for (auto it = entries_.begin(); it != entries_.end();) {
            const auto candidate = it->second;
            if (now >= candidate->entry.expire_time) {
                it = entries_.erase(it);
                order_.erase(candidate);
            } else {
                ++it;
            }
        }
        while (entries_.size() > capacity_) {
            const auto victim = std::prev(order_.end());
            entries_.erase(std::string_view(victim->domain));
            order_.erase(victim);
        }
    }
}

DnsCacheStats DnsCache::GetStats() const {
    return DnsCacheStats{
        .hits = hits_,
        .misses = misses_,
        .entries = entries_.size(),
        .capacity = capacity_,
        .expired = expired_,
    };
}

}  // namespace acpp::app::dns
