#include "cache_internal.hpp"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <memory>

namespace app::dns {

DnsCache::DnsCache(size_t max_size, uint32_t min_ttl, uint32_t max_ttl,
                   NegativeEvent negative_event)
    : capacity_(max_size)
    , min_ttl_(std::min(min_ttl, max_ttl))
    , max_ttl_(std::max(min_ttl, max_ttl))
    , negative_event_(negative_event) {
    if (capacity_ > 0) entries_.reserve(capacity_);
}

DnsCache::~DnsCache() {
    for (const auto& node : order_) {
        if (!node.entry.expired_negative) Report(node, "shutdown");
    }
}

void DnsCache::Report(const CacheNode& node, std::string_view event) const noexcept {
    const auto* reason = std::get_if<memory::ThreadLocalString>(&node.entry.answer);
    if (!negative_event_ || !reason) return;
    try {
        negative_event_(std::string_view(node.domain), std::string_view(*reason),
                        node.entry.negative_hits, event);
    } catch (...) {
        // Optional diagnostics must not invalidate cached answers or cleanup.
    }
}


std::optional<DnsResult> DnsCache::GetResult(std::string_view domain) {
    const auto found = entries_.find(domain);
    if (found == entries_.end()) {
        ++misses_;
        return std::nullopt;
    }
    const auto node = found->second;
    const auto now = steady_clock::now();
    if (now >= node->entry.expire_time) {
        if (std::holds_alternative<memory::ThreadLocalString>(node->entry.answer)) {
            // Keep only bounded recovery metadata, never serve an expired
            // answer. It shares the cache's eviction slots, not a second map.
            if (!node->entry.expired_negative) {
                node->entry.expired_negative = true;
                ++expired_negatives_;
                Report(*node, "expired");
            }
            order_.splice(order_.end(), order_, node);
        } else {
            entries_.erase(found);
            order_.erase(node);
        }
        ++misses_;
        return std::nullopt;
    }

    DnsCacheEntry& entry = node->entry;
    DnsResult result;
    if (const auto* reason = std::get_if<memory::ThreadLocalString>(&entry.answer)) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg.assign(reason->data(), reason->size());
        if (entry.negative_hits != UINT64_MAX) ++entry.negative_hits;
    } else {
        const auto& addresses = std::get<memory::ThreadLocalVector<net::ip::address>>(entry.answer);
        result.addresses.assign(addresses.begin(), addresses.end());
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        entry.expire_time - now);
    result.ttl = static_cast<uint32_t>(std::max<int64_t>(remaining.count(), 1));
    result.from_cache = true;
    ++hits_;
    return result;
}

void DnsCache::Store(std::string_view domain, const DnsResult& result) {
    if (capacity_ == 0 || (!result.Ok() && result.error != ErrorCode::DNS_NO_RECORD)) {
        return;
    }
    const auto existing = entries_.find(domain);
    // 零 TTL 地址只供本次查询使用，不受本地 TTL 下限延长，也不保留载荷。
    if (result.Ok() && result.ttl == 0) {
        if (existing != entries_.end()) {
            const auto node = existing->second;
            Report(*node, "recovered");
            if (node->entry.expired_negative) --expired_negatives_;
            entries_.erase(existing);
            order_.erase(node);
        }
        return;
    }

    DnsCacheEntry prepared;
    if (result.Ok()) {
        auto& addresses = std::get<memory::ThreadLocalVector<net::ip::address>>(prepared.answer);
        addresses.assign(result.addresses.begin(), result.addresses.end());
    } else {
        prepared.answer.emplace<memory::ThreadLocalString>(
            result.error_msg.data(), result.error_msg.size());
    }
    const uint32_t ttl = result.ttl == 0 ? 0 : std::clamp(result.ttl, min_ttl_, max_ttl_);
    prepared.expire_time = steady_clock::now() + std::chrono::seconds(ttl);

    if (existing != entries_.end()) {
        const auto node = existing->second;
        if (result.Ok() || !node->entry.expired_negative) {
            Report(*node, result.Ok() ? "recovered" : "refreshed");
        }
        if (node->entry.expired_negative) --expired_negatives_;
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

    // Insertion is the only growth path and adds one entry, so one eviction
    // restores the bound. Expired entries leave lazily on lookup; sweeping the
    // whole table here would make every insert into a full cache O(capacity).
    if (entries_.size() > capacity_) {
        const auto victim = std::prev(order_.end());
        if (!victim->entry.expired_negative) Report(*victim, "evicted");
        if (victim->entry.expired_negative) --expired_negatives_;
        entries_.erase(std::string_view(victim->domain));
        order_.erase(victim);
    }
}

DnsCacheStats DnsCache::GetStats() const {
    return DnsCacheStats{
        .hits = hits_,
        .misses = misses_,
        .entries = entries_.size() - expired_negatives_,
        .capacity = capacity_,
    };
}

}  // namespace app::dns
