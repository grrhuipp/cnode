#include "global_cache.hpp"

#include "acppnode/common/clock.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/string_hash.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <unordered_map>

namespace acpp::app::dns {

namespace {

constexpr size_t kNumShards = 256;

struct Settings {
    size_t max_entries = 0;
    uint32_t min_ttl = 60;
    uint32_t max_ttl = 3600;
};

struct Entry {
    std::vector<net::ip::address> addresses;
    std::string error_msg;
    time_point expire_time{};
    uint32_t ttl = 60;
    bool negative = false;
};

using EntryMap =
    std::unordered_map<std::string, Entry, TransparentStringHash, TransparentStringEq>;

struct ShardSnapshot {
    EntryMap entries;
    uint64_t generation = 0;
};

struct PreparedUpdate {
    std::string domain;
    Entry entry;
};

std::atomic<std::shared_ptr<const Settings>>& GlobalSettings() {
    static std::atomic<std::shared_ptr<const Settings>> settings{
        std::make_shared<const Settings>()};
    return settings;
}

std::array<std::atomic<std::shared_ptr<const ShardSnapshot>>, kNumShards>&
GlobalShards() {
    static std::array<std::atomic<std::shared_ptr<const ShardSnapshot>>, kNumShards> shards{};
    return shards;
}

std::atomic<uint64_t>& HitCount() {
    static std::atomic<uint64_t> value{0};
    return value;
}

std::atomic<uint64_t>& MissCount() {
    static std::atomic<uint64_t> value{0};
    return value;
}

std::atomic<uint64_t>& ExpiredCount() {
    static std::atomic<uint64_t> value{0};
    return value;
}

std::shared_ptr<const Settings> LoadSettings() {
    return GlobalSettings().load(std::memory_order_acquire);
}

size_t ActiveShardCount(const Settings& settings) noexcept {
    if (settings.max_entries == 0) {
        return 0;
    }
    return std::min(settings.max_entries, kNumShards);
}

size_t ShardCapacity(const Settings& settings, size_t shard_index) noexcept {
    const size_t active = ActiveShardCount(settings);
    if (active == 0 || shard_index >= active) {
        return 0;
    }
    const size_t base = settings.max_entries / active;
    const size_t remainder = settings.max_entries % active;
    return base + (shard_index < remainder ? 1 : 0);
}

size_t ShardIndex(std::string_view domain, const Settings& settings) noexcept {
    const size_t active = ActiveShardCount(settings);
    if (active == 0) {
        return 0;
    }
    return std::hash<std::string_view>{}(domain) % active;
}

uint32_t ClampTtl(uint32_t ttl, const Settings& settings) noexcept {
    return std::max(settings.min_ttl, std::min(settings.max_ttl, ttl));
}

uint32_t RemainingTtl(const Entry& entry, time_point now) noexcept {
    if (entry.expire_time <= now) {
        return 0;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        entry.expire_time - now);
    return static_cast<uint32_t>(std::max<int64_t>(remaining.count(), 1));
}

DnsResult MakeResult(const Entry& entry, time_point now) {
    DnsResult result;
    result.from_cache = true;
    result.ttl = RemainingTtl(entry, now);
    if (entry.negative) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = entry.error_msg.empty()
            ? "DNS negative cache"
            : entry.error_msg;
        return result;
    }

    result.addresses = entry.addresses;
    result.error = ErrorCode::OK;
    return result;
}

void ResetStats() noexcept {
    HitCount().store(0, std::memory_order_relaxed);
    MissCount().store(0, std::memory_order_relaxed);
    ExpiredCount().store(0, std::memory_order_relaxed);
}

void ClearShards() {
    auto empty = std::make_shared<const ShardSnapshot>();
    for (auto& shard : GlobalShards()) {
        shard.store(empty, std::memory_order_release);
    }
}

void TrimShard(ShardSnapshot& snapshot, const Settings& settings, size_t shard_index) {
    const auto now = steady_clock::now();
    for (auto it = snapshot.entries.begin(); it != snapshot.entries.end();) {
        if (it->second.expire_time <= now) {
            it = snapshot.entries.erase(it);
        } else {
            ++it;
        }
    }

    const size_t max_entries = ShardCapacity(settings, shard_index);
    while (snapshot.entries.size() > max_entries) {
        auto victim = std::min_element(
            snapshot.entries.begin(),
            snapshot.entries.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.second.expire_time < rhs.second.expire_time;
            });
        if (victim == snapshot.entries.end()) {
            break;
        }
        snapshot.entries.erase(victim);
    }
}

std::optional<PreparedUpdate> PrepareUpdate(
    const GlobalDnsCacheUpdate& update,
    const Settings& settings,
    time_point now) {
    auto domain = ::acpp::domain::CanonicalDnsHostname(update.domain);
    if (domain.empty()) {
        return std::nullopt;
    }

    Entry entry;
    entry.addresses = update.addresses;
    entry.error_msg = update.error_msg;
    entry.ttl = ClampTtl(update.ttl, settings);
    entry.expire_time = now + std::chrono::seconds(entry.ttl);
    entry.negative = update.negative;

    if (!entry.negative && entry.addresses.empty()) {
        return std::nullopt;
    }

    return PreparedUpdate{
        .domain = std::move(domain),
        .entry = std::move(entry),
    };
}

void PublishShard(
    size_t shard_index,
    std::span<const PreparedUpdate* const> updates,
    const Settings& settings) {
    if (updates.empty() || ShardCapacity(settings, shard_index) == 0) {
        return;
    }

    auto& shard = GlobalShards()[shard_index];
    for (;;) {
        auto current = shard.load(std::memory_order_acquire);
        auto next = current
            ? std::make_shared<ShardSnapshot>(*current)
            : std::make_shared<ShardSnapshot>();

        for (const auto* update : updates) {
            if (!update) {
                continue;
            }
            next->entries[update->domain] = update->entry;
        }
        TrimShard(*next, settings, shard_index);
        next->generation = current ? current->generation + 1 : 1;

        std::shared_ptr<const ShardSnapshot> published = std::move(next);
        if (shard.compare_exchange_weak(
                current,
                published,
                std::memory_order_release,
                std::memory_order_acquire)) {
            return;
        }
    }
}

}  // namespace

void GlobalDnsCache::Configure(
    size_t max_entries,
    uint32_t min_ttl,
    uint32_t max_ttl) {
    if (min_ttl > max_ttl) {
        std::swap(min_ttl, max_ttl);
    }

    auto& global = GlobalSettings();
    for (;;) {
        auto current = global.load(std::memory_order_acquire);
        if (current &&
            current->max_entries == max_entries &&
            current->min_ttl == min_ttl &&
            current->max_ttl == max_ttl) {
            return;
        }

        auto next = std::make_shared<Settings>(Settings{
            .max_entries = max_entries,
            .min_ttl = min_ttl,
            .max_ttl = max_ttl,
        });
        std::shared_ptr<const Settings> published = std::move(next);
        if (global.compare_exchange_weak(
                current,
                published,
                std::memory_order_release,
                std::memory_order_acquire)) {
            ClearShards();
            ResetStats();
            return;
        }
    }
}

std::optional<DnsResult> GlobalDnsCache::Lookup(std::string_view domain) {
    auto settings = LoadSettings();
    if (!settings || settings->max_entries == 0) {
        return std::nullopt;
    }

    auto canonical = ::acpp::domain::CanonicalDnsHostname(domain);
    if (canonical.empty()) {
        return std::nullopt;
    }

    const size_t shard_index = ShardIndex(canonical, *settings);
    auto snapshot = GlobalShards()[shard_index].load(std::memory_order_acquire);
    if (!snapshot) {
        MissCount().fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    auto it = snapshot->entries.find(std::string_view(canonical));
    if (it == snapshot->entries.end()) {
        MissCount().fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    const auto now = steady_clock::now();
    if (it->second.expire_time <= now) {
        ExpiredCount().fetch_add(1, std::memory_order_relaxed);
        MissCount().fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    HitCount().fetch_add(1, std::memory_order_relaxed);
    return MakeResult(it->second, now);
}

void GlobalDnsCache::PublishResult(std::string_view domain, const DnsResult& result) {
    if (result.from_cache) {
        return;
    }
    if (!result.Ok() && result.error != ErrorCode::DNS_NO_RECORD) {
        return;
    }

    GlobalDnsCacheUpdate update;
    update.domain.assign(domain);
    update.addresses = result.addresses;
    update.error_msg = result.error_msg;
    update.ttl = result.ttl;
    update.negative = !result.Ok();
    PublishBatch(std::span<const GlobalDnsCacheUpdate>(&update, 1));
}

void GlobalDnsCache::PublishBatch(std::span<const GlobalDnsCacheUpdate> updates) {
    auto settings = LoadSettings();
    if (!settings || settings->max_entries == 0 || updates.empty()) {
        return;
    }

    const auto now = steady_clock::now();
    std::vector<PreparedUpdate> prepared;
    prepared.reserve(updates.size());
    std::array<std::vector<const PreparedUpdate*>, kNumShards> grouped;

    for (const auto& update : updates) {
        auto item = PrepareUpdate(update, *settings, now);
        if (!item) {
            continue;
        }
        const size_t shard_index = ShardIndex(item->domain, *settings);
        prepared.push_back(std::move(*item));
        grouped[shard_index].push_back(&prepared.back());
    }

    for (size_t i = 0; i < ActiveShardCount(*settings); ++i) {
        if (grouped[i].empty()) {
            continue;
        }
        PublishShard(
            i,
            std::span<const PreparedUpdate* const>(grouped[i].data(), grouped[i].size()),
            *settings);
    }
}

DnsCacheStats GlobalDnsCache::GetStats() {
    DnsCacheStats stats;
    auto settings = LoadSettings();
    if (!settings) {
        return stats;
    }

    stats.hits = HitCount().load(std::memory_order_relaxed);
    stats.misses = MissCount().load(std::memory_order_relaxed);
    stats.expired = ExpiredCount().load(std::memory_order_relaxed);
    stats.capacity = settings->max_entries;

    const size_t active = ActiveShardCount(*settings);
    for (size_t i = 0; i < active; ++i) {
        auto snapshot = GlobalShards()[i].load(std::memory_order_acquire);
        if (snapshot) {
            stats.entries += snapshot->entries.size();
        }
    }
    return stats;
}

void GlobalDnsCache::Clear() {
    ClearShards();
    ResetStats();
}

}  // namespace acpp::app::dns
