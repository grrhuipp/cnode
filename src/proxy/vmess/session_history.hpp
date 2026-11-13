#pragma once

#include "proxy/expiring_keyed_map.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <variant>

namespace proxy {

// Coordinator-owned, Sans-I/O AEAD request tuple history. A full table rejects
// new tuples rather than forgetting requests still inside the replay window.
class VmessSessionHistory {
public:
    using SessionKey = std::array<uint8_t, 32>;
    static constexpr int64_t kTtlSeconds = 180;
    static constexpr int64_t kCleanupIntervalSeconds = 30;
    static constexpr size_t kMaxEntries = 65536;

    explicit VmessSessionHistory(size_t capacity = kMaxEntries) : entries_(capacity), capacity_(capacity) {}

    [[nodiscard]] bool AddIfNew(const SessionKey& key, int64_t now) {
        if (now - last_cleanup_ >= kCleanupIntervalSeconds || entries_.size() >= capacity_) {
            last_cleanup_ = now;
            entries_.Prune(now);
        }
        auto* entry = entries_.Find(key);
        if (entry && entry->expires_at > now) return false;
        const auto expires_at = now + kTtlSeconds;
        if (entry) {
            entries_.Rearm(key, *entry, expires_at);
            return true;
        }
        if (entries_.size() >= capacity_) return false;
        return entries_.Insert(key, expires_at, std::monostate{}) != nullptr;
    }

private:
    proxy::ExpiringKeyedMap<32, std::monostate, int64_t> entries_;
    size_t capacity_;
    int64_t last_cleanup_ = 0;
};

}  // namespace proxy
