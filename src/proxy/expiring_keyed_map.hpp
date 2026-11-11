#pragma once

#include "common/allocator.hpp"
#include "common/hash_container_shrink.hpp"

#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/siphash.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <utility>

// 带 TTL 与容量上限的密钥化过期表：防重放会话键（VMess）与 0-RTT 票据（VLESS）共用。
namespace proxy {

// 对端可控的定长键按进程随机种子做 SipHash，防止哈希洪泛。
struct SecretKeyedHash {
    std::array<uint64_t, 2> key{};

    [[nodiscard]] static SecretKeyedHash Random() noexcept {
        SecretKeyedHash hash;
        if (RAND_bytes(reinterpret_cast<uint8_t*>(hash.key.data()), sizeof(hash.key)) != 1) {
            // 没有随机种子时整个防重放前提不成立，不可降级继续服务。
            std::abort();
        }
        return hash;
    }

    template <size_t N>
    [[nodiscard]] size_t operator()(const std::array<uint8_t, N>& value) const noexcept {
        return static_cast<size_t>(SIPHASH_24(key.data(), value.data(), N));
    }
};

struct TimingSafeEqual {
    template <size_t N>
    [[nodiscard]] bool operator()(const std::array<uint8_t, N>& a,
                                  const std::array<uint8_t, N>& b) const noexcept {
        return CRYPTO_memcmp(a.data(), b.data(), N) == 0;
    }
};

struct IgnoreErasedEntry {
    template <typename Entry>
    void operator()(Entry&) const noexcept {}
};

// FIFO 直接链接到哈希表节点；擦除与重新武装同步解链，既不复制键，也不积累过期队列记录。
// unordered_map 的 rehash 不移动节点；本表禁止移动以固定链表宿主。
template <size_t N, typename Value, typename TimePoint>
class ExpiringKeyedMap {
public:
    using Key = std::array<uint8_t, N>;
    struct Entry {
        TimePoint expires_at{};
        Value value;
        const Key* key = nullptr;
        Entry* previous = nullptr;
        Entry* next = nullptr;
    };

    explicit ExpiringKeyedMap(size_t capacity)
        : entries_(0, SecretKeyedHash::Random()), capacity_(capacity) {}
    ExpiringKeyedMap(const ExpiringKeyedMap&) = delete;
    ExpiringKeyedMap& operator=(const ExpiringKeyedMap&) = delete;

    [[nodiscard]] SecretKeyedHash hash_function() const noexcept { return entries_.hash_function(); }
    [[nodiscard]] size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
    [[nodiscard]] Entry* Find(const Key& key) noexcept {
        const auto it = entries_.find(key);
        return it == entries_.end() ? nullptr : &it->second;
    }

    template <typename OnErase = IgnoreErasedEntry>
    void Prune(TimePoint now, OnErase&& on_erase = {}) {
        while (first_ && first_->expires_at <= now) EvictOldest(on_erase);
        common::MaybeShrinkHashContainer(entries_);
    }

    template <typename OnErase = IgnoreErasedEntry>
    bool EvictOldest(OnErase&& on_erase = {}) {
        if (!first_) return false;
        Erase(*first_->key, on_erase);
        return true;
    }

    template <typename OnErase = IgnoreErasedEntry>
    Entry* Insert(const Key& key, TimePoint expires_at, Value value, OnErase&& on_erase = {}) {
        if (capacity_ == 0 || entries_.find(key) != entries_.end()) return nullptr;
        while (entries_.size() >= capacity_) EvictOldest(on_erase);
        auto [it, inserted] = entries_.try_emplace(key, Entry{expires_at, std::move(value)});
        if (!inserted) return nullptr;
        it->second.key = &it->first;
        Append(it->second);
        return &it->second;
    }

    void Rearm(const Key&, Entry& entry, TimePoint expires_at) noexcept {
        Unlink(entry);
        entry.expires_at = expires_at;
        Append(entry);
    }

    template <typename OnErase = IgnoreErasedEntry>
    void Erase(const Key& key, OnErase&& on_erase = {}) noexcept {
        if (auto it = entries_.find(key); it != entries_.end()) {
            Unlink(it->second);
            on_erase(it->second);
            entries_.erase(it);
        }
    }

private:
    void Append(Entry& entry) noexcept {
        entry.previous = last_;
        entry.next = nullptr;
        if (last_) last_->next = &entry;
        else first_ = &entry;
        last_ = &entry;
    }
    void Unlink(Entry& entry) noexcept {
        if (entry.previous) entry.previous->next = entry.next;
        else first_ = entry.next;
        if (entry.next) entry.next->previous = entry.previous;
        else last_ = entry.previous;
        entry.previous = entry.next = nullptr;
    }

    memory::UnorderedMap<Key, Entry, SecretKeyedHash, TimingSafeEqual> entries_;
    size_t capacity_;
    Entry* first_ = nullptr;
    Entry* last_ = nullptr;
};
}  // namespace proxy
