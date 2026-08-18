#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/common/target_address.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace acpp::buf {

struct Buffer;

namespace detail {
// Worker-local 8KB Buffer 回收缓存的两个原语（定义在 Buffer 之后，需要完整类型）。
// 严格 thread_local = 单 Worker 私有，绝不跨 Worker 共享，符合 AGENTS 对
// “thread-local allocator / buffer provider” 的约束。
[[nodiscard]] inline void* BufferRecyclePop() noexcept;
[[nodiscard]] inline bool  BufferRecyclePush(void* raw) noexcept;
}  // namespace detail

// ============================================================================
// Buffer - relay/MultiBuffer 固定 8KB 数据块（对应 Xray buf.Buffer）
//
// 设计原则：
//   - relay 数据面固定 8KB，与 Xray 保持一致，消除转发循环里的多档大小选择
//   - 所有 release/诊断构建都使用 system allocator
//   - 握手、小对象和短 scratch 不占用 relay Buffer，走 allocator 的合适尺寸桶
//   - start/end 游标：Advance() 消费数据无需 memmove，Produce() 记录写入量
//   - New()/Free() 直接走 allocator 原语，避免每次分配都把整块 8KB 清零
// ============================================================================
struct Buffer {
    static constexpr uint32_t kSize = 8192;

    uint8_t  data[kSize];
    uint32_t start = 0;
    uint32_t end   = 0;

    // UDP 数据面：本 Buffer 数据对应的对端地址（Full Cone 逐包目标/来源），
    // 对齐 xray-core buf.Buffer.UDP 的 "buffer 携带 endpoint" 语义。上行=目标，
    // 回包=来源。TCP relay 路径通常不携带 endpoint，因此懒构造 TargetAddress。
    std::optional<TargetAddress> udp_;

    // 有效数据视图 [start, end)
    std::span<uint8_t>       Bytes() noexcept       { return {data + start, end - start}; }
    std::span<const uint8_t> Bytes() const noexcept { return {data + start, end - start}; }

    // 可写尾部 [end, kSize)
    std::span<uint8_t> Tail() noexcept { return {data + end, kSize - end}; }

    uint32_t Len()       const noexcept { return end - start; }
    uint32_t Available() const noexcept { return kSize - end; }
    bool     IsEmpty()   const noexcept { return start == end; }

    // 消费 n 字节（移动 start 游标，零 memmove）
    void Advance(uint32_t n) noexcept { start += n; }

    // 写入 n 字节后调用（移动 end 游标）
    void Produce(uint32_t n) noexcept { end += n; }

    // 将有效数据挪回 data[0]，为尾部追加腾出空间。只在已经消费过头部
    // 且调用方明确需要合并极小跨界片段时使用，避免常规 Advance 做 memmove。
    void CompactToFront() noexcept {
        const uint32_t len = Len();
        if (start == 0) {
            return;
        }
        if (len > 0) {
            std::memmove(data, data + start, len);
        }
        start = 0;
        end = len;
    }

    // 重置游标（复用 buffer），同时清除 UDP endpoint 标记。
    void Reset() noexcept {
        start = 0;
        end = 0;
        ClearUDP();
    }

    // 设置/清除本 Buffer 的 UDP 对端地址。
    void SetUDP(const TargetAddress& dest) {
        udp_ = dest;
    }
    void SetUDP(TargetAddress&& dest) {
        udp_ = std::move(dest);
    }
    void ClearUDP() noexcept {
        udp_.reset();
    }
    [[nodiscard]] bool HasUDP() const noexcept { return udp_.has_value(); }
    [[nodiscard]] TargetAddress& UDP() noexcept { return *udp_; }
    [[nodiscard]] const TargetAddress& UDP() const noexcept { return *udp_; }
    // 从 Worker-local 回收缓存或 allocator 获取；仅初始化游标，payload 保持
    // 未初始化以避免热路径无谓 memset。命中回收缓存时省去 8KB 全局分配。
    [[nodiscard]] static Buffer* New() noexcept {
        void* raw = detail::BufferRecyclePop();
        if (!raw) {
            raw = memory::AllocateRaw(sizeof(Buffer), alignof(Buffer));
            if (!raw) {
                return nullptr;
            }
        }
        auto* b = ::new (raw) Buffer;
        b->start = 0;
        b->end = 0;
        memory::OnBufferNew();
        return b;
    }

    // 归还。Buffer 含非平凡成员（udp_），先析构；裸内存优先回收到 Worker-local
    // 缓存，缓存满才真正还给 allocator。
    static void Free(Buffer* b) noexcept {
        if (!b) {
            return;
        }
        memory::OnBufferFree();
        b->~Buffer();
        if (!detail::BufferRecyclePush(b)) {
            memory::DeallocateRaw(b, sizeof(Buffer), alignof(Buffer));
        }
    }
};

namespace detail {

// 每 Worker 的 8KB 块回收缓存初始保留 16 块（128KB），遇到真实满载压力
// 后最多增长到 32 块（256KB）。单 io_context 单线程时这是纯 Worker-local
// 状态，不需要锁，也不会把空闲 RSS 一开始就抬高到最大值。
inline constexpr size_t kBufferRecycleInitialCap = 16;
inline constexpr size_t kBufferRecycleMaxCap = 32;

struct BufferRecycleCache {
    void* slots[kBufferRecycleMaxCap];
    size_t count = 0;
    size_t capacity = kBufferRecycleInitialCap;
#ifdef CNODE_MEMORY_STATS
    uint64_t high_water = 0;
    uint64_t pop_hits = 0;
    uint64_t pop_misses = 0;
    uint64_t push_hits = 0;
    uint64_t push_drops = 0;
    uint64_t trim_frees = 0;
#endif

    BufferRecycleCache() noexcept = default;
    BufferRecycleCache(const BufferRecycleCache&) = delete;
    BufferRecycleCache& operator=(const BufferRecycleCache&) = delete;

    ~BufferRecycleCache() {
        // Worker 线程退出时把缓存的裸块还给 allocator，不泄漏。
        while (count > 0) {
            memory::DeallocateRaw(slots[--count], sizeof(Buffer), alignof(Buffer));
        }
    }
};

inline BufferRecycleCache& TlsBufferRecycle() noexcept {
    thread_local BufferRecycleCache cache;
    return cache;
}

[[nodiscard]] inline void* BufferRecyclePop() noexcept {
    auto& cache = TlsBufferRecycle();
    if (cache.count == 0) {
#ifdef CNODE_MEMORY_STATS
        ++cache.pop_misses;
#endif
        return nullptr;
    }
#ifdef CNODE_MEMORY_STATS
    ++cache.pop_hits;
#endif
    return cache.slots[--cache.count];
}

[[nodiscard]] inline bool BufferRecyclePush(void* raw) noexcept {
    auto& cache = TlsBufferRecycle();
    if (cache.count >= cache.capacity && cache.capacity < kBufferRecycleMaxCap) {
        cache.capacity = std::min(cache.capacity * 2, kBufferRecycleMaxCap);
    }
    if (cache.count >= cache.capacity) {
#ifdef CNODE_MEMORY_STATS
        ++cache.push_drops;
#endif
        return false;
    }
    cache.slots[cache.count++] = raw;
#ifdef CNODE_MEMORY_STATS
    ++cache.push_hits;
    cache.high_water = std::max<uint64_t>(
        cache.high_water,
        static_cast<uint64_t>(cache.count));
#endif
    return true;
}

inline void TrimBufferRecycle(bool force) noexcept {
    auto& cache = TlsBufferRecycle();
    const size_t target = force ? 0 : kBufferRecycleInitialCap;
    while (cache.count > target) {
        memory::DeallocateRaw(cache.slots[--cache.count], sizeof(Buffer), alignof(Buffer));
#ifdef CNODE_MEMORY_STATS
        ++cache.trim_frees;
#endif
    }
    if (cache.capacity > kBufferRecycleInitialCap &&
        cache.count <= kBufferRecycleInitialCap) {
        cache.capacity = kBufferRecycleInitialCap;
    }
}

[[nodiscard]] inline memory::BufferRecycleStats SnapshotBufferRecycleStats() noexcept {
    auto& cache = TlsBufferRecycle();
    memory::BufferRecycleStats stats;
    stats.cache_depth = cache.count;
    stats.cache_capacity = cache.capacity;
#ifdef CNODE_MEMORY_STATS
    stats.cache_high_water = cache.high_water;
    stats.pop_hits = cache.pop_hits;
    stats.pop_misses = cache.pop_misses;
    stats.push_hits = cache.push_hits;
    stats.push_drops = cache.push_drops;
    stats.trim_frees = cache.trim_frees;
#endif
    return stats;
}

}  // namespace detail

[[nodiscard]] inline memory::BufferRecycleStats SnapshotThreadBufferRecycleStats() noexcept {
    return detail::SnapshotBufferRecycleStats();
}

inline void TrimThreadBufferRecycle(bool force) noexcept {
    detail::TrimBufferRecycle(force);
}

// RAII 守卫：离开作用域时自动释放单个 Buffer
struct BufferGuard {
    Buffer* ptr = nullptr;

    BufferGuard() = default;
    explicit BufferGuard(Buffer* b) noexcept : ptr(b) {}
    ~BufferGuard() noexcept { Buffer::Free(ptr); }

    BufferGuard(const BufferGuard&) = delete;
    BufferGuard& operator=(const BufferGuard&) = delete;

    BufferGuard(BufferGuard&& other) noexcept : ptr(other.ptr) {
        other.ptr = nullptr;
    }

    BufferGuard& operator=(BufferGuard&& other) noexcept {
        if (this != &other) {
            Buffer::Free(ptr);
            ptr = other.ptr;
            other.ptr = nullptr;
        }
        return *this;
    }

    [[nodiscard]] Buffer* get() const noexcept { return ptr; }
    [[nodiscard]] Buffer* release() noexcept {
        Buffer* out = ptr;
        ptr = nullptr;
        return out;
    }
    [[nodiscard]] explicit operator bool() const noexcept { return ptr != nullptr; }
    [[nodiscard]] Buffer* operator->() const noexcept { return ptr; }
    [[nodiscard]] Buffer& operator*() const noexcept { return *ptr; }
};

// ============================================================================
// MultiBuffer - Buffer 指针链（对应 Xray buf.MultiBuffer）
//
// 所有权语义：
//   - MultiBuffer 是 owning 容器；析构和 clear() 都归还持有的 Buffer
//   - std::move(mb) 即为所有权转移，零数据拷贝（只移动指针）
//   - 常规协议/分帧路径最多 8 个 Buffer，指针链内联保存，避免每次
//     ReadMultiBuffer() 为 vector 元数据再做一次堆分配；超过 8 个才 spill
//     到同一 Worker thread-local heap。
// ============================================================================
class MultiBuffer {
public:
    static constexpr size_t kInlineCapacity = 8;

    MultiBuffer() noexcept = default;

    explicit MultiBuffer(Buffer* buffer) noexcept {
        if (buffer) {
            inline_buffers_[0] = buffer;
            size_ = 1;
            total_bytes_ = buffer->Len();
        }
    }

    MultiBuffer(const MultiBuffer&) = delete;
    MultiBuffer& operator=(const MultiBuffer&) = delete;

    MultiBuffer(MultiBuffer&& other) noexcept {
        MoveFrom(std::move(other));
    }

    MultiBuffer& operator=(MultiBuffer&& other) noexcept {
        if (this != &other) {
            ReleaseOwnedBuffers();
            spill_.clear();
            size_ = 0;
            using_spill_ = false;
            total_bytes_ = 0;
            MoveFrom(std::move(other));
        }
        return *this;
    }

    ~MultiBuffer() noexcept {
        clear();
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }
    [[nodiscard]] size_t size() const noexcept {
        return using_spill_ ? spill_.size() - spill_start_ : size_;
    }
    [[nodiscard]] size_t byte_size() const noexcept {
        return total_bytes_;
    }
    [[nodiscard]] Buffer* back() noexcept {
        if (empty()) {
            return nullptr;
        }
        return using_spill_ ? spill_.back() : inline_buffers_[size_ - 1];
    }
    [[nodiscard]] const Buffer* back() const noexcept {
        if (empty()) {
            return nullptr;
        }
        return using_spill_ ? spill_.back() : inline_buffers_[size_ - 1];
    }

    void reserve(size_t n) {
        if (n <= kInlineCapacity) {
            return;
        }
        EnsureSpill();
        spill_.reserve(n);
    }

    void push_back(Buffer* buffer) {
        if (!buffer) {
            return;
        }
        total_bytes_ += buffer->Len();
        if (!using_spill_ && size_ < kInlineCapacity) {
            inline_buffers_[size_++] = buffer;
            return;
        }
        EnsureSpill();
        spill_.push_back(buffer);
    }

    [[nodiscard]] Buffer* pop_front() noexcept {
        if (empty()) {
            return nullptr;
        }

        if (using_spill_) {
            Buffer* out = spill_[spill_start_];
            if (out) {
                total_bytes_ -= std::min(total_bytes_, static_cast<size_t>(out->Len()));
            }
            spill_[spill_start_++] = nullptr;
            CompactConsumedSpill();
            return out;
        }

        Buffer* out = inline_buffers_[0];
        if (out) {
            total_bytes_ -= std::min(total_bytes_, static_cast<size_t>(out->Len()));
        }
        for (size_t i = 1; i < size_; ++i) {
            inline_buffers_[i - 1] = inline_buffers_[i];
        }
        inline_buffers_[--size_] = nullptr;
        return out;
    }

    // 释放并移除最前面的 n 个 Buffer，单次搬移（O(size) 而非 n 次 pop_front 的
    // O(n·size)）。用于 pending 数据消费：调用方按前缀计数，一次性丢弃已消费的
    // 头部 Buffer。
    void drop_front(size_t n) noexcept {
        const size_t cur = size();
        if (n == 0) {
            return;
        }
        if (n >= cur) {
            clear();
            return;
        }
        if (using_spill_) {
            for (size_t i = 0; i < n; ++i) {
                if (spill_[spill_start_ + i]) {
                    total_bytes_ -= std::min(
                        total_bytes_,
                        static_cast<size_t>(spill_[spill_start_ + i]->Len()));
                }
                Buffer::Free(spill_[spill_start_ + i]);
                spill_[spill_start_ + i] = nullptr;
            }
            spill_start_ += n;
            CompactConsumedSpill();
            return;
        }
        for (size_t i = 0; i < n; ++i) {
            if (inline_buffers_[i]) {
                total_bytes_ -= std::min(
                    total_bytes_,
                    static_cast<size_t>(inline_buffers_[i]->Len()));
            }
            Buffer::Free(inline_buffers_[i]);
        }
        const size_t rest = size_ - n;
        for (size_t i = 0; i < rest; ++i) {
            inline_buffers_[i] = inline_buffers_[i + n];
        }
        for (size_t i = rest; i < size_; ++i) {
            inline_buffers_[i] = nullptr;
        }
        size_ = rest;
    }

    size_t DropPrefixBytes(size_t bytes) noexcept {
        size_t remaining = bytes;
        size_t dropped = 0;
        size_t drained = 0;

        for (Buffer* buffer : *this) {
            if (remaining == 0) {
                break;
            }
            if (!buffer || buffer->IsEmpty()) {
                ++drained;
                continue;
            }

            const size_t len = buffer->Len();
            if (remaining >= len) {
                remaining -= len;
                dropped += len;
                ++drained;
                continue;
            }

            buffer->Advance(static_cast<uint32_t>(remaining));
            dropped += remaining;
            total_bytes_ -= std::min(total_bytes_, remaining);
            remaining = 0;
            break;
        }

        drop_front(drained);
        return dropped;
    }

    size_t ConsumePrefixTo(std::span<uint8_t> dst) noexcept {
        size_t copied = 0;
        size_t drained = 0;

        for (Buffer* buffer : *this) {
            if (copied >= dst.size()) {
                break;
            }
            if (!buffer || buffer->IsEmpty()) {
                ++drained;
                continue;
            }

            const auto bytes = buffer->Bytes();
            const size_t n = std::min(dst.size() - copied, bytes.size());
            std::memcpy(dst.data() + copied, bytes.data(), n);
            buffer->Advance(static_cast<uint32_t>(n));
            copied += n;
            total_bytes_ -= std::min(total_bytes_, n);
            if (buffer->IsEmpty()) {
                ++drained;
            } else {
                break;
            }
        }

        drop_front(drained);
        return copied;
    }

    [[nodiscard]] bool MovePrefixTo(MultiBuffer& dst, size_t bytes) {
        if (std::addressof(dst) == this) {
            return false;
        }

        size_t remaining = bytes;
        size_t drained = 0;
        for (Buffer*& buffer : *this) {
            if (remaining == 0) {
                break;
            }
            if (!buffer || buffer->IsEmpty()) {
                ++drained;
                continue;
            }

            const size_t len = buffer->Len();
            if (len <= remaining) {
                remaining -= len;
                dst.push_back(ReleaseSlot(buffer));
                ++drained;
                continue;
            }

            if (Buffer* tail = dst.back();
                tail && !tail->HasUDP() && remaining <= Buffer::kSize) {
                if (tail->Available() < remaining && tail->start > 0) {
                    tail->CompactToFront();
                }
                if (tail->Available() >= remaining) {
                    const auto prefix = buffer->Bytes().first(remaining);
                    std::memcpy(tail->Tail().data(), prefix.data(), remaining);
                    tail->Produce(static_cast<uint32_t>(remaining));
                    dst.RecordTailProduced(remaining);
                    buffer->Advance(static_cast<uint32_t>(remaining));
                    total_bytes_ -= std::min(total_bytes_, remaining);
                    remaining = 0;
                    break;
                }
            }

            BufferGuard out{Buffer::New()};
            if (!out || out->Available() < remaining) {
                drop_front(drained);
                return false;
            }
            const auto prefix = buffer->Bytes().first(remaining);
            std::memcpy(out->Tail().data(), prefix.data(), remaining);
            out->Produce(static_cast<uint32_t>(remaining));
            dst.push_back(out.release());
            buffer->Advance(static_cast<uint32_t>(remaining));
            total_bytes_ -= std::min(total_bytes_, remaining);
            remaining = 0;
            break;
        }

        drop_front(drained);
        return remaining == 0;
    }

    [[nodiscard]] std::span<const uint8_t> PrefixSpan(size_t len) const noexcept {
        if (len == 0) {
            return {};
        }
        for (const Buffer* buffer : *this) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            if (bytes.size() >= len) {
                return bytes.first(len);
            }
            return {};
        }
        return {};
    }

    [[nodiscard]] std::span<const uint8_t> FrontSpan() const noexcept {
        for (const Buffer* buffer : *this) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            return buffer->Bytes();
        }
        return {};
    }

    size_t CopyPrefixTo(std::span<uint8_t> dst) const noexcept {
        size_t copied = 0;
        for (const Buffer* buffer : *this) {
            if (copied >= dst.size()) {
                break;
            }
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            const size_t n = std::min(dst.size() - copied, bytes.size());
            std::memcpy(dst.data() + copied, bytes.data(), n);
            copied += n;
        }
        return copied;
    }

    [[nodiscard]] Buffer* TakeFrontIfLen(size_t len) noexcept {
        while (!empty()) {
            Buffer* buffer = *begin();
            if (!buffer || buffer->IsEmpty()) {
                drop_front(1);
                continue;
            }
            if (buffer->Len() != len) {
                return nullptr;
            }
            return pop_front();
        }
        return nullptr;
    }

    Buffer** insert(Buffer** pos, Buffer* buffer) {
        if (!buffer) {
            return pos;
        }

        const size_t index = static_cast<size_t>(pos - begin());
        total_bytes_ += buffer->Len();
        if (!using_spill_ && size_ < kInlineCapacity) {
            for (size_t i = size_; i > index; --i) {
                inline_buffers_[i] = inline_buffers_[i - 1];
            }
            inline_buffers_[index] = buffer;
            ++size_;
            return inline_buffers_ + index;
        }

        EnsureSpill();
        auto it = spill_.insert(
            spill_.begin() + static_cast<std::ptrdiff_t>(spill_start_ + index),
            buffer);
        return spill_.data() + static_cast<size_t>(it - spill_.begin());
    }

    void clear() noexcept {
        ReleaseOwnedBuffers();
        if (using_spill_) {
            spill_.clear();
            spill_start_ = 0;
        } else {
            for (size_t i = 0; i < size_; ++i) {
                inline_buffers_[i] = nullptr;
            }
        }
        size_ = 0;
        total_bytes_ = 0;
    }

    void RecordTailProduced(size_t bytes) noexcept {
        total_bytes_ += bytes;
    }

    [[nodiscard]] Buffer* ReleaseSlot(Buffer*& slot) noexcept {
        Buffer* buffer = slot;
        if (!buffer) {
            return nullptr;
        }
        const size_t len = buffer->Len();
        total_bytes_ = len >= total_bytes_ ? 0 : total_bytes_ - len;
        slot = nullptr;
        return buffer;
    }

    void FreeSlot(Buffer*& slot) noexcept {
        Buffer::Free(ReleaseSlot(slot));
    }

    void MoveTo(MultiBuffer& dst, bool clear_udp = false) {
        if (std::addressof(dst) == this) {
            return;
        }
        for (Buffer*& buffer : *this) {
            if (!buffer || buffer->IsEmpty()) {
                FreeSlot(buffer);
                continue;
            }
            if (clear_udp) {
                buffer->ClearUDP();
            }
            dst.push_back(ReleaseSlot(buffer));
        }
        clear();
    }

    Buffer** begin() noexcept {
        return using_spill_ && size() > 0
            ? spill_.data() + spill_start_
            : inline_buffers_;
    }
    Buffer** end() noexcept {
        return begin() + size();
    }
    Buffer* const* begin() const noexcept {
        return using_spill_ && size() > 0
            ? spill_.data() + spill_start_
            : inline_buffers_;
    }
    Buffer* const* end() const noexcept {
        return begin() + size();
    }

private:
    void ReleaseOwnedBuffers() noexcept {
        if (using_spill_) {
            for (size_t i = spill_start_; i < spill_.size(); ++i) {
                Buffer::Free(spill_[i]);
                spill_[i] = nullptr;
            }
            return;
        }
        for (size_t i = 0; i < size_; ++i) {
            Buffer::Free(inline_buffers_[i]);
            inline_buffers_[i] = nullptr;
        }
    }

    void EnsureSpill() {
        if (using_spill_) {
            return;
        }
        spill_.reserve(kInlineCapacity * 2);
        for (size_t i = 0; i < size_; ++i) {
            spill_.push_back(inline_buffers_[i]);
            inline_buffers_[i] = nullptr;
        }
        using_spill_ = true;
        spill_start_ = 0;
        size_ = 0;
    }

    void CompactConsumedSpill() noexcept {
        if (!using_spill_ || spill_start_ == 0) {
            return;
        }
        if (spill_start_ == spill_.size()) {
            spill_.clear();
            spill_start_ = 0;
            return;
        }
        if (spill_start_ < kInlineCapacity || spill_start_ * 2 < spill_.size()) {
            return;
        }
        spill_.erase(
            spill_.begin(),
            spill_.begin() + static_cast<std::ptrdiff_t>(spill_start_));
        spill_start_ = 0;
    }

    void MoveFrom(MultiBuffer&& other) noexcept {
        using_spill_ = other.using_spill_;
        if (using_spill_) {
            spill_ = std::move(other.spill_);
            spill_start_ = other.spill_start_;
        } else {
            size_ = other.size_;
            for (size_t i = 0; i < size_; ++i) {
                inline_buffers_[i] = other.inline_buffers_[i];
                other.inline_buffers_[i] = nullptr;
            }
        }
        other.size_ = 0;
        other.using_spill_ = false;
        other.spill_start_ = 0;
        total_bytes_ = other.total_bytes_;
        other.total_bytes_ = 0;
    }

    Buffer* inline_buffers_[kInlineCapacity]{};
    size_t size_ = 0;
    size_t total_bytes_ = 0;
    bool using_spill_ = false;
    size_t spill_start_ = 0;
    std::vector<Buffer*> spill_;
};

// 计算 MultiBuffer 中所有 Buffer 的有效字节总数
inline size_t TotalLen(const MultiBuffer& mb) noexcept {
    return mb.byte_size();
}

enum class UdpDatagramStatus : uint8_t {
    Empty,
    Valid,
    MissingTarget,
    MixedTarget,
    SizeOverflow,
};

// UDP 链路的一次 Read/WriteMultiBuffer 必须表示一份 datagram；多个 Buffer
// 只是同一报文的存储分块。返回的指针仅在 MultiBuffer 未修改期间有效。
struct UdpDatagramInfo {
    UdpDatagramStatus status = UdpDatagramStatus::Empty;
    const TargetAddress* target = nullptr;
    const Buffer* single_buffer = nullptr;
    size_t buffer_count = 0;
    size_t payload_size = 0;

    [[nodiscard]] bool Valid() const noexcept {
        return status == UdpDatagramStatus::Valid;
    }
};

[[nodiscard]] inline UdpDatagramInfo InspectUdpDatagram(
    const MultiBuffer& mb) noexcept {
    UdpDatagramInfo info;
    for (const Buffer* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        if (!buffer->HasUDP()) {
            info.status = UdpDatagramStatus::MissingTarget;
            return info;
        }
        if (info.target && !info.target->SameEndpoint(buffer->UDP())) {
            info.status = UdpDatagramStatus::MixedTarget;
            return info;
        }
        if (buffer->Len() > std::numeric_limits<size_t>::max() - info.payload_size) {
            info.status = UdpDatagramStatus::SizeOverflow;
            return info;
        }
        if (!info.target) {
            info.target = std::addressof(buffer->UDP());
        }
        info.single_buffer = buffer;
        ++info.buffer_count;
        info.payload_size += buffer->Len();
    }
    if (info.buffer_count != 0) {
        info.status = UdpDatagramStatus::Valid;
    }
    return info;
}

[[nodiscard]] inline bool HasData(const MultiBuffer& mb) noexcept {
    return mb.byte_size() != 0;
}

[[nodiscard]] inline bool AppendSpanToMultiBuffer(std::span<const uint8_t> data,
                                                  MultiBuffer& out_mb,
                                                  bool coalesce_tail = true) {
    size_t offset = 0;

    if (coalesce_tail) {
        Buffer* tail = out_mb.back();
        // UDP endpoint marks packet boundaries; only coalesce plain stream buffers.
        if (tail && !tail->HasUDP() && tail->Available() > 0) {
            const size_t chunk = std::min(
                data.size(),
                static_cast<size_t>(tail->Available()));
            if (chunk > 0) {
                std::memcpy(tail->Tail().data(), data.data(), chunk);
                tail->Produce(static_cast<uint32_t>(chunk));
                out_mb.RecordTailProduced(chunk);
                offset += chunk;
            }
        }
    }

    while (offset < data.size()) {
        BufferGuard out{Buffer::New()};
        if (!out) {
            return false;
        }
        const size_t chunk = std::min(
            data.size() - offset,
            static_cast<size_t>(out->Available()));
        std::memcpy(out->Tail().data(), data.data() + offset, chunk);
        out->Produce(static_cast<uint32_t>(chunk));
        out_mb.push_back(out.release());
        offset += chunk;
    }
    return true;
}

}  // namespace acpp::buf
