#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <memory_resource>
#include <vector>

namespace buf {

struct Buffer;

// ============================================================================
// Buffer - relay/MultiBuffer 固定 8KB 数据块
//
// 数据面固定 8KB，直接向进程资源借还；MultiBuffer 不缓存空闲块。
// start/end 游标：Advance() 消费无需 memmove，Produce() 记录写入量。
// ============================================================================
struct Buffer {
    static constexpr uint32_t kSize = 8192;

    uint8_t  data[kSize];
    uint32_t start = 0;
    uint32_t end   = 0;

    // UDP 数据面：本 Buffer 数据对应的对端地址（Full Cone 逐包目标/来源），
    // 对齐 xray-core buf.Buffer.UDP 的 "buffer 携带 endpoint" 语义。上行=目标，
    // 回包=来源。TCP relay 路径通常不携带 endpoint，因此懒构造 TargetAddress。
    std::optional<common::TargetAddress> udp_;

    // 有效数据视图 [start, end)
    std::span<uint8_t> Bytes() noexcept {
        return {data + start, end - start};
    }
    std::span<const uint8_t> Bytes() const noexcept {
        return {data + start, end - start};
    }

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
        udp_.reset();
    }

    // 设置/清除本 Buffer 的 UDP 对端地址。
    void SetUDP(const common::TargetAddress& dest) {
        udp_ = dest;
    }
    void SetUDP(common::TargetAddress&& dest) {
        udp_ = std::move(dest);
    }
    void ClearUDP() noexcept {
        udp_.reset();
    }
    [[nodiscard]] bool HasUDP() const noexcept { return udp_.has_value(); }
    [[nodiscard]] common::TargetAddress& UDP() noexcept { return *udp_; }
    [[nodiscard]] const common::TargetAddress& UDP() const noexcept { return *udp_; }

    // 默认初始化不清零 payload；分配失败保持非抛出入口的 nullptr 语义。
    [[nodiscard]] static Buffer* New() noexcept {
        void* raw = memory::detail::TryAllocateProcessRaw(sizeof(Buffer), alignof(Buffer));
        if (!raw) return nullptr;
        auto* b = ::new (raw) Buffer;
        memory::OnBufferNew();
        return b;
    }

    // 非平凡成员必须在归还存储前析构。
    static void Free(Buffer* b) noexcept {
        if (!b) {
            return;
        }
        memory::OnBufferFree();
        b->~Buffer();
        mi_free(b);
    }

private:
    Buffer() noexcept = default;
};

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
    void reset(Buffer* b = nullptr) noexcept {
        if (ptr != b) {
            Buffer::Free(ptr);
            ptr = b;
        }
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
//     ReadMultiBuffer() 为 vector 元数据再做一次堆分配；超过 8 个才构造
//     spill vector 及其分配器，借用当时所属会话域的地址稳定资源。
// ============================================================================
class MultiBuffer {
public:
    static constexpr size_t kInlineCapacity = 8;

    MultiBuffer() noexcept = default;

    explicit MultiBuffer(BufferGuard buffer) noexcept {
        if (buffer) {
            total_bytes_ = buffer->Len();
            inline_buffers_[0] = buffer.release();
            size_ = 1;
        }
    }

    MultiBuffer(const MultiBuffer&) = delete;
    MultiBuffer& operator=(const MultiBuffer&) = delete;

    MultiBuffer(MultiBuffer&& other) noexcept
        : spill_(std::move(other.spill_)) {
        MoveFrom(std::move(other));
    }

    MultiBuffer& operator=(MultiBuffer&& other) noexcept {
        if (this != &other) {
            ReleaseOwnedBuffers();
            spill_ = std::move(other.spill_);
            start_ = 0;
            size_ = 0;
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
        return spill_ ? spill_->size() - start_ : size_;
    }
    [[nodiscard]] size_t byte_size() const noexcept {
        return total_bytes_;
    }
    [[nodiscard]] bool HasUDP() const noexcept {
        for (const auto* buffer : *this) {
            if (buffer && buffer->HasUDP()) return true;
        }
        return false;
    }
    [[nodiscard]] Buffer* back() noexcept {
        if (empty()) {
            return nullptr;
        }
        return spill_ ? spill_->back() : inline_buffers_[start_ + size_ - 1];
    }
    [[nodiscard]] const Buffer* back() const noexcept {
        if (empty()) {
            return nullptr;
        }
        return spill_ ? spill_->back() : inline_buffers_[start_ + size_ - 1];
    }


    void reserve(size_t n) {
        if (!spill_) {
            if (n > kInlineCapacity) EnsureSpill(n);
            return;
        }
        if (n <= spill_->capacity() - start_) return;
        if (start_ != 0) {
            spill_->erase(spill_->begin(), spill_->begin() +
                static_cast<std::ptrdiff_t>(start_));
            start_ = 0;
        }
        spill_->reserve(n);
    }

    // Consumes the guard even on failure. A failed insertion releases that
    // buffer and leaves the container's data and accounting unchanged.
    void push_back(BufferGuard buffer) {
        if (!buffer) {
            return;
        }
        const size_t bytes = buffer->Len();
        if (bytes > std::numeric_limits<size_t>::max() - total_bytes_)
            throw std::length_error("MultiBuffer byte size overflow");
        if (!spill_ && size_ < kInlineCapacity) {
            if (start_ + size_ >= kInlineCapacity) {
                CompactInline();
            }
            inline_buffers_[start_ + size_++] = buffer.release();
            total_bytes_ += bytes;
            return;
        }
        EnsureSpill();
        spill_->push_back(buffer.get());
        (void)buffer.release();
        total_bytes_ += bytes;
    }

    [[nodiscard]] BufferGuard pop_front() noexcept {
        if (empty()) {
            return {};
        }

        if (spill_) {
            Buffer* out = (*spill_)[start_];
            if (out) {
                total_bytes_ -= std::min(total_bytes_, static_cast<size_t>(out->Len()));
            }
            (*spill_)[start_++] = nullptr;
            CompactConsumedSpill();
            return BufferGuard{out};
        }

        Buffer* out = inline_buffers_[start_];
        if (out) {
            total_bytes_ -= std::min(total_bytes_, static_cast<size_t>(out->Len()));
        }
        inline_buffers_[start_++] = nullptr;
        if (--size_ == 0) {
            start_ = 0;
        }
        return BufferGuard{out};
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
        if (spill_) {
            for (size_t i = 0; i < n; ++i) {
                if ((*spill_)[start_ + i]) {
                    total_bytes_ -= std::min(
                        total_bytes_,
                        static_cast<size_t>((*spill_)[start_ + i]->Len()));
                }
                Buffer::Free((*spill_)[start_ + i]);
                (*spill_)[start_ + i] = nullptr;
            }
            start_ += n;
            CompactConsumedSpill();
            return;
        }
        for (size_t i = 0; i < n; ++i) {
            Buffer*& slot = inline_buffers_[start_ + i];
            if (slot) {
                total_bytes_ -= std::min(
                    total_bytes_,
                    static_cast<size_t>(slot->Len()));
            }
            Buffer::Free(slot);
            slot = nullptr;
        }
        start_ += n;
        size_ -= n;
        if (size_ == 0) {
            start_ = 0;
        }
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
        ReleaseIfIdle();
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
        ReleaseIfIdle();
        return copied;
    }

    [[nodiscard]] bool MovePrefixTo(MultiBuffer& dst, size_t bytes) {
        if (std::addressof(dst) == this || bytes > total_bytes_ ||
            bytes > std::numeric_limits<size_t>::max() - dst.total_bytes_) {
            return false;
        }
        if (bytes == 0) {
            ReleaseIfIdle();
            return true;
        }
        // Prepare the only possible split and all destination pointer slots
        // before releasing a source slot or changing either buffer's cursors.
        size_t remaining = bytes;
        size_t whole_buffers = 0;
        Buffer* tail = dst.back();
        Buffer* split_source = nullptr;
        for (Buffer* buffer : *this) {
            if (!buffer || buffer->IsEmpty()) continue;
            if (buffer->Len() > remaining) { split_source = buffer; break; }
            remaining -= buffer->Len();
            ++whole_buffers;
            tail = buffer;
            if (remaining == 0) break;
        }
        const bool coalesce = split_source && !split_source->HasUDP() && tail &&
            !tail->HasUDP() && tail->Available() + tail->start >= remaining;
        BufferGuard split;
        if (split_source && !coalesce) {
            split = BufferGuard{Buffer::New()};
            if (!split) return false;
            std::memcpy(split->Tail().data(), split_source->Bytes().data(), remaining);
            split->Produce(static_cast<uint32_t>(remaining));
        }
        try {
            if (split_source && split_source->HasUDP()) {
                split->SetUDP(split_source->UDP());
            }
            dst.ReserveAdditional(whole_buffers + (split ? 1 : 0), bytes);
        } catch (const std::bad_alloc&) {
            return false;
        } catch (const std::length_error&) {
            return false;
        }

        size_t drained = 0;
        size_t transferred = 0;
        for (Buffer*& buffer : *this) {
            if (split_source ? buffer == split_source : transferred == whole_buffers) break;
            if (buffer && !buffer->IsEmpty()) {
                dst.push_back(ReleaseSlot(buffer));
                ++transferred;
            }
            ++drained;
        }
        if (split_source) {
            if (coalesce) {
                if (tail->Available() < remaining) tail->CompactToFront();
                std::memcpy(tail->Tail().data(), split_source->Bytes().data(), remaining);
                tail->Produce(static_cast<uint32_t>(remaining));
                dst.RecordTailProduced(remaining);
            } else {
                dst.push_back(std::move(split));
            }
            split_source->Advance(static_cast<uint32_t>(remaining));
            total_bytes_ -= remaining;
        }
        drop_front(drained);
        ReleaseIfIdle();
        return true;
    }

    [[nodiscard]] std::span<const uint8_t> PrefixSpan(size_t len) const& noexcept {
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
    std::span<const uint8_t> PrefixSpan(size_t) const&& = delete;

    [[nodiscard]] std::span<const uint8_t> FrontSpan() const& noexcept {
        for (const Buffer* buffer : *this) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            return buffer->Bytes();
        }
        return {};
    }
    std::span<const uint8_t> FrontSpan() const&& = delete;

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

    [[nodiscard]] BufferGuard TakeFrontIfLen(size_t len) noexcept {
        while (!empty()) {
            Buffer* buffer = *begin();
            if (!buffer || buffer->IsEmpty()) {
                drop_front(1);
                continue;
            }
            if (buffer->Len() != len) {
                return {};
            }
            return pop_front();
        }
        return {};
    }

    void clear() noexcept {
        ReleaseOwnedBuffers();
        spill_.reset();
        start_ = 0;
        size_ = 0;
        total_bytes_ = 0;
    }

    // A tagged zero-byte datagram is a message, not idle retained storage.
    void ReleaseIfIdle() noexcept {
        if (!empty() && total_bytes_ == 0 && !HasUDP()) clear();
    }

    void RecordTailProduced(size_t bytes) {
        if (bytes > std::numeric_limits<size_t>::max() - total_bytes_) {
            throw std::length_error("MultiBuffer byte size overflow");
        }
        total_bytes_ += bytes;
    }

    [[nodiscard]] BufferGuard ReleaseSlot(Buffer*& slot) noexcept {
        Buffer* buffer = slot;
        if (!buffer) {
            return {};
        }
        const size_t len = buffer->Len();
        total_bytes_ = len >= total_bytes_ ? 0 : total_bytes_ - len;
        slot = nullptr;
        return BufferGuard{buffer};
    }

    void FreeSlot(Buffer*& slot) noexcept {
        (void)ReleaseSlot(slot);
    }

    void MoveTo(MultiBuffer& dst, bool clear_udp = false) {
        if (std::addressof(dst) == this) {
            return;
        }
        dst.ReserveAdditional(size(), total_bytes_);
        for (Buffer*& buffer : *this) {
            if (!buffer || (buffer->IsEmpty() && (clear_udp || !buffer->HasUDP()))) {
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

    void AppendAndCoalesce(MultiBuffer&& next) {
        if (std::addressof(next) == this) {
            return;
        }
        size_t additional = next.size();
        const size_t capacity = spill_ ? spill_->capacity() : kInlineCapacity;
        // Resolve the exact slot budget only when the upper bound would allocate.
        if (additional > capacity - size()) {
            additional = 0;
            const Buffer* tail = back();
            size_t tail_space = tail && !tail->HasUDP() ? Buffer::kSize - tail->Len() : 0;
            for (const Buffer* buffer : next) {
                if (!buffer) continue;
                const uint32_t len = buffer->Len();
                if (len == 0 && !buffer->HasUDP()) continue;
                const bool udp = buffer->HasUDP();
                if (!udp && len <= tail_space) {
                    tail_space -= len;
                } else {
                    ++additional;
                    tail_space = udp ? 0 : Buffer::kSize - len;
                }
            }
        }
        ReserveAdditional(additional, next.total_bytes_);
        for (Buffer*& buffer : next) {
            if (!buffer || (buffer->IsEmpty() && !buffer->HasUDP())) {
                next.FreeSlot(buffer);
                continue;
            }
            Buffer* tail = back();
            const uint32_t len = buffer->Len();
            if (!buffer->HasUDP() && tail && !tail->HasUDP() &&
                tail->Available() + tail->start >= len) {
                if (tail->Available() < len) {
                    tail->CompactToFront();
                }
                std::memcpy(tail->Tail().data(), buffer->Bytes().data(), len);
                tail->Produce(len);
                RecordTailProduced(len);
                next.FreeSlot(buffer);
            } else {
                push_back(next.ReleaseSlot(buffer));
            }
        }
        next.clear();
    }

    // 空 spill 的 start_ 是 spill 偏移，不能用来索引内联数组。
    Buffer** begin() noexcept {
        if (!spill_) return inline_buffers_ + start_;
        return size() > 0 ? spill_->data() + start_ : inline_buffers_;
    }
    Buffer** end() noexcept {
        return begin() + size();
    }
    Buffer* const* begin() const noexcept {
        if (!spill_) return inline_buffers_ + start_;
        return size() > 0 ? spill_->data() + start_ : inline_buffers_;
    }
    Buffer* const* end() const noexcept {
        return begin() + size();
    }

private:
    void ReserveAdditional(size_t buffers, size_t bytes) {
        if (buffers > std::numeric_limits<size_t>::max() - size() ||
            bytes > std::numeric_limits<size_t>::max() - total_bytes_)
            throw std::length_error("MultiBuffer size overflow");
        if (buffers != 0) reserve(size() + buffers);
    }

    void ReleaseOwnedBuffers() noexcept {
        if (spill_) {
            for (size_t i = start_; i < spill_->size(); ++i) {
                Buffer::Free((*spill_)[i]);
                (*spill_)[i] = nullptr;
            }
            return;
        }
        for (size_t i = 0; i < size_; ++i) {
            Buffer::Free(inline_buffers_[start_ + i]);
            inline_buffers_[start_ + i] = nullptr;
        }
    }

    void CompactInline() noexcept {
        if (start_ == 0) {
            return;
        }
        for (size_t i = 0; i < size_; ++i) {
            inline_buffers_[i] = inline_buffers_[start_ + i];
        }
        for (size_t i = size_; i < start_ + size_; ++i) {
            inline_buffers_[i] = nullptr;
        }
        start_ = 0;
    }

    void EnsureSpill(size_t capacity = kInlineCapacity * 2) {
        if (spill_) {
            return;
        }
        // Do not publish spilled state until the only fallible step succeeds.
        std::vector<Buffer*> prepared;
        prepared.reserve(std::max(capacity, kInlineCapacity * 2));
        spill_.emplace(std::move(prepared));
        for (size_t i = 0; i < size_; ++i) {
            spill_->push_back(inline_buffers_[start_ + i]);
            inline_buffers_[start_ + i] = nullptr;
        }
        start_ = 0;
        size_ = 0;
    }

    void CompactConsumedSpill() noexcept {
        if (!spill_ || start_ == 0) {
            return;
        }
        const size_t remaining = spill_->size() - start_;
        if (remaining <= kInlineCapacity) {
            for (size_t i = 0; i < remaining; ++i)
                inline_buffers_[i] = (*spill_)[start_ + i];
            size_ = remaining;
            start_ = 0;
            spill_.reset();
            return;
        }
        if (start_ < kInlineCapacity || start_ * 2 < spill_->size()) {
            return;
        }
        spill_->erase(
            spill_->begin(),
            spill_->begin() + static_cast<std::ptrdiff_t>(start_));
        start_ = 0;
    }

    void MoveFrom(MultiBuffer&& other) noexcept {
        if (spill_) {
            start_ = other.start_;
        } else {
            start_ = 0;
            size_ = other.size_;
            for (size_t i = 0; i < size_; ++i) {
                inline_buffers_[i] = other.inline_buffers_[other.start_ + i];
                other.inline_buffers_[other.start_ + i] = nullptr;
            }
        }
        other.start_ = 0;
        other.size_ = 0;
        other.spill_.reset();
        total_bytes_ = other.total_bytes_;
        other.total_bytes_ = 0;
    }

    Buffer* inline_buffers_[kInlineCapacity]{};
    // 无 spill 时为内联数组偏移，有 spill 时为 spill 偏移。
    size_t start_ = 0;
    size_t size_ = 0;
    size_t total_bytes_ = 0;
    std::optional<std::vector<Buffer*>> spill_;
};

// A completed UDP message owns a buffer even when it carries no data. An empty
// container remains EOF/no message; callers must not tag an uncompleted read.
[[nodiscard]] inline bool SetUdpTarget(MultiBuffer& packet, const common::TargetAddress& target) {
    if (packet.empty()) {
        BufferGuard buffer{Buffer::New()};
        if (!buffer) return false;
        buffer->SetUDP(target);
        packet.push_back(std::move(buffer));
        return true;
    }
    for (auto* buffer : packet) {
        if (buffer) buffer->SetUDP(target);
    }
    return true;
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
    const common::TargetAddress* target = nullptr;
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
        if (!buffer || (buffer->IsEmpty() && !buffer->HasUDP())) {
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

UdpDatagramInfo InspectUdpDatagram(const MultiBuffer&&) = delete;

[[nodiscard]] inline bool AppendSpanToMultiBuffer(std::span<const uint8_t> data,
                                                  MultiBuffer& out_mb) {
    if (data.empty()) return true;
    if (data.size() > std::numeric_limits<size_t>::max() - out_mb.byte_size())
        throw std::length_error("MultiBuffer byte size overflow");

    Buffer* tail = out_mb.back();
    const size_t tail_bytes = tail && !tail->HasUDP()
        ? std::min(data.size(), static_cast<size_t>(tail->Available())) : 0;

    if (tail_bytes == data.size()) {
        std::memmove(tail->Tail().data(), data.data(), tail_bytes);
        tail->Produce(static_cast<uint32_t>(tail_bytes));
        out_mb.RecordTailProduced(tail_bytes);
        return true;
    }
    // Build only the new suffix. Existing buffers and tail bytes remain
    // untouched until every data block and pointer slot is available.
    MultiBuffer suffix;
    try {
        size_t offset = tail_bytes;
        while (offset < data.size()) {
            BufferGuard buffer{Buffer::New()};
            if (!buffer) return false;
            const size_t chunk = std::min(data.size() - offset,
                                          static_cast<size_t>(Buffer::kSize));
            std::memcpy(buffer->Tail().data(), data.data() + offset, chunk);
            buffer->Produce(static_cast<uint32_t>(chunk));
            suffix.push_back(std::move(buffer));
            offset += chunk;
        }
        out_mb.reserve(out_mb.size() + suffix.size());
    } catch (const std::bad_alloc&) {
        return false;
    }

    if (tail_bytes != 0) {
        std::memmove(tail->Tail().data(), data.data(), tail_bytes);
        tail->Produce(static_cast<uint32_t>(tail_bytes));
        out_mb.RecordTailProduced(tail_bytes);
    }
    suffix.MoveTo(out_mb);
    return true;
}

// One uninitialized contiguous scratch block, returned on Reset rather than
// retained across frames or idle waits.
class ContiguousWriteBuffer {
public:
    ContiguousWriteBuffer() noexcept = default;
    ContiguousWriteBuffer(const ContiguousWriteBuffer&) = delete;
    ContiguousWriteBuffer& operator=(const ContiguousWriteBuffer&) = delete;
    ContiguousWriteBuffer(ContiguousWriteBuffer&& other) noexcept
        : pooled_(std::move(other.pooled_))
        , heap_(std::exchange(other.heap_, nullptr))
        , heap_size_(std::exchange(other.heap_size_, 0)) {}
    ContiguousWriteBuffer& operator=(ContiguousWriteBuffer&& other) noexcept {
        if (this != &other) {
            Reset();
            pooled_ = std::move(other.pooled_);
            heap_ = std::exchange(other.heap_, nullptr);
            heap_size_ = std::exchange(other.heap_size_, 0);
        }
        return *this;
    }
    ~ContiguousWriteBuffer() noexcept { Reset(); }

    [[nodiscard]] uint8_t* Prepare(size_t capacity) {
        Reset();
        if (capacity <= Buffer::kSize) {
            pooled_ = BufferGuard{Buffer::New()};
            if (!pooled_) {
                throw std::bad_alloc();
            }
            return pooled_->Tail().data();
        }
        if (capacity > kMaxCapacity) {
            throw std::length_error("ContiguousWriteBuffer capacity");
        }
        heap_ = static_cast<uint8_t*>(
            memory::detail::AllocateProcessRaw(capacity, alignof(uint8_t)));
        heap_size_ = capacity;
        return heap_;
    }

    [[nodiscard]] uint8_t* TryPrepare(size_t capacity) noexcept {
        if (capacity > kMaxCapacity) {
            Reset();
            return nullptr;
        }
        try {
            return Prepare(capacity);
        } catch (const std::bad_alloc&) {
            return nullptr;
        }
    }

    [[nodiscard]] uint8_t* Data() noexcept {
        if (pooled_) {
            return pooled_->Tail().data();
        }
        return heap_;
    }

    [[nodiscard]] bool Empty() const noexcept {
        return !pooled_ && !heap_;
    }

    void Reset() noexcept {
        pooled_.reset();
        if (heap_) {
            heap_size_ = 0;
            mi_free(std::exchange(heap_, nullptr));
        }
    }

    [[nodiscard]] bool TryAppendTo(size_t size, MultiBuffer& out) noexcept {
        try {
            if (pooled_) {
                if (size > pooled_->Available()) {
                    Reset();
                    return false;
                }
                pooled_->Produce(static_cast<uint32_t>(size));
                out.push_back(std::move(pooled_));
                Reset();
                return true;
            }
            if (size > heap_size_) {
                Reset();
                return false;
            }
            const bool appended = AppendSpanToMultiBuffer(
                std::span<const uint8_t>(heap_, size), out);
            Reset();
            return appended;
        } catch (...) {
            Reset();
            return false;
        }
    }

    void AppendTo(size_t size, MultiBuffer& out) {
        if (!TryAppendTo(size, out)) {
            throw std::bad_alloc();
        }
    }

private:
    static constexpr size_t kMaxCapacity =
        static_cast<size_t>(std::numeric_limits<std::ptrdiff_t>::max());

    BufferGuard pooled_;
    uint8_t* heap_ = nullptr;
    size_t heap_size_ = 0;
};

// Presents fragmented buffer storage as one contiguous byte span. A single
// non-empty input buffer remains zero-copy; fragmented input is copied once.
// This scoped view cannot be copied or moved: its span may refer to owned_.
// For zero-copy input, the source buffers must outlive the view's use.
class ContiguousBufferView {
public:
    ContiguousBufferView(const ContiguousBufferView&) = delete;
    ContiguousBufferView& operator=(const ContiguousBufferView&) = delete;
    ContiguousBufferView(const MultiBuffer&&) = delete;

    explicit ContiguousBufferView(const MultiBuffer& buffers)
        : owned_(memory::process_resource()) {
        const Buffer* single = nullptr;
        size_t buffer_count = 0;
        size_t total_size = 0;
        for (const Buffer* buffer : buffers) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            AddSize(buffer->Len(), total_size);
            single = buffer;
            ++buffer_count;
        }
        if (buffer_count == 0) {
            return;
        }
        if (buffer_count == 1) {
            bytes_ = single->Bytes();
            return;
        }
        owned_.reserve(total_size);
        for (const Buffer* buffer : buffers) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            owned_.insert(owned_.end(), bytes.begin(), bytes.end());
        }
        bytes_ = owned_;
    }

    ContiguousBufferView(std::span<const net::const_buffer> buffers,
                         std::pmr::memory_resource* resource = nullptr)
        : owned_(memory::ResourceOrProcess(resource)) {
        const net::const_buffer* single = nullptr;
        size_t buffer_count = 0;
        size_t total_size = 0;
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            if (!buffer.data()) {
                throw IoSystemError(
                    io_error::invalid_argument,
                    "buffer sequence contains a null data pointer");
            }
            AddSize(buffer.size(), total_size);
            single = &buffer;
            ++buffer_count;
        }
        if (buffer_count == 1) {
            bytes_ = std::span<const uint8_t>(
                static_cast<const uint8_t*>(single->data()), single->size());
            return;
        }
        owned_.reserve(total_size);
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            owned_.insert(owned_.end(), data, data + buffer.size());
        }
        bytes_ = owned_;
    }

    [[nodiscard]] std::span<const uint8_t> Bytes() const & noexcept {
        return bytes_;
    }
    std::span<const uint8_t> Bytes() const && = delete;

private:
    static void AddSize(size_t size, size_t& total_size) {
        if (size > std::numeric_limits<size_t>::max() - total_size) {
            throw IoSystemError(
                io_error::message_size, "buffer sequence is too large");
        }
        total_size += size;
    }

    std::pmr::vector<uint8_t> owned_;
    std::span<const uint8_t> bytes_;
};

// Each element owns one reader result, including all fragments of one datagram.
// The common zero/one-element case needs no queue allocation.
class MultiBufferBatch {
public:
    MultiBufferBatch() noexcept = default;
    explicit MultiBufferBatch(MultiBuffer payload) { Push(std::move(payload)); }
    MultiBufferBatch(const MultiBufferBatch&) = delete;
    MultiBufferBatch& operator=(const MultiBufferBatch&) = delete;

    MultiBufferBatch(MultiBufferBatch&& other) noexcept
        : first_(std::move(other.first_)), overflow_(std::move(other.overflow_)),
          bytes_(std::exchange(other.bytes_, 0)),
          occupied_(std::exchange(other.occupied_, false)) {}

    MultiBufferBatch& operator=(MultiBufferBatch&& other) noexcept {
        if (this != &other) {
            clear();
            overflow_ = std::move(other.overflow_);
            first_ = std::move(other.first_);
            bytes_ = std::exchange(other.bytes_, 0);
            occupied_ = std::exchange(other.occupied_, false);
        }
        return *this;
    }

    void Push(MultiBuffer payload) {
        const size_t bytes = payload.byte_size();
        if (bytes == 0 && !payload.HasUDP()) {
            payload.clear();
            return;
        }
        if (bytes > std::numeric_limits<size_t>::max() - bytes_) {
            throw std::length_error("MultiBufferBatch byte size overflow");
        }
        if (!occupied_) {
            first_ = std::move(payload);
            occupied_ = true;
        } else {
            overflow_.push_back(std::move(payload));
        }
        bytes_ += bytes;
    }

    [[nodiscard]] MultiBuffer PopFront() noexcept {
        if (!occupied_) return {};
        MultiBuffer result = std::move(first_);
        bytes_ -= result.byte_size();
        if (!overflow_.empty()) {
            first_ = std::move(overflow_.front());
            overflow_.pop_front();
        } else {
            occupied_ = false;
        }
        return result;
    }

    [[nodiscard]] bool empty() const noexcept { return !occupied_; }
    [[nodiscard]] size_t byte_size() const noexcept { return bytes_; }

    void clear() noexcept {
        first_.clear();
        overflow_.clear();
        bytes_ = 0;
        occupied_ = false;
    }

private:
    MultiBuffer first_;
    memory::RingDeque<MultiBuffer> overflow_;
    size_t bytes_ = 0;
    bool occupied_ = false;
};

}  // namespace buf

namespace buf {

[[nodiscard]] inline std::span<const uint8_t> ChunkBytes(const Buffer* buffer) noexcept {
    return buffer ? buffer->Bytes() : std::span<const uint8_t>{};
}

[[nodiscard]] inline std::span<const uint8_t> ChunkBytes(const net::const_buffer& buffer) noexcept {
    const auto* data = static_cast<const uint8_t*>(buffer.data());
    return data ? std::span<const uint8_t>(data, buffer.size()) : std::span<const uint8_t>{};
}

}  // namespace buf
