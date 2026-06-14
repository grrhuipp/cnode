#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/common/target_address.hpp"

#include <cstdint>
#include <cstring>
#include <new>
#include <span>
#include <utility>
#include <vector>

namespace acpp::buf {

// ============================================================================
// Buffer - relay/MultiBuffer 固定 8KB 数据块（对应 Xray buf.Buffer）
//
// 设计原则：
//   - relay 数据面固定 8KB，与 Xray 保持一致，消除转发循环里的多档大小选择
//   - Worker 仍只有一个 thread-local heap；heap 内可由 mimalloc size class 承载多尺寸对象
//   - 握手、小对象和短 scratch 不占用 relay Buffer，走同一 Worker heap 的合适尺寸桶
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
    // 回包=来源。TCP relay 路径 has_udp 恒为 false，udp 默认构造、析构近乎 no-op。
    bool has_udp = false;
    TargetAddress udp;

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

    // 重置游标（复用 buffer），同时清除 UDP endpoint 标记。
    void Reset() noexcept {
        start = 0;
        end = 0;
        ClearUDP();
    }

    // 设置/清除本 Buffer 的 UDP 对端地址。
    void SetUDP(const TargetAddress& dest) {
        udp = dest;
        has_udp = true;
    }
    void SetUDP(TargetAddress&& dest) noexcept {
        udp = std::move(dest);
        has_udp = true;
    }
    void ClearUDP() noexcept {
        if (has_udp) {
            udp = TargetAddress{};
            has_udp = false;
        }
    }
    [[nodiscard]] bool HasUDP() const noexcept { return has_udp; }

    // 从 allocator 获取；仅初始化游标，payload 保持未初始化以避免热路径无谓 memset。
    [[nodiscard]] static Buffer* New() noexcept {
        void* raw = memory::AllocateRaw(sizeof(Buffer), alignof(Buffer));
        if (!raw) {
            return nullptr;
        }
        auto* b = ::new (raw) Buffer;
        b->start = 0;
        b->end = 0;
        memory::OnBufferNew();
        return b;
    }

    // 归还到 pool。Buffer 现在含非平凡成员（udp），必须先析构再回收原始内存。
    static void Free(Buffer* b) noexcept {
        if (!b) {
            return;
        }
        memory::OnBufferFree();
        b->~Buffer();
        memory::DeallocateRaw(b, sizeof(Buffer), alignof(Buffer));
    }
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
//   - 常规 relay/readv 路径最多 8 个 Buffer，指针链内联保存，避免每次
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
            MoveFrom(std::move(other));
        }
        return *this;
    }

    ~MultiBuffer() noexcept {
        clear();
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }
    [[nodiscard]] size_t size() const noexcept {
        return using_spill_ ? spill_.size() : size_;
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
            Buffer* out = spill_.front();
            spill_.erase(spill_.begin());
            return out;
        }

        Buffer* out = inline_buffers_[0];
        for (size_t i = 1; i < size_; ++i) {
            inline_buffers_[i - 1] = inline_buffers_[i];
        }
        inline_buffers_[--size_] = nullptr;
        return out;
    }

    Buffer** insert(Buffer** pos, Buffer* buffer) {
        if (!buffer) {
            return pos;
        }

        const size_t index = static_cast<size_t>(pos - begin());
        if (!using_spill_ && size_ < kInlineCapacity) {
            for (size_t i = size_; i > index; --i) {
                inline_buffers_[i] = inline_buffers_[i - 1];
            }
            inline_buffers_[index] = buffer;
            ++size_;
            return inline_buffers_ + index;
        }

        EnsureSpill();
        auto it = spill_.insert(spill_.begin() + static_cast<std::ptrdiff_t>(index), buffer);
        return spill_.data() + static_cast<size_t>(it - spill_.begin());
    }

    void clear() noexcept {
        ReleaseOwnedBuffers();
        if (using_spill_) {
            spill_.clear();
        } else {
            for (size_t i = 0; i < size_; ++i) {
                inline_buffers_[i] = nullptr;
            }
        }
        size_ = 0;
    }

    Buffer** begin() noexcept {
        return using_spill_ ? spill_.data() : inline_buffers_;
    }
    Buffer** end() noexcept {
        return begin() + size();
    }
    Buffer* const* begin() const noexcept {
        return using_spill_ ? spill_.data() : inline_buffers_;
    }
    Buffer* const* end() const noexcept {
        return begin() + size();
    }

private:
    void ReleaseOwnedBuffers() noexcept {
        if (using_spill_) {
            for (auto*& buffer : spill_) {
                Buffer::Free(buffer);
                buffer = nullptr;
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
        size_ = 0;
    }

    void MoveFrom(MultiBuffer&& other) noexcept {
        using_spill_ = other.using_spill_;
        if (using_spill_) {
            spill_ = std::move(other.spill_);
        } else {
            size_ = other.size_;
            for (size_t i = 0; i < size_; ++i) {
                inline_buffers_[i] = other.inline_buffers_[i];
                other.inline_buffers_[i] = nullptr;
            }
        }
        other.size_ = 0;
        other.using_spill_ = false;
    }

    Buffer* inline_buffers_[kInlineCapacity]{};
    size_t size_ = 0;
    bool using_spill_ = false;
    std::vector<Buffer*> spill_;
};

// 计算 MultiBuffer 中所有 Buffer 的有效字节总数
inline size_t TotalLen(const MultiBuffer& mb) noexcept {
    size_t n = 0;
    for (const auto* b : mb) {
        if (b) {
            n += b->Len();
        }
    }
    return n;
}

}  // namespace acpp::buf
