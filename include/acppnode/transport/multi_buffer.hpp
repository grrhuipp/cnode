#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace acpp {

// ============================================================================
// Buffer - 固定 8KB 的缓冲块（对应 Xray buf.Buffer）
//
// 设计原则：
//   - 固定 8KB，与 Xray 保持一致，消除多档大小选择的复杂度
//   - start/end 游标：Advance() 消费数据无需 memmove，Produce() 记录写入量
//   - New()/Free() 委托给 mimalloc（全局 new/delete 已被替换）
// ============================================================================
struct Buffer {
    static constexpr uint32_t kSize = 8192;

    uint8_t  data[kSize];
    uint32_t start = 0;
    uint32_t end   = 0;

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

    // 重置游标（复用 buffer）
    void Reset() noexcept { start = 0; end = 0; }

    // 从 pool 获取（mimalloc 管理，不会返回 nullptr）
    [[nodiscard]] static Buffer* New() noexcept { return new (std::nothrow) Buffer{}; }

    // 归还到 pool
    static void Free(Buffer* b) noexcept { delete b; }
};

// ============================================================================
// MultiBuffer - Buffer 指针链（对应 Xray buf.MultiBuffer）
//
// 所有权语义：
//   - 持有 MultiBuffer 的一方负责最终调用 FreeMultiBuffer()
//   - std::move(mb) 即为所有权转移，零数据拷贝（只移动指针）
// ============================================================================
using MultiBuffer = std::vector<Buffer*>;

// 计算 MultiBuffer 中所有 Buffer 的有效字节总数
inline size_t TotalLen(const MultiBuffer& mb) noexcept {
    size_t n = 0;
    for (const auto* b : mb) n += b->Len();
    return n;
}

// 释放所有 Buffer，清空 mb
inline void FreeMultiBuffer(MultiBuffer& mb) noexcept {
    for (auto* b : mb) Buffer::Free(b);
    mb.clear();
}

// RAII 守卫：离开作用域时自动释放 MultiBuffer
struct MultiBufferGuard {
    MultiBuffer& mb;
    explicit MultiBufferGuard(MultiBuffer& m) noexcept : mb(m) {}
    ~MultiBufferGuard() noexcept { FreeMultiBuffer(mb); }
    MultiBufferGuard(const MultiBufferGuard&) = delete;
    MultiBufferGuard& operator=(const MultiBufferGuard&) = delete;
};

}  // namespace acpp
