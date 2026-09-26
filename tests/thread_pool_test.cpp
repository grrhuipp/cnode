#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <thread>

namespace {

bool RunPool() {
    using acpp::memory::PowerOfTwoAtLeast;
    constexpr auto highest = std::size_t{1} << (std::numeric_limits<std::size_t>::digits - 1);
    if (PowerOfTwoAtLeast(0) != 1 || PowerOfTwoAtLeast(1) != 1 ||
        PowerOfTwoAtLeast(192) != 256 || PowerOfTwoAtLeast(highest) != highest ||
        PowerOfTwoAtLeast(highest + 1) != 0 ||
        PowerOfTwoAtLeast(std::numeric_limits<std::size_t>::max()) != 0) return false;
    acpp::memory::ReturningThreadPool pool;
    constexpr std::array<std::size_t, 13> sizes{
        1, 64, 128, 2048, 4000, 4096, 8192, 16384, 17408, 18416, 18432, 32768, 65536};
    constexpr std::array<std::size_t, 5> alignments{8, 16, 64, 4096, 8192};
    for (int round = 0; round < 64; ++round) {
        for (auto size : sizes) {
            for (auto align : alignments) {
                void* block = pool.Allocate(size, align);
                if (!block || reinterpret_cast<std::uintptr_t>(block) % align != 0)
                    return false;
                std::memset(block, 0xa5, size);
                pool.Deallocate(block);
                // A direct chunk is already unmapped; current must not point to it.
                block = pool.Allocate(size, align);
                if (!block || reinterpret_cast<std::uintptr_t>(block) % align != 0)
                    return false;
                std::memset(block, 0x5a, size);
                pool.Deallocate(block);
            }
        }
    }
    std::array<void*, 128> concurrent{};
    for (auto& block : concurrent) {
        block = pool.Allocate(256, 32);
        if (!block) return false;
        std::memset(block, 0xa5, 256);
    }
    for (auto* block : concurrent) pool.Deallocate(block);
    if (pool.GetFootprint().idle_bytes == 0 || pool.GetFootprint().direct_bytes != 0)
        return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    pool.Purge();
    if (pool.GetFootprint().mapped_bytes != 0 || pool.GetFootprint().chunks != 0)
        return false;
    void* block = pool.Allocate(8192, 8192);
    if (!block || reinterpret_cast<std::uintptr_t>(block) % 8192 != 0)
        return false;
    pool.Deallocate(block);
    block = pool.Allocate(6000, 16);
    if (!block || pool.GetFootprint().direct_bytes > 2 * 4096)
        return false;
    std::memset(block, 0xa5, 6000);
    pool.Deallocate(block);
    return pool.Allocate(std::numeric_limits<std::size_t>::max(), 16) == nullptr &&
           pool.Allocate(8192, 3) == nullptr;
}

bool RunFragmented() {
    acpp::memory::ReturningThreadPool pool;
    std::array<void*, 512> blocks{};
    std::array<void*, 48> pinned{};
    for (auto& pin : pinned) {
        for (auto& block : blocks) {
            block = pool.Allocate(128, 16);
            if (!block) return false;
            std::memset(block, 0x5a, 128);
        }
        pin = blocks[0];
        for (std::size_t i = 1; i < blocks.size(); ++i)
            pool.Deallocate(blocks[i], 128, 16);
        if (pool.GetFootprint().mapped_bytes > 8 * acpp::memory::kThreadPoolChunkBytes)
            return false;
    }
    for (auto* pin : pinned) pool.Deallocate(pin, 128, 16);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    pool.Purge();
    if (pool.GetFootprint().mapped_bytes != 0) return false;

    // Requests can share a size class but not the alignment or usable size
    // of a freed slot. Keep a second object alive to prevent chunk recycling.
    void* small = pool.Allocate(1, 32);
    void* held = pool.Allocate(1, 32);
    if (!small || !held) return false;
    pool.Deallocate(small, 1, 32);
    void* larger = pool.Allocate(48, 8);
    if (!larger || larger == small) return false;
    std::memset(larger, 0xa5, 48);
    pool.Deallocate(larger, 48, 8);
    void* aligned = pool.Allocate(16, 32);
    if (!aligned || reinterpret_cast<std::uintptr_t>(aligned) % 32 != 0)
        return false;
    pool.Deallocate(aligned, 16, 32);
    pool.Deallocate(held, 1, 32);

    // A slot carved with alignment 32 has 992 usable bytes in a 1024-byte
    // class. Reusing it at alignment 16 must not inflate it to 1008 bytes.
    void* short_slot = pool.Allocate(481, 32);
    void* pinned_slot = pool.Allocate(600, 16);
    if (!short_slot || !pinned_slot) return false;
    std::memset(pinned_slot, 0x6b, 600);
    pool.Deallocate(short_slot, 481, 32);
    void* reused = pool.Allocate(665, 16);
    if (reused != short_slot) return false;
    pool.Deallocate(reused, 665, 16);
    void* longer = pool.Allocate(1005, 16);
    if (!longer || longer == short_slot) return false;
    std::memset(longer, 0xa7, 1005);
    for (std::size_t i = 0; i < 600; ++i)
        if (static_cast<const std::uint8_t*>(pinned_slot)[i] != 0x6b) return false;
    pool.Deallocate(longer, 1005, 16);
    pool.Deallocate(pinned_slot, 600, 16);
    return true;
}

bool RunMixed() {
    acpp::memory::ReturningThreadPool pool;
    struct Slot {
        void* ptr = nullptr;
        std::size_t bytes = 0;
        std::size_t alignment = 0;
        std::uint8_t pattern = 0;
    };
    std::array<Slot, 256> slots{};
    std::uint32_t state = 0xb35dff21u;
    const auto next = [&state] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    const auto intact = [](const Slot& slot) {
        const auto* bytes = static_cast<const std::uint8_t*>(slot.ptr);
        for (std::size_t i = 0; i < slot.bytes; ++i)
            if (bytes[i] != slot.pattern) return false;
        return true;
    };
    for (int step = 0; step < 100000; ++step) {
        Slot& slot = slots[next() % slots.size()];
        if (slot.ptr) {
            if (!intact(slot)) {
                std::fprintf(stderr, "mixed mismatch step=%d slot=%zu ptr=%p bytes=%zu align=%zu\n",
                             step, static_cast<std::size_t>(&slot - slots.data()),
                             slot.ptr, slot.bytes, slot.alignment);
                return false;
            }
            pool.Deallocate(slot.ptr, slot.bytes, slot.alignment);
            slot.ptr = nullptr;
        } else {
            slot.bytes = 8 + next() % 2000;
            slot.alignment = std::size_t{1} << (3 + next() % 5);
            slot.pattern = static_cast<std::uint8_t>(next());
            slot.ptr = pool.Allocate(slot.bytes, slot.alignment);
            if (!slot.ptr || reinterpret_cast<std::uintptr_t>(slot.ptr) % slot.alignment)
                return false;
            std::memset(slot.ptr, slot.pattern, slot.bytes);
        }
        if (step % 97 == 0) {
            for (const Slot& live : slots) {
                if (live.ptr && !intact(live)) {
                    std::fprintf(stderr, "mixed sweep mismatch step=%d slot=%zu ptr=%p bytes=%zu align=%zu\n",
                                 step, static_cast<std::size_t>(&live - slots.data()),
                                 live.ptr, live.bytes, live.alignment);
                    return false;
                }
            }
        }
    }
    for (const Slot& slot : slots) {
        if (slot.ptr && !intact(slot)) return false;
        pool.Deallocate(slot.ptr, slot.bytes, slot.alignment);
    }
    return pool.GetFootprint().direct_bytes == 0;
}

bool RunHotClass() {
    using acpp::memory::kThreadPoolChunkBytes;
    acpp::memory::ReturningThreadPool pool;
    std::array<void*, 8> blocks{};
    for (auto& block : blocks) {
        block = pool.Allocate(8192, 16); // payload plus header fits the 9 KiB class
        if (!block || reinterpret_cast<std::uintptr_t>(block) % 16 != 0)
            return false;
        std::memset(block, 0x6b, 8192);
        if (&block == &blocks[6] && pool.GetFootprint().chunks != 1) return false;
    }
    auto footprint = pool.GetFootprint();
    if (footprint.chunks != 2 || footprint.mapped_bytes != 2 * kThreadPoolChunkBytes ||
        footprint.direct_bytes != 0 || footprint.idle_bytes != 0)
        return false;
    pool.Deallocate(blocks[1], 8192, 16);
    void* reused = pool.Allocate(8192, 16);
    if (reused != blocks[1] || pool.GetFootprint().chunks != 2)
        return false;
    blocks[1] = reused;
    std::memset(reused, 0xa7, 8192);
    for (auto* block : blocks) {
        const auto* bytes = static_cast<const std::uint8_t*>(block);
        for (std::size_t i = 0; i < 8192; ++i)
            if (bytes[i] != (block == reused ? 0xa7 : 0x6b)) return false;
        pool.Deallocate(block, 8192, 16);
    }
    footprint = pool.GetFootprint();
    if (footprint.idle_bytes != 2 * kThreadPoolChunkBytes || footprint.direct_bytes != 0)
        return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    pool.Purge();
    if (pool.GetFootprint().mapped_bytes != 0 || pool.GetFootprint().chunks != 0)
        return false;

    // All other large stride classes still map actual-size direct allocations.
    for (auto size : {std::size_t{4000}, std::size_t{6000}, std::size_t{19000}}) {
        void* direct = pool.Allocate(size, 16);
        footprint = pool.GetFootprint();
        if (!direct || footprint.chunks != 1 || footprint.direct_bytes != footprint.mapped_bytes ||
            footprint.idle_bytes != 0 ||
            (size == 6000 && footprint.mapped_bytes > 2 * 4096))
            return false;
        pool.Deallocate(direct, size, 16);
        if (pool.GetFootprint().mapped_bytes != 0 || pool.GetFootprint().idle_bytes != 0)
            return false;
    }
    return true;
}

bool RunLargeClass() {
    using namespace acpp::memory;
    ReturningThreadPool pool;
    constexpr size_t bytes = 17 * 1024;
    std::array<void*, 6> blocks{};
    for (size_t i = 0; i < blocks.size(); ++i) {
        blocks[i] = pool.Allocate(bytes, 16);
        if (!blocks[i]) return false;
        std::memset(blocks[i], 0x5a, bytes);
        if (pool.GetFootprint().chunks != (i / 3) + 1 ||
            pool.GetFootprint().direct_bytes != 0) return false;
    }
    // A live buffer pins its own chunk only, not unrelated empty chunks.
    for (size_t i : {0, 1, 2, 4, 5}) pool.Deallocate(blocks[i], bytes, 16);
    if (pool.GetFootprint().idle_bytes != kThreadPoolChunkBytes) return false;
    std::this_thread::sleep_for(kThreadPoolPurgeDelay + std::chrono::milliseconds(5));
    pool.Purge();
    if (pool.GetFootprint().mapped_bytes != kThreadPoolChunkBytes ||
        pool.GetFootprint().idle_bytes != 0) return false;
    for (size_t i = 0; i < bytes; ++i)
        if (static_cast<const unsigned char*>(blocks[3])[i] != 0x5a) return false;
    void* first = pool.Allocate(bytes, 16);
    void* second = pool.Allocate(bytes, 16);
    if (!first || !second || first == second ||
        (first != blocks[4] && first != blocks[5]) ||
        (second != blocks[4] && second != blocks[5]) ||
        pool.GetFootprint().chunks != 1) return false;
    pool.Deallocate(first, bytes, 16);
    pool.Deallocate(second, bytes, 16);
    pool.Deallocate(blocks[3], bytes, 16);
    std::this_thread::sleep_for(kThreadPoolPurgeDelay + std::chrono::milliseconds(5));
    pool.Purge();
    if (pool.GetFootprint().mapped_bytes != 0) return false;
    // Over-aligned requests must retain the direct-allocation fallback.
    void* aligned = pool.Allocate(bytes, 4096);
    if (!aligned || reinterpret_cast<uintptr_t>(aligned) % 4096 ||
        pool.GetFootprint().direct_bytes == 0) return false;
    pool.Deallocate(aligned, bytes, 4096);
    return pool.GetFootprint().mapped_bytes == 0;
}

bool RunBufferIntegration() {
    using acpp::buf::Buffer;
    auto& pool = acpp::memory::ThreadPool();
    std::array<Buffer*, 8> blocks{};
    for (auto& block : blocks) {
        block = Buffer::New();
        if (!block || reinterpret_cast<std::uintptr_t>(block) % alignof(Buffer) != 0)
            return false;
        std::memset(block->data, 0x5a, Buffer::kSize);
        block->Produce(1);
        if (&block == &blocks[6] && pool.GetFootprint().chunks != 1) return false;
    }
    auto footprint = pool.GetFootprint();
    if (footprint.chunks != 2 ||
        footprint.mapped_bytes != 2 * acpp::memory::kThreadPoolChunkBytes ||
        footprint.direct_bytes != 0)
        return false;
    Buffer* freed = blocks[1];
    Buffer::Free(freed);
    blocks[1] = Buffer::New();
    if (blocks[1] != freed || blocks[1]->Len() != 0 || blocks[1]->HasUDP())
        return false;
    for (auto* block : blocks) {
        if (block != freed) {
            for (auto byte : block->data)
                if (byte != 0x5a) return false;
        }
        Buffer::Free(block);
    }
    if (pool.GetFootprint().idle_bytes != 2 * acpp::memory::kThreadPoolChunkBytes)
        return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    pool.Purge();
    return pool.GetFootprint().mapped_bytes == 0 && pool.GetFootprint().chunks == 0;
}

bool RunIdleAccounting() {
    using acpp::memory::kThreadPoolChunkBytes;
    using acpp::memory::kThreadPoolPurgeDelay;

    // A pool with no idle chunks can become idle later and must still return
    // that chunk after its original idle delay.
    {
        acpp::memory::ReturningThreadPool pool;
        void* block = pool.Allocate(128, 16);
        if (!block || pool.GetFootprint().idle_bytes != 0) return false;
        pool.Deallocate(block, 128, 16);
        if (pool.GetFootprint().idle_bytes != kThreadPoolChunkBytes) return false;
        std::this_thread::sleep_for(kThreadPoolPurgeDelay + std::chrono::milliseconds(5));
        // Exercise the automatic Allocate path without Purge() resetting the
        // deadline. A different class cannot consume the old idle chunk.
        void* next = pool.Allocate(8192, 16);
        if (!next || pool.GetFootprint().chunks != 1 ||
            pool.GetFootprint().idle_bytes != 0) return false;
        pool.Deallocate(next, 8192, 16);
        std::this_thread::sleep_for(kThreadPoolPurgeDelay + std::chrono::milliseconds(5));
        pool.Purge();
        if (pool.GetFootprint().mapped_bytes != 0 || pool.GetFootprint().idle_bytes != 0)
            return false;
    }

    // Purging an expired idle chunk must not release a different live chunk.
    {
        acpp::memory::ReturningThreadPool pool;
        void* idle = pool.Allocate(128, 16);
        void* live = pool.Allocate(8192, 16);
        if (!idle || !live || pool.GetFootprint().chunks != 2) return false;
        std::memset(live, 0xa5, 8192);
        pool.Deallocate(idle, 128, 16);
        std::this_thread::sleep_for(kThreadPoolPurgeDelay + std::chrono::milliseconds(5));
        pool.Purge();
        const auto footprint = pool.GetFootprint();
        if (footprint.chunks != 1 || footprint.mapped_bytes != kThreadPoolChunkBytes ||
            footprint.idle_bytes != 0 || footprint.direct_bytes != 0)
            return false;
        for (std::size_t i = 0; i < 8192; ++i)
            if (static_cast<const std::uint8_t*>(live)[i] != 0xa5) return false;
        pool.Deallocate(live, 8192, 16);
    }

    // Reusing the final idle chunk removes it from idle accounting; returning
    // its last live allocation adds it back exactly once.
    {
        acpp::memory::ReturningThreadPool pool;
        void* block = pool.Allocate(128, 16);
        if (!block) return false;
        pool.Deallocate(block, 128, 16);
        if (pool.GetFootprint().idle_bytes != kThreadPoolChunkBytes) return false;
        void* reused = pool.Allocate(128, 16);
        auto footprint = pool.GetFootprint();
        if (!reused || footprint.chunks != 1 || footprint.idle_bytes != 0) return false;
        pool.Deallocate(reused, 128, 16);
        footprint = pool.GetFootprint();
        if (footprint.chunks != 1 || footprint.idle_bytes != kThreadPoolChunkBytes)
            return false;
    }
    return true;
}

bool RunIdleQueue() {
    using acpp::memory::kThreadPoolChunkBytes;
    using acpp::memory::kThreadPoolPurgeDelay;
    acpp::memory::ReturningThreadPool pool;
    std::array<void*, 3> blocks{};
    constexpr std::array<size_t, 3> sizes{64, 256, 1024};
    for (size_t i = 0; i < blocks.size(); ++i) {
        blocks[i] = pool.Allocate(sizes[i], 16);
        if (!blocks[i]) return false;
    }
    for (size_t i = 0; i < blocks.size(); ++i) pool.Deallocate(blocks[i], sizes[i], 16);
    if (pool.GetFootprint().idle_bytes != 3 * kThreadPoolChunkBytes) return false;
    size_t remaining = 3;
    // Reuse the middle, then head, then tail of the idle FIFO.
    for (size_t i : {1, 0, 2}) {
        blocks[i] = pool.Allocate(sizes[i], 16);
        if (!blocks[i] || pool.GetFootprint().idle_bytes != --remaining * kThreadPoolChunkBytes)
            return false;
        std::memset(blocks[i], 0x5a, sizes[i]);
    }
    pool.Deallocate(blocks[0], sizes[0], 16);
    std::this_thread::sleep_for(kThreadPoolPurgeDelay + std::chrono::milliseconds(5));
    // A new idle transition must expire the old head but keep its own deadline.
    pool.Deallocate(blocks[1], sizes[1], 16);
    if (pool.GetFootprint().chunks != 2 ||
        pool.GetFootprint().idle_bytes != kThreadPoolChunkBytes) return false;
    for (size_t i = 0; i < sizes[2]; ++i)
        if (static_cast<uint8_t*>(blocks[2])[i] != 0x5a) return false;
    pool.Deallocate(blocks[2], sizes[2], 16);
    std::this_thread::sleep_for(kThreadPoolPurgeDelay + std::chrono::milliseconds(5));
    pool.Purge();
    if (pool.GetFootprint().chunks != 0 || pool.GetFootprint().idle_bytes != 0) return false;
    // Empty-to-nonempty after purging must not retain dangling FIFO links.
    auto* again = pool.Allocate(256, 16);
    if (!again) return false;
    pool.Deallocate(again, 256, 16);
    return pool.GetFootprint().chunks == 1 && pool.GetFootprint().idle_bytes == kThreadPoolChunkBytes;
}

bool RunPmr() {
    for (auto alignment : {std::size_t{8}, std::size_t{64}, std::size_t{4096}}) {
        void* block = acpp::memory::AllocatePmr(8192, alignment);
        if (!block || reinterpret_cast<std::uintptr_t>(block) % alignment != 0)
            return false;
        std::memset(block, 0xa5, 8192);
        acpp::memory::DeallocatePmr(block);
    }
    // Include the PMR ownership prefix, not just raw pool slot headers.
    std::array<void*, 3> records{};
    for (auto& record : records) {
        record = acpp::memory::AllocatePmr(17 * 1024);
        if (!record || acpp::memory::ThreadPool().GetFootprint().direct_bytes != 0) return false;
        std::memset(record, 0x6b, 17 * 1024);
    }
    for (auto* record : records) acpp::memory::DeallocatePmr(record);
    return acpp::memory::AllocatePmr(std::numeric_limits<std::size_t>::max(), 16) == nullptr;
}

bool RunAll() {
    struct Case { const char* name; bool (*run)(); };
    for (const auto& test : std::array{
             Case{"pool", RunPool}, Case{"fragmented", RunFragmented},
             Case{"mixed", RunMixed}, Case{"9KiB class", RunHotClass},
             Case{"17KiB payload class", RunLargeClass}, Case{"Buffer", RunBufferIntegration},
             Case{"idle accounting", RunIdleAccounting}, Case{"idle FIFO", RunIdleQueue},
             Case{"PMR prefix", RunPmr}}) {
        if (!test.run()) {
            std::fprintf(stderr, "pool case failed: %s\n", test.name);
            return false;
        }
    }
    return true;
}

} // namespace

int main() {
    bool worker = false;
    std::thread thread([&worker] { worker = RunAll(); });
    thread.join();
    const bool main_thread = RunAll();
    std::printf("pool same-thread direct/reuse/alignment/purge/Buffer: %s\n",
                worker && main_thread ? "PASS" : "FAIL");
    return worker && main_thread ? 0 : 1;
}
