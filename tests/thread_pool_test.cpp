#include "acppnode/common/allocator.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <thread>

namespace {

bool RunPool() {
    acpp::memory::ReturningThreadPool pool;
    constexpr std::array<std::size_t, 10> sizes{
        1, 64, 128, 2048, 4000, 4096, 8192, 16384, 32768, 65536};
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

bool RunPmr() {
    for (auto alignment : {std::size_t{8}, std::size_t{64}, std::size_t{4096}}) {
        void* block = acpp::memory::AllocatePmr(8192, alignment);
        if (!block || reinterpret_cast<std::uintptr_t>(block) % alignment != 0)
            return false;
        std::memset(block, 0xa5, 8192);
        acpp::memory::DeallocatePmr(block);
    }
    return acpp::memory::AllocatePmr(std::numeric_limits<std::size_t>::max(), 16) == nullptr;
}

} // namespace

int main() {
    bool worker = false;
    std::thread thread([&worker] { worker = RunPool() && RunFragmented() && RunMixed() && RunPmr(); });
    thread.join();
    const bool main_thread = RunPool() && RunFragmented() && RunMixed() && RunPmr();
    std::printf("pool same-thread direct/reuse/alignment/purge: %s\n",
                worker && main_thread ? "PASS" : "FAIL");
    return worker && main_thread ? 0 : 1;
}
