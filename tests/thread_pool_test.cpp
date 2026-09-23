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
    return true;
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
    std::thread thread([&worker] { worker = RunPool() && RunFragmented() && RunPmr(); });
    thread.join();
    const bool main_thread = RunPool() && RunFragmented() && RunPmr();
    std::printf("pool same-thread direct/reuse/alignment/purge: %s\n",
                worker && main_thread ? "PASS" : "FAIL");
    return worker && main_thread ? 0 : 1;
}
