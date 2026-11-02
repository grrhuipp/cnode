#include <asio/detail/thread_info_base.hpp>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace {
// The linker redirects aligned_alloc after compilation. Volatile prevents
// the optimizer assuming this private counter is unchanged by the libc call.
thread_local volatile size_t system_allocations = 0;
}
#if defined(CNODE_WRAP_ALIGNED_ALLOC)
extern "C" void* __real_aligned_alloc(size_t alignment, size_t size);
extern "C" void* __wrap_aligned_alloc(size_t alignment, size_t size) {
    system_allocations = system_allocations + 1;
    return __real_aligned_alloc(alignment, size);
}
#endif

namespace {
using Info = asio::detail::thread_info_base;
struct Result { bool ok = true; size_t allocations = 0; };
template<class Purpose>
Result RunPurpose(int rounds) {
    Info info;
    // Emulate completion batches with more short-lived objects than the old
    // eight-slot cache. Do not change Asio's allocator or create another pool.
    constexpr size_t batch = 64;
    constexpr size_t size = 240;
    std::array<void*, batch> blocks{};
    auto cycle = [&] {
        for (auto& p : blocks) {
            p = Info::allocate(Purpose{}, &info, size, 16);
            if (reinterpret_cast<size_t>(p) % 16) return false;
            std::memset(p, 0x5a, size);
        }
        for (auto* p : blocks) {
            for (size_t i = 0; i < size; ++i)
                if (static_cast<unsigned char*>(p)[i] != 0x5a) return false;
            Info::deallocate(Purpose{}, &info, p, size);
        }
        return true;
    };
    const auto cold_before = system_allocations;
    if (!cycle()) return {false, 0};
#if defined(CNODE_WRAP_ALIGNED_ALLOC)
    if (system_allocations - cold_before != batch) {
        std::fprintf(stderr, "aligned_alloc instrumentation did not observe cold allocations\n");
        return {false, 0};
    }
#else
    (void)cold_before;
#endif
    const auto before = system_allocations;
    for (int i = 0; i < rounds; ++i) if (!cycle()) return {false, 0};
    const auto slow = system_allocations - before;
#if defined(CNODE_WRAP_ALIGNED_ALLOC)
    if constexpr (ASIO_RECYCLING_ALLOCATOR_CACHE_SIZE >= batch) {
        if (slow != 0) return {false, slow};
    } else {
        if (slow == 0) return {false, slow};
    }
#endif
    return {true, slow};
}
Result Run(int rounds) {
    const auto frames = RunPurpose<Info::awaitable_frame_tag>(rounds);
    const auto cancellation = RunPurpose<Info::cancellation_signal_tag>(rounds);
    const auto completions = RunPurpose<Info::executor_function_tag>(rounds);
    return {frames.ok && cancellation.ok && completions.ok,
            frames.allocations + cancellation.allocations + completions.allocations};
}
}
int main(int argc, char** argv) {
    const int rounds = argc == 2 && std::strcmp(argv[1], "--benchmark") == 0 ? 2000 : 8;
    std::array<Result, 4> results;
    std::array<std::thread, 4> threads;
    const auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < threads.size(); ++i) threads[i] = std::thread([&, i] { results[i] = Run(rounds); });
    for (auto& thread : threads) thread.join();
    size_t slow = 0;
    for (const auto& result : results) { if (!result.ok) return 1; slow += result.allocations; }
    const auto ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
#if defined(CNODE_WRAP_ALIGNED_ALLOC)
    std::printf("Asio cache=%d threads=4 rounds=%d slow_allocations=%zu elapsed_ms=%.2f PASS\n",
                ASIO_RECYCLING_ALLOCATOR_CACHE_SIZE, rounds, slow, ms);
#else
    (void)slow;
    std::printf("Asio cache=%d threads=4 rounds=%d slow_allocations=unmeasured elapsed_ms=%.2f PASS\n",
                ASIO_RECYCLING_ALLOCATOR_CACHE_SIZE, rounds, ms);
#endif
}
