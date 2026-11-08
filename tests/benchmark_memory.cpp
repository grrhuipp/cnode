#include "benchmark_memory.hpp"

#include <cstddef>
#include <exception>
#include <new>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

namespace {
thread_local benchmark::AllocationCounts* active_counts = nullptr;

void CountNew(size_t bytes) noexcept {
    if (!active_counts) return;
    ++active_counts->cpp_calls;
    active_counts->cpp_bytes += bytes;
}
} // namespace

benchmark::AllocationCountScope::AllocationCountScope(AllocationCounts& counts) noexcept
    : counts_(&counts) {
    if (active_counts) std::terminate();
    active_counts = counts_;
}
benchmark::AllocationCountScope::~AllocationCountScope() {
    if (active_counts != counts_) std::terminate();
    active_counts = nullptr;
}

extern "C" void* __real__Znwm(size_t);
extern "C" void* __wrap__Znwm(size_t size) {
    CountNew(size);
    return __real__Znwm(size);
}
extern "C" void* __real__Znam(size_t);
extern "C" void* __wrap__Znam(size_t size) {
    CountNew(size);
    return __real__Znam(size);
}
extern "C" void* __real__ZnwmSt11align_val_t(size_t, std::align_val_t);
extern "C" void* __wrap__ZnwmSt11align_val_t(size_t size, std::align_val_t alignment) {
    CountNew(size);
    return __real__ZnwmSt11align_val_t(size, alignment);
}
extern "C" void* __real__ZnamSt11align_val_t(size_t, std::align_val_t);
extern "C" void* __wrap__ZnamSt11align_val_t(size_t size, std::align_val_t alignment) {
    CountNew(size);
    return __real__ZnamSt11align_val_t(size, alignment);
}
extern "C" void* __real_mi_malloc_aligned(size_t, size_t);
extern "C" void* __wrap_mi_malloc_aligned(size_t size, size_t alignment) {
    if (active_counts) ++active_counts->aligned_calls;
    return __real_mi_malloc_aligned(size, alignment);
}

size_t benchmark::ResidentBytes() {
    auto* file = std::fopen("/proc/self/statm", "r");
    if (!file) throw std::runtime_error("process resident memory unavailable");
    size_t pages = 0;
    const int fields = std::fscanf(file, "%*s %zu", &pages);
    std::fclose(file);
    const auto page_size = ::sysconf(_SC_PAGESIZE);
    if (fields != 1 || page_size <= 0)
        throw std::runtime_error("process resident memory parse failed");
    return pages * static_cast<size_t>(page_size);
}

benchmark::ProcessMemorySnapshot benchmark::ReadProcessMemory() {
    // Unlike getrusage's inherited high-water mark, VmHWM belongs to this exec.
    auto* file = std::fopen("/proc/self/status", "r");
    if (!file) throw std::runtime_error("process memory unavailable");
    ProcessMemorySnapshot result;
    char line[256], field[64];
    size_t kib = 0;
    unsigned found = 0;
    while (std::fgets(line, sizeof(line), file)) {
        if (std::sscanf(line, "%63s %zu kB", field, &kib) != 2) continue;
        if (std::strcmp(field, "VmHWM:") == 0) {
            result.peak_resident_bytes = kib * 1024;
            found |= 1;
        } else if (std::strcmp(field, "RssAnon:") == 0) {
            result.anonymous_resident_bytes = kib * 1024;
            found |= 2;
        } else if (std::strcmp(field, "RssFile:") == 0) {
            result.file_resident_bytes = kib * 1024;
            found |= 4;
        }
        if (found == 7) break;
    }
    std::fclose(file);
    if (found != 7) throw std::runtime_error("process memory parse failed");
    return result;
}
