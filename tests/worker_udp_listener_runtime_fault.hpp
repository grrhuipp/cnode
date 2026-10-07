#pragma once

#include "acppnode/common/allocator.hpp"

#include <asio/detail/memory.hpp>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#ifdef _WIN32
#include <malloc.h>
#endif

namespace worker_udp_listener_runtime_test {

enum class FaultKind { None, Standard, Pmr };
struct FaultState {
    const char* stage = nullptr;
    int stage_index = -1;
    FaultKind kind = FaultKind::None;
    std::size_t allocation_budget = 0;
    std::size_t hooks_after_arm = 0;
    bool armed = false;
    bool consumed = false;
    std::size_t rejected_before = 0;
    bool preparation_finished = false;
    std::size_t maintenance_attempts = 0;
};
inline thread_local FaultState fault;

inline void Configure(const char* stage, int stage_index, FaultKind kind,
                      std::size_t allocation_budget = 0) noexcept {
    fault = {stage, stage_index, kind, allocation_budget, 0, false, false,
             acpp::memory::rejected_pmr_allocations};
}

inline void OnStage(const char* stage, int index) noexcept {
    if (!fault.stage || fault.armed || fault.consumed ||
        fault.stage_index != index || std::strcmp(fault.stage, stage) != 0) return;
    fault.armed = true;
    std::fprintf(stderr, "udp-listener-fault stage=%s index=%d budget=%zu armed=1\n",
                 stage, index, fault.allocation_budget);
    std::fflush(stderr);
    if (fault.kind == FaultKind::Pmr)
        acpp::memory::reject_next_pmr_allocation = true;
}

inline void CheckStandardAllocation() {
    if (!fault.armed || fault.kind != FaultKind::Standard) return;
    const std::size_t hook = fault.hooks_after_arm++;
    if (hook != fault.allocation_budget) return;
    fault.armed = false;
    fault.consumed = true;
    std::fprintf(stderr,
                 "udp-listener-fault consumed=std-new hook=%zu budget=%zu\n",
                 hook, fault.allocation_budget);
    std::fflush(stderr);
    throw std::bad_alloc();
}

inline void ReportPmrConsumption() noexcept {
    if (fault.kind != FaultKind::Pmr || fault.consumed) return;
    const auto rejected = acpp::memory::rejected_pmr_allocations - fault.rejected_before;
    if (rejected == 0) return;
    fault.armed = false;
    fault.consumed = true;
    std::fprintf(stderr, "udp-listener-fault consumed=pmr rejected=%zu\n", rejected);
    std::fflush(stderr);
}

inline void FinishPreparation() noexcept {
    if (!fault.stage || std::strcmp(fault.stage, "prepare-listener") != 0) return;
    fault.preparation_finished = true;
    fault.armed = false;
    std::fprintf(stderr, "udp-listener-prepare-window completed hooks=%zu\n", fault.hooks_after_arm);
    std::fflush(stderr);
}

inline void ReportMaintenanceRearm() noexcept {
    if (!fault.stage || std::strcmp(fault.stage, "udp-maintenance") != 0) return;
    std::fprintf(stderr, "udp-maintenance-rearm begun=1\n");
    std::fflush(stderr);
}

inline void OnMaintenanceSchedule() noexcept {
    OnStage("udp-maintenance", static_cast<int>(fault.maintenance_attempts++));
}

inline void ReportSuccessfulSpawn(std::size_t index) noexcept {
    if (!fault.stage || (std::strcmp(fault.stage, "spawn") != 0 &&
                         std::strcmp(fault.stage, "ready") != 0)) return;
    std::fprintf(stderr, "udp-listener-runtime spawn-started index=%zu\n", index);
    std::fflush(stderr);
}

inline void* AllocateStandard(std::size_t size) {
    CheckStandardAllocation();
    if (void* p = std::malloc(size == 0 ? 1 : size)) return p;
    throw std::bad_alloc();
}
inline void* AllocateAligned(std::size_t alignment, std::size_t size) {
    CheckStandardAllocation();
    if (alignment < alignof(void*)) alignment = alignof(void*);
    void* p = nullptr;
    const std::size_t bytes = size == 0 ? 1 : size;
#if defined(_WIN32)
    p = _aligned_malloc(bytes, alignment);
#else
    if (::posix_memalign(&p, alignment, bytes) != 0) p = nullptr;
#endif
    if (!p) throw std::bad_alloc();
    return p;
}
inline void DeallocateAligned(void* p) noexcept {
#if defined(_WIN32)
    _aligned_free(p);
#else
    std::free(p);
#endif
}

}  // namespace worker_udp_listener_runtime_test

namespace asio::detail {
inline void* WorkerUdpListenerRuntimeAlignedNew(std::size_t alignment,
                                                 std::size_t size) {
    return worker_udp_listener_runtime_test::AllocateAligned(alignment, size);
}
}  // namespace asio::detail

#define aligned_new WorkerUdpListenerRuntimeAlignedNew
