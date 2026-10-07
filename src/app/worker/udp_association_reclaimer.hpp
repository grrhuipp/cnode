#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace acpp::worker_detail {

class UdpIngress;

struct UdpAssociationHook final {
    UdpAssociationHook* previous = nullptr;
    UdpAssociationHook* next = nullptr;
    UdpIngress* owner = nullptr;
    uint64_t last_batch_generation = 0;
    std::string_view socket_key;
    std::string_view client_key;
    std::chrono::seconds idle_timeout{};
};

// Worker-local bounded scan over association rows embedded in UdpIngress maps.
class UdpAssociationReclaimer final : public memory::ThreadAllocated {
public:
    explicit UdpAssociationReclaimer(TimeoutScheduler& scheduler) noexcept;
    ~UdpAssociationReclaimer() noexcept;
    UdpAssociationReclaimer(const UdpAssociationReclaimer&) = delete;
    UdpAssociationReclaimer& operator=(const UdpAssociationReclaimer&) = delete;

    void Register(UdpAssociationHook& hook, UdpIngress& owner,
                  std::string_view socket_key, std::string_view client_key,
                  std::chrono::seconds idle_timeout) noexcept;
    void Unregister(UdpAssociationHook& hook) noexcept;
    void Stop() noexcept;

    struct Stats {
        size_t rows = 0;
        size_t last_batch_checks = 0;
        size_t max_batch_checks = 0;
    };
    // Owner-thread-only cold-path observation for tests and diagnostics.
    [[nodiscard]] Stats GetStats() const noexcept;

private:
    static void Tick(void* owner) noexcept;
    void Schedule() noexcept;
    void RunBatch() noexcept;

    TimeoutScheduler& scheduler_;
    UdpAssociationHook* head_ = nullptr;
    UdpAssociationHook* cursor_ = nullptr;
    TimeoutToken token_;
    bool stopped_ = false;
    size_t rows_ = 0;
    uint64_t batch_generation_ = 0;
    size_t last_batch_checks_ = 0;
    size_t max_batch_checks_ = 0;
};

} // namespace acpp::worker_detail
