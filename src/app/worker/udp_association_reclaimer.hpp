#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <string_view>

namespace acpp::worker_detail {

class UdpIngress;
struct ClientSessionKey;

struct UdpAssociationHook final {
    UdpAssociationHook* previous = nullptr;
    UdpAssociationHook* next = nullptr;
    UdpIngress* owner = nullptr;
    uint64_t last_batch_generation = 0;
    std::string_view socket_key;
    const ClientSessionKey* client_key = nullptr;
    std::chrono::seconds idle_timeout{};
};

// Worker-local bounded scan over association rows embedded in UdpIngress maps.
class UdpAssociationReclaimer final : public memory::ThreadAllocated, private TimeoutEvent {
public:
    UdpAssociationReclaimer(TimeoutScheduler& scheduler,
        std::function<void(std::exception_ptr)> on_failure) noexcept;
    ~UdpAssociationReclaimer() noexcept;
    UdpAssociationReclaimer(const UdpAssociationReclaimer&) = delete;
    UdpAssociationReclaimer& operator=(const UdpAssociationReclaimer&) = delete;

    void Register(UdpAssociationHook& hook, UdpIngress& owner,
                  std::string_view socket_key, const ClientSessionKey& client_key,
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
    void OnTimeout() noexcept override;
    void Schedule() noexcept;
    void RunBatch() noexcept;

    TimeoutScheduler& scheduler_;
    std::function<void(std::exception_ptr)> on_failure_;
    UdpAssociationHook* head_ = nullptr;
    UdpAssociationHook* cursor_ = nullptr;
    bool stopped_ = false;
    bool failed_ = false;
    size_t rows_ = 0;
    uint64_t batch_generation_ = 0;
    size_t last_batch_checks_ = 0;
    size_t max_batch_checks_ = 0;
};

} // namespace acpp::worker_detail
