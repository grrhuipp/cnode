#pragma once

#include "app/session_group_executor.hpp"

#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <cstdint>

namespace app {

// Process-wide request pressure. Stable shared ownership survives the accepting
// Worker and migration; physical and dispatch counts are not added together.
class RequestLoadState final {
public:
    RequestLoadState(uint32_t pressure_threshold,
                     uint32_t pressure_idle_timeout) noexcept
        : pressure_threshold_(std::max<uint32_t>(pressure_threshold, 1)),
          pressure_idle_timeout_(pressure_idle_timeout) {}

    [[nodiscard]] static std::shared_ptr<RequestLoadState> Acquire(
        uint32_t threshold, uint32_t idle_timeout, GroupCoordinator& coordinator) {
        return net::use_service<Service>(coordinator.Services()).Acquire(
            threshold, idle_timeout);
    }

    [[nodiscard]] uint32_t ActiveConnections() const noexcept {
        return std::max(physical_connections_.load(std::memory_order_relaxed),
                        active_dispatches_.load(std::memory_order_relaxed));
    }

    [[nodiscard]] uint32_t PressureIdleTimeout() const noexcept {
        return ActiveConnections() >= pressure_threshold_
            ? pressure_idle_timeout_
            : 0;
    }

    class PhysicalConnectionScope final {
    public:
        explicit PhysicalConnectionScope(RequestLoadState& state) noexcept
            : state_(&state) {
            state_->physical_connections_.fetch_add(1, std::memory_order_relaxed);
        }

        ~PhysicalConnectionScope() noexcept {
            state_->physical_connections_.fetch_sub(1, std::memory_order_relaxed);
        }

        PhysicalConnectionScope(const PhysicalConnectionScope&) = delete;
        PhysicalConnectionScope& operator=(const PhysicalConnectionScope&) = delete;
        PhysicalConnectionScope(PhysicalConnectionScope&&) = delete;
        PhysicalConnectionScope& operator=(PhysicalConnectionScope&&) = delete;

    private:
        RequestLoadState* state_;
    };

    class DispatchScope final {
    public:
        explicit DispatchScope(RequestLoadState& state) noexcept
            : state_(state) {
            state_.active_dispatches_.fetch_add(1, std::memory_order_relaxed);
        }

        ~DispatchScope() noexcept {
            state_.active_dispatches_.fetch_sub(1, std::memory_order_relaxed);
        }

        DispatchScope(const DispatchScope&) = delete;
        DispatchScope& operator=(const DispatchScope&) = delete;
        DispatchScope(DispatchScope&&) = delete;
        DispatchScope& operator=(DispatchScope&&) = delete;

    private:
        RequestLoadState& state_;
    };

private:
    class Service final : public net::execution_context::service {
    public:
        inline static net::execution_context::id id;
        explicit Service(net::execution_context& context) : service(context) {}
        std::shared_ptr<RequestLoadState> Acquire(
            uint32_t threshold, uint32_t idle_timeout) {
            const std::lock_guard lock(mutex_);
            if (auto existing = published_.lock()) return existing;
            auto state = std::make_shared<RequestLoadState>(threshold, idle_timeout);
            published_ = state;
            return state;
        }
    private:
        void shutdown() override {
            const std::lock_guard lock(mutex_);
            published_.reset();
        }
        std::mutex mutex_;
        std::weak_ptr<RequestLoadState> published_;
    };

    std::atomic<uint32_t> physical_connections_{0};
    std::atomic<uint32_t> active_dispatches_{0};
    const uint32_t pressure_threshold_;
    const uint32_t pressure_idle_timeout_;
};

}  // namespace app
