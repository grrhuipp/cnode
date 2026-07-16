#pragma once

#include <algorithm>
#include <cstdint>

namespace acpp::app {

// Worker-local request load. Physical transports and dispatcher requests are
// tracked separately because one multiplexed transport may own many requests,
// while a regular TCP request appears in both sets. The larger set is the
// effective load, avoiding double counting without hiding logical substreams.
class RequestLoadState final {
public:
    RequestLoadState(uint32_t pressure_threshold,
                     uint32_t pressure_idle_timeout) noexcept {
        Configure(pressure_threshold, pressure_idle_timeout);
    }

    void Configure(uint32_t pressure_threshold,
                   uint32_t pressure_idle_timeout) noexcept {
        pressure_threshold_ = std::max<uint32_t>(pressure_threshold, 1);
        pressure_idle_timeout_ = pressure_idle_timeout;
    }

    [[nodiscard]] uint32_t ActiveConnections() const noexcept {
        return std::max(physical_connections_, active_dispatches_);
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
            ++state_->physical_connections_;
        }

        ~PhysicalConnectionScope() noexcept {
            --state_->physical_connections_;
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
        explicit DispatchScope(RequestLoadState* state) noexcept
            : state_(state) {
            if (state_) {
                ++state_->active_dispatches_;
            }
        }

        ~DispatchScope() noexcept {
            if (state_) {
                --state_->active_dispatches_;
            }
        }

        DispatchScope(const DispatchScope&) = delete;
        DispatchScope& operator=(const DispatchScope&) = delete;
        DispatchScope(DispatchScope&&) = delete;
        DispatchScope& operator=(DispatchScope&&) = delete;

    private:
        RequestLoadState* state_;
    };

private:
    uint32_t physical_connections_ = 0;
    uint32_t active_dispatches_ = 0;
    uint32_t pressure_threshold_ = 1;
    uint32_t pressure_idle_timeout_ = 0;
};

}  // namespace acpp::app
