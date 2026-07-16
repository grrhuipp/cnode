#pragma once

#include "acppnode/common/asio_types.hpp"

#include <algorithm>
#include <vector>

namespace acpp {

class CancelableTimerRegistry {
public:
    class Registration {
    public:
        Registration(
            CancelableTimerRegistry& registry,
            net::steady_timer& timer)
            : registry_(registry)
            , timer_(&timer) {
            registry_.timers_.push_back(timer_);
        }

        ~Registration() {
            const auto entry = std::ranges::find(registry_.timers_, timer_);
            if (entry != registry_.timers_.end()) {
                registry_.timers_.erase(entry);
            }
        }

        Registration(const Registration&) = delete;
        Registration& operator=(const Registration&) = delete;
        Registration(Registration&&) = delete;
        Registration& operator=(Registration&&) = delete;

    private:
        CancelableTimerRegistry& registry_;
        net::steady_timer* timer_;
    };

    void CancelAll() noexcept {
        for (net::steady_timer* timer : timers_) {
            IoErrorCode ignored;
            timer->cancel(ignored);
        }
    }

private:
    std::vector<net::steady_timer*> timers_;
};

}  // namespace acpp
