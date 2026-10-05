#include "../src/transport/internet/connection_timeouts.hpp"

#include <chrono>
#include <cstdio>
#include <memory>

namespace {
using namespace std::chrono_literals;
using Timeouts = acpp::transport::internet::detail::ConnectionTimeouts<struct Owner>;

class SchedulerScope final {
public:
    explicit SchedulerScope(acpp::net::any_io_executor executor)
        : executor_(std::move(executor)) {
        acpp::TimeoutScheduler::Install(executor_);
    }
    ~SchedulerScope() {
        acpp::TimeoutScheduler::ReleaseForExecutor(executor_);
    }
private:
    acpp::net::any_io_executor executor_;
};

struct Owner {
    int calls = 0;
    acpp::ErrorCode reason = acpp::ErrorCode::OK;
    void OnTimeout(acpp::ErrorCode error) noexcept { ++calls; reason = error; }
};

bool TestIdleAndOperations() {
    acpp::net::io_context io;
    SchedulerScope scheduler_scope(io.get_executor());
    Owner owner;
    Timeouts timeouts(io.get_executor(), owner);
    timeouts.SetIdleTimeout(1s);
    timeouts.BeginWrite();
    timeouts.EndWrite();
    timeouts.TouchActivity();
    io.run_for(1100ms);
    return owner.calls == 1 && owner.reason == acpp::ErrorCode::CANCELLED &&
           timeouts.ConsumeIdleTimeout() && !timeouts.ConsumeWriteTimeout();
}

bool TestPhaseReplacementAndClear() {
    acpp::net::io_context io;
    SchedulerScope scheduler_scope(io.get_executor());
    Owner owner;
    Timeouts timeouts(io.get_executor(), owner);
    auto old = timeouts.StartPhaseDeadline(1s);
    auto current = timeouts.StartPhaseDeadline(2s);
    if (!old || !current || old.Expired() || current.Expired()) return false;
    timeouts.ClearPhaseDeadline();
    if (current.Expired() || timeouts.ConsumePhaseDeadline()) return false;
    timeouts.SetReadTimeout(1s);
    timeouts.BeginRead();
    auto later_phase = timeouts.StartPhaseDeadline(2s);
    io.run_for(1100ms);
    return owner.calls == 1 && later_phase && !later_phase.Expired() &&
           timeouts.ConsumeReadTimeout() && !timeouts.ConsumePhaseDeadline();
}

bool TestExpiredPhaseAndStopFlag() {
    acpp::net::io_context io;
    SchedulerScope scheduler_scope(io.get_executor());
    Owner owner;
    Timeouts timeouts(io.get_executor(), owner);
    auto phase = timeouts.StartPhaseDeadline(1s);
    io.run_for(1100ms);
    if (owner.calls != 1 || !timeouts.ConsumePhaseDeadline()) return false;
    timeouts.Stop();
    timeouts.ClearPhaseDeadline();
    return !phase.Expired() && !timeouts.ConsumePhaseDeadline();
}

bool TestDestroyOwnerAndMaximumTimeout() {
    acpp::net::io_context io;
    SchedulerScope scheduler_scope(io.get_executor());
    auto owner = std::make_unique<Owner>();
    {
        auto timeouts = std::make_unique<Timeouts>(io.get_executor(), *owner);
        timeouts->SetIdleTimeout(std::chrono::seconds::max());
        timeouts->BeginRead();
        timeouts.reset();
    }
    owner.reset();
    io.run_for(10ms);
    return true;
}
}  // namespace

int main() {
    const bool idle = TestIdleAndOperations();
    const bool phase = TestPhaseReplacementAndClear();
    const bool expired = TestExpiredPhaseAndStopFlag();
    const bool destruction = TestDestroyOwnerAndMaximumTimeout();
    std::printf("connection timeouts: idle=%d phase=%d expired=%d destruction=%d\n",
                idle, phase, expired, destruction);
    return idle && phase && expired && destruction ? 0 : 1;
}
