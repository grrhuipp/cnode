#include <gtest/gtest.h>

#include "../src/transport/internet/connection_timeouts.hpp"

#include <chrono>
#include <cstdio>
#include <memory>

namespace {
using namespace std::chrono_literals;
using Timeouts = ::transport::internet::detail::ConnectionTimeouts<struct Owner>;

struct Owner {
    int calls = 0;
    ::ErrorCode reason = ::ErrorCode::OK;
    void OnTimeout(::ErrorCode error) noexcept { ++calls; reason = error; }
};

bool TestIdleAndOperations() {
    ::net::io_context io;
    Owner owner;
    Timeouts timeouts(io, owner);
    timeouts.SetIdleTimeout(1s);
    timeouts.BeginWrite();
    timeouts.EndWrite();
    timeouts.TouchActivity();
    io.run_for(1100ms);
    return owner.calls == 1 && owner.reason == ::ErrorCode::CANCELLED &&
           timeouts.ConsumeIdleTimeout() && !timeouts.ConsumeWriteTimeout();
}

bool TestPhaseReplacementAndClear() {
    ::net::io_context io;
    Owner owner;
    Timeouts timeouts(io, owner);
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
    ::net::io_context io;
    Owner owner;
    Timeouts timeouts(io, owner);
    auto phase = timeouts.StartPhaseDeadline(1s);
    io.run_for(1100ms);
    if (owner.calls != 1 || !timeouts.ConsumePhaseDeadline()) return false;
    timeouts.Stop();
    timeouts.ClearPhaseDeadline();
    return !phase.Expired() && !timeouts.ConsumePhaseDeadline();
}

bool TestDestroyOwnerAndMaximumTimeout() {
    ::net::io_context io;
    auto owner = std::make_unique<Owner>();
    {
        auto timeouts = std::make_unique<Timeouts>(io, *owner);
        timeouts->SetIdleTimeout(std::chrono::seconds::max());
        timeouts->BeginRead();
        timeouts.reset();
    }
    owner.reset();
    io.run_for(10ms);
    return true;
}

bool TestActivityDoesNotExtendPhase() {
    ::net::io_context io;
    Owner owner;
    Timeouts timeouts(io, owner);
    timeouts.SetIdleTimeout(1s);
    auto phase = timeouts.StartPhaseDeadline(1s);
    io.run_for(600ms);
    if (owner.calls) return false;
    timeouts.TouchActivity();
    io.restart();
    io.run_for(600ms);
    return owner.calls == 1 && phase.Expired() && timeouts.ConsumePhaseDeadline() &&
        !timeouts.ConsumeIdleTimeout();
}
}  // namespace

TEST(ConnectionTimeouts, Contract) {
    const bool idle = TestIdleAndOperations();
    const bool phase = TestPhaseReplacementAndClear();
    const bool expired = TestExpiredPhaseAndStopFlag();
    const bool destruction = TestDestroyOwnerAndMaximumTimeout();
    const bool dual = TestActivityDoesNotExtendPhase();
    std::printf("connection timeouts: idle=%d phase=%d expired=%d destruction=%d dual=%d\n",
                idle, phase, expired, destruction, dual);
    { ASSERT_TRUE(idle && phase && expired && destruction && dual); return; }
}
