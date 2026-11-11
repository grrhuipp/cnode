#include <gtest/gtest.h>
#include "transport/internet/connection_timeouts.hpp"
#include <chrono>
#include <memory>

namespace {
using namespace std::chrono_literals;
struct Owner {
    int calls = 0;
    ::common::ErrorCode reason = ::common::ErrorCode::OK;
    void OnTimeout(::common::ErrorCode error) noexcept { ++calls; reason = error; }
};
using Timeouts = ::transport::internet::detail::ConnectionTimeouts<Owner>;

TEST(ConnectionTimeouts, ActivityArmsIdleTimeoutAfterCompletedWrite) {
    ::net::io_context io;
    Owner owner;
    Timeouts timeouts(io, owner);
    timeouts.SetIdleTimeout(1s);
    timeouts.BeginWrite();
    timeouts.EndWrite();
    timeouts.TouchActivity();
    io.run_for(1100ms);
    EXPECT_EQ(owner.calls, 1);
    EXPECT_EQ(owner.reason, ::common::ErrorCode::CANCELLED);
    EXPECT_TRUE(timeouts.ConsumeIdleTimeout());
    EXPECT_FALSE(timeouts.ConsumeWriteTimeout());
}

TEST(ConnectionTimeouts, ReadTimeoutSurvivesPhaseReplacementAndClear) {
    ::net::io_context io;
    Owner owner;
    Timeouts timeouts(io, owner);
    auto old = timeouts.StartPhaseDeadline(1s);
    auto current = timeouts.StartPhaseDeadline(2s);
    EXPECT_TRUE(old);
    EXPECT_TRUE(current);
    EXPECT_FALSE(old.Expired());
    EXPECT_FALSE(current.Expired());
    timeouts.ClearPhaseDeadline();
    EXPECT_FALSE(current.Expired());
    EXPECT_FALSE(timeouts.ConsumePhaseDeadline());
    timeouts.SetReadTimeout(1s);
    timeouts.BeginRead();
    auto later_phase = timeouts.StartPhaseDeadline(2s);
    io.run_for(1100ms);
    EXPECT_EQ(owner.calls, 1);
    EXPECT_TRUE(later_phase);
    EXPECT_FALSE(later_phase.Expired());
    EXPECT_TRUE(timeouts.ConsumeReadTimeout());
    EXPECT_FALSE(timeouts.ConsumePhaseDeadline());
}

TEST(ConnectionTimeouts, StopAndClearInvalidateExpiredPhase) {
    ::net::io_context io;
    Owner owner;
    Timeouts timeouts(io, owner);
    auto phase = timeouts.StartPhaseDeadline(1s);
    io.run_for(1100ms);
    EXPECT_EQ(owner.calls, 1);
    EXPECT_TRUE(timeouts.ConsumePhaseDeadline());
    timeouts.Stop();
    timeouts.ClearPhaseDeadline();
    EXPECT_FALSE(phase.Expired());
    EXPECT_FALSE(timeouts.ConsumePhaseDeadline());
}

TEST(ConnectionTimeouts, DestructionCancelsMaximumDeadlineBeforeOwnerDestruction) {
    ::net::io_context io;
    auto owner = std::make_unique<Owner>();
    auto timeouts = std::make_unique<Timeouts>(io, *owner);
    timeouts->SetIdleTimeout(std::chrono::seconds::max());
    timeouts->BeginRead();
    timeouts.reset();
    io.run_for(10ms);
    EXPECT_EQ(owner->calls, 0);
    owner.reset();
    io.restart();
    io.run_for(10ms);
}

TEST(ConnectionTimeouts, ActivityDoesNotExtendPhaseDeadline) {
    ::net::io_context io;
    Owner owner;
    Timeouts timeouts(io, owner);
    timeouts.SetIdleTimeout(1s);
    auto phase = timeouts.StartPhaseDeadline(1s);
    io.run_for(600ms);
    EXPECT_EQ(owner.calls, 0);
    timeouts.TouchActivity();
    io.restart();
    io.run_for(600ms);
    EXPECT_EQ(owner.calls, 1);
    EXPECT_TRUE(phase.Expired());
    EXPECT_TRUE(timeouts.ConsumePhaseDeadline());
    EXPECT_FALSE(timeouts.ConsumeIdleTimeout());
}
} // namespace
