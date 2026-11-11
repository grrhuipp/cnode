#include <gtest/gtest.h>

#include "transport/async_stream.hpp"
#include "transport/internet/tcp_stream.hpp"

#include <chrono>
#include <memory>
#include <stdexcept>

namespace {
using namespace std::chrono_literals;

// Exercise the real AsyncStream capability dispatch and Worker scheduler, with
// a shared physical transport and independently observable logical cancellation.
class LogicalStream final : public ::AsyncStream {
public:
    LogicalStream(::net::io_context& io, ::TcpStream& physical, int& cancellations)
        : physical_(physical), cancellations_(cancellations),
          deadline_(io, *this) {}

    ::net::awaitable<std::size_t> AsyncRead(::net::mutable_buffer) override {
        throw std::logic_error("deadline test does not perform byte reads");
    }
    ::net::awaitable<std::size_t> AsyncWrite(::net::const_buffer) override {
        throw std::logic_error("deadline test does not perform byte writes");
    }
    ::net::awaitable<::buf::MultiBuffer> ReadMultiBuffer() override {
        throw std::logic_error("deadline test does not perform buffer reads");
    }
    void ShutdownWrite() override { Close(); }
    void Cancel() noexcept override {
        ++cancellations_;
        NotifyCancellation();
    }
    void Close() override {
        ClearPhaseDeadline();
        open_ = false;
        NotifyClosed();
    }
    int NativeHandle() const override { return physical_.NativeHandle(); }
    bool IsOpen() const override { return open_; }

protected:
    ::StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }
    ::TcpStream* BaseTcpStream() override { return &physical_; }

private:
    ::TcpStream& physical_;
    int& cancellations_;
    ::StreamPhaseDeadline deadline_;
    bool open_ = true;
};

struct CancellationObserver final : ::transport::CancellationSubscription {
    explicit CancellationObserver(int& notifications) noexcept : notifications(notifications) {}
    int& notifications;
private:
    void OnCancellation(::transport::Cancellation) noexcept override {
        ++notifications;
    }
};

TEST(PhaseDeadline, ClearingOneLogicalDeadlineDoesNotCancelItsSiblingOrPhysicalStream) {
    ::net::io_context io;
    ::TcpStream physical(::tcp::socket(io, ::tcp::v4()));
    auto& scheduler = ::TimeoutScheduler::ForIoContext(io);
    int first_cancelled = 0, second_cancelled = 0;
    LogicalStream first(io, physical, first_cancelled);
    LogicalStream second(io, physical, second_cancelled);
    ::AsyncStream& first_control = first;
    ::AsyncStream& second_control = second;
    int physical_notifications = 0, first_notifications = 0, second_notifications = 0;
    CancellationObserver physical_observer(physical_notifications);
    CancellationObserver first_observer(first_notifications);
    CancellationObserver second_observer(second_notifications);
    physical_observer.Resubscribe(physical.Cancellation());
    first_observer.Resubscribe(first_control.Cancellation());
    second_observer.Resubscribe(second_control.Cancellation());

    const auto physical_phase = physical.StartPhaseDeadline(1h);
    const auto first_phase = first_control.StartPhaseDeadline(1s);
    const auto second_phase = second_control.StartPhaseDeadline(1s);
    ASSERT_TRUE(physical_phase);
    ASSERT_TRUE(first_phase);
    ASSERT_TRUE(second_phase);
    EXPECT_EQ(scheduler.GetResourceStats().active_events, 3u);
    first_control.ClearPhaseDeadline();
    EXPECT_EQ(scheduler.GetResourceStats().active_events, 2u);
    io.run_for(1500ms);
    EXPECT_EQ(first_cancelled, 0);
    EXPECT_EQ(second_cancelled, 1);
    EXPECT_EQ(physical_notifications, 0);
    EXPECT_EQ(first_notifications, 0);
    EXPECT_EQ(second_notifications, 1);
    EXPECT_FALSE(first_phase.Expired());
    EXPECT_TRUE(second_phase.Expired());
    EXPECT_FALSE(physical_phase.Expired());
    EXPECT_TRUE(physical.IsOpen());
    EXPECT_EQ(scheduler.GetResourceStats().active_events, 1u);
    EXPECT_FALSE(first_control.ConsumePhaseDeadline());
    EXPECT_TRUE(second_control.ConsumePhaseDeadline());
    EXPECT_FALSE(second_control.ConsumePhaseDeadline());
    EXPECT_FALSE(second_phase.Expired());
    second_control.ClearPhaseDeadline();
    EXPECT_EQ(scheduler.GetResourceStats().active_events, 1u);
    physical.ClearPhaseDeadline();
    EXPECT_EQ(scheduler.GetResourceStats().active_events, 0u);
}

TEST(PhaseDeadline, ReplacingDeadlineInvalidatesOldTokensAndSaturatesMaximumDuration) {
    ::net::io_context io;
    ::TcpStream physical(::tcp::socket(io, ::tcp::v4()));
    int cancellations = 0;
    LogicalStream stream(io, physical, cancellations);
    ::AsyncStream& control = stream;
    const auto old = control.StartPhaseDeadline(1s);
    const auto maximum = control.StartPhaseDeadline(std::chrono::seconds::max());
    ASSERT_TRUE(old);
    ASSERT_TRUE(maximum);
    io.run_for(1100ms);
    EXPECT_EQ(cancellations, 0);
    EXPECT_FALSE(old.Expired());
    EXPECT_FALSE(maximum.Expired());
    const auto current = control.StartPhaseDeadline(1s);
    io.restart();
    io.run_for(1500ms);
    EXPECT_TRUE(current.Expired());
    EXPECT_FALSE(old.Expired());
    EXPECT_FALSE(maximum.Expired());
    EXPECT_EQ(cancellations, 1);
    control.ClearPhaseDeadline();
    EXPECT_FALSE(current.Expired());
    EXPECT_FALSE(control.ConsumePhaseDeadline());
}

class DisabledPhaseDeadline : public ::testing::TestWithParam<int> {};

TEST_P(DisabledPhaseDeadline, NonPositiveDurationClearsAnArmedDeadline) {
    ::net::io_context io;
    ::TcpStream physical(::tcp::socket(io, ::tcp::v4()));
    int cancellations = 0;
    LogicalStream stream(io, physical, cancellations);
    ::AsyncStream& control = stream;
    ASSERT_TRUE(control.StartPhaseDeadline(1h));
    EXPECT_FALSE(control.StartPhaseDeadline(std::chrono::seconds(GetParam())));
    EXPECT_EQ(::TimeoutScheduler::ForIoContext(io).GetResourceStats().active_events, 0u);
    io.poll();
    EXPECT_EQ(cancellations, 0);
}

INSTANTIATE_TEST_SUITE_P(ZeroAndNegativeDuration, DisabledPhaseDeadline,
                        ::testing::Values(0, -1));

TEST(PhaseDeadline, ClosedLogicalStreamRejectsDeadlineWithoutClosingPhysicalStream) {
    ::net::io_context io;
    ::TcpStream physical(::tcp::socket(io, ::tcp::v4()));
    int cancellations = 0;
    LogicalStream stream(io, physical, cancellations);
    ::AsyncStream& control = stream;
    ASSERT_TRUE(control.StartPhaseDeadline(1h));
    control.Close();
    EXPECT_FALSE(control.StartPhaseDeadline(1s));
    EXPECT_EQ(::TimeoutScheduler::ForIoContext(io).GetResourceStats().active_events, 0u);
    EXPECT_TRUE(physical.IsOpen());
}

TEST(PhaseDeadline, DestructionCancelsOnlyOwnedEvent) {
    ::net::io_context io;
    ::TcpStream physical(::tcp::socket(io, ::tcp::v4()));
    auto& scheduler = ::TimeoutScheduler::ForIoContext(io);
    int destroyed_cancellations = 0, survivor_cancellations = 0;
    {
        LogicalStream survivor(io, physical, survivor_cancellations);
        auto destroyed = std::make_unique<LogicalStream>(io, physical, destroyed_cancellations);
        ASSERT_TRUE(destroyed->StartPhaseDeadline(1s));
        ASSERT_TRUE(survivor.StartPhaseDeadline(1s));
        EXPECT_EQ(scheduler.GetResourceStats().active_events, 2u);
        destroyed.reset();
        EXPECT_EQ(scheduler.GetResourceStats().active_events, 1u);
        io.run_for(1500ms);
        EXPECT_EQ(destroyed_cancellations, 0);
        EXPECT_EQ(survivor_cancellations, 1);
        EXPECT_TRUE(survivor.ConsumePhaseDeadline());
        ASSERT_TRUE(survivor.StartPhaseDeadline(std::chrono::seconds::max()));
    }
    io.restart();
    io.poll();
    EXPECT_EQ(destroyed_cancellations, 0);
    EXPECT_EQ(survivor_cancellations, 1);
    EXPECT_EQ(scheduler.GetResourceStats().active_events, 0u);
}
}  // namespace

