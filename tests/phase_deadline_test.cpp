#include <gtest/gtest.h>

#include "transport/async_stream.hpp"
#include "transport/internet/tcp_stream.hpp"

#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>

namespace {
using namespace std::chrono_literals;

// Exercise the real AsyncStream capability dispatch and Worker scheduler, with
// a shared physical transport and independently observable logical cancellation.
class LogicalStream final : public ::AsyncStream {
public:
    LogicalStream(::net::io_context& io, ::TcpStream& physical, int& cancellations)
        : physical_(physical), cancellations_(cancellations), deadline_(io, *this) {}

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

    int physical_lookups = 0;

protected:
    ::StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }
    ::TcpStream* BaseTcpStream() override {
        ++physical_lookups;
        return &physical_;
    }

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

bool TestClearAndTimeoutIsolation() {
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
    if (!physical_phase || !first_phase || !second_phase ||
        scheduler.GetResourceStats().active_events != 3) return false;
    first_control.ClearPhaseDeadline();
    if (scheduler.GetResourceStats().active_events != 2) return false;
    io.run_for(1500ms);
    if (first_cancelled != 0 || second_cancelled != 1 || physical_notifications != 0 ||
        first_notifications != 0 || second_notifications != 1 ||
        first_phase.Expired() || !second_phase.Expired() || physical_phase.Expired() ||
        !physical.IsOpen() || scheduler.GetResourceStats().active_events != 1) return false;
    if (first_control.ConsumePhaseDeadline() || !second_control.ConsumePhaseDeadline() ||
        second_control.ConsumePhaseDeadline() || second_phase.Expired()) return false;
    second_control.ClearPhaseDeadline();
    if (scheduler.GetResourceStats().active_events != 1 ||
        first.physical_lookups != 0 || second.physical_lookups != 0) return false;
    physical.ClearPhaseDeadline();
    return scheduler.GetResourceStats().active_events == 0;
}

bool TestReplacementDisabledAndClosed() {
    ::net::io_context io;
    ::TcpStream physical(::tcp::socket(io, ::tcp::v4()));
    auto& scheduler = ::TimeoutScheduler::ForIoContext(io);
    int cancellations = 0;
    LogicalStream stream(io, physical, cancellations);
    ::AsyncStream& control = stream;
    const auto old = control.StartPhaseDeadline(1s);
    const auto maximum = control.StartPhaseDeadline(std::chrono::seconds::max());
    if (!old || !maximum || scheduler.GetResourceStats().active_events != 1) return false;
    io.run_for(1100ms);
    if (cancellations != 0 || old.Expired() || maximum.Expired()) return false;
    const auto current = control.StartPhaseDeadline(1s);
    io.restart();
    io.run_for(1500ms);
    if (!current || !current.Expired() || old.Expired() || maximum.Expired() ||
        cancellations != 1 || scheduler.GetResourceStats().active_events != 0) return false;
    control.ClearPhaseDeadline();
    if (current.Expired() || control.ConsumePhaseDeadline()) return false;
    if (!control.StartPhaseDeadline(1h) || control.StartPhaseDeadline(0s) ||
        scheduler.GetResourceStats().active_events != 0) return false;
    if (!control.StartPhaseDeadline(1h) || control.StartPhaseDeadline(-1s) ||
        scheduler.GetResourceStats().active_events != 0) return false;
    if (!control.StartPhaseDeadline(1h)) return false;
    control.Close();
    return !control.StartPhaseDeadline(1s) &&
           scheduler.GetResourceStats().active_events == 0 && stream.physical_lookups == 0;
}

bool TestDestructionCancelsOnlyOwnedEvent() {
    ::net::io_context io;
    ::TcpStream physical(::tcp::socket(io, ::tcp::v4()));
    auto& scheduler = ::TimeoutScheduler::ForIoContext(io);
    int destroyed_cancellations = 0, survivor_cancellations = 0;
    {
        LogicalStream survivor(io, physical, survivor_cancellations);
        auto destroyed = std::make_unique<LogicalStream>(io, physical, destroyed_cancellations);
        if (!destroyed->StartPhaseDeadline(1s) || !survivor.StartPhaseDeadline(1s) ||
            scheduler.GetResourceStats().active_events != 2) return false;
        destroyed.reset();
        if (scheduler.GetResourceStats().active_events != 1) return false;
        io.run_for(1500ms);
        if (destroyed_cancellations != 0 || survivor_cancellations != 1 ||
            !survivor.ConsumePhaseDeadline()) return false;
        if (!survivor.StartPhaseDeadline(std::chrono::seconds::max())) return false;
    }
    io.restart();
    io.poll();
    const auto stats = scheduler.GetResourceStats();
    return destroyed_cancellations == 0 && survivor_cancellations == 1 &&
           stats.active_events == 0;
}
}  // namespace

TEST(PhaseDeadline, Contract) {
    const bool isolation = TestClearAndTimeoutIsolation();
    const bool replacement = TestReplacementDisabledAndClosed();
    const bool destruction = TestDestructionCancelsOnlyOwnedEvent();
    std::printf("logical phase deadlines: isolation=%d replacement=%d destruction=%d\n",
                isolation, replacement, destruction);
    { ASSERT_TRUE(isolation && replacement && destruction); return; }
}
