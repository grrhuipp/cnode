#include "acppnode/app/session_tracking.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/sharded_user_stats.hpp"

#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/strand.hpp>
#include <asio/use_future.hpp>
#include <array>
#include <atomic>
#include <exception>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
using namespace acpp;
void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

net::awaitable<void> CheckTraffic(app::SessionTrackingState& tracking) {
    std::weak_ptr<session::TrafficSource> source;
    {
    session::Context context(co_await net::this_coro::executor);
    context.traffic.bytes_up = 100;
    context.traffic.bytes_down = 40;
    auto registration = co_await tracking.RegisterActiveSession(1, "traffic", 7, context.traffic_owner);
    const auto first = co_await tracking.CollectAndResetTraffic("traffic");
    Check(first.users.at(7).upload == 100 && first.users.at(7).download == 40,
          "active traffic must be reported before the connection closes");
    context.traffic.bytes_up += 30;
    context.traffic.bytes_down += 20;
    const auto second = co_await tracking.CollectAndResetTraffic("traffic");
    Check(second.users.at(7).upload == 30 && second.users.at(7).download == 20,
          "repeated active collection must return only the new traffic");
    context.traffic.bytes_up += 10;
    context.traffic.bytes_down += 5;
    co_await tracking.UnregisterActiveSession(std::move(registration), context.traffic);
    const auto final = co_await tracking.CollectAndResetTraffic("traffic");
    Check(final.users.at(7).upload == 10 && final.users.at(7).download == 5,
          "close must submit the final delta exactly once");
    const auto empty = co_await tracking.CollectAndResetTraffic("traffic");
    Check(empty.empty(), "no traffic may remain after final collection");
    source = context.traffic_owner;
    }
    Check(source.expired(), "unregister must release the owning session snapshot endpoint");
}

net::awaitable<void> CheckFullCleanup(UserOnlineTracker& tracker) {
    UserOnlineLease lease(tracker);
    Check(co_await lease.Acquire("full", 1, "192.0.2.1", 1), "initial device admission failed");
    bool full = false;
    try { (void)co_await tracker.GetOnlineDevices("full"); }
    catch (const ServiceChannelFull&) { full = true; }
    Check(full, "the cleanup reservation must count against service capacity");
    co_await lease.Release();
    Check((co_await tracker.GetOnlineDevices("full")).empty(),
          "reserved cleanup must succeed even while ordinary entry capacity is full");
}

using Gate = net::experimental::concurrent_channel<void(IoErrorCode)>;
net::awaitable<bool> Attempt(UserOnlineTracker& tracker, Gate& gate,
    std::atomic<unsigned>& attempted, std::promise<void>& ready, std::string ip) {
    UserOnlineLease lease(tracker);
    const bool admitted = co_await lease.Acquire("parallel", 7, std::move(ip), 1);
    if (attempted.fetch_add(1) + 1 == 64) ready.set_value();
    if (admitted) co_await gate.async_receive(net::use_awaitable);
    co_await lease.Release();
    co_return admitted;
}

void CheckConcurrentAdmission(net::io_context& io, UserOnlineTracker& tracker, bool same_ip) {
    Gate gate(io, 64);
    std::atomic<unsigned> attempted{0};
    std::promise<void> ready;
    auto all_attempted = ready.get_future();
    std::vector<std::future<bool>> results;
    for (unsigned i = 0; i < 64; ++i) {
        const auto ip = same_ip ? "192.0.2.1" : "192.0.2." + std::to_string(i + 1);
        results.push_back(net::co_spawn(net::make_strand(io),
            Attempt(tracker, gate, attempted, ready, ip), net::use_future));
    }
    all_attempted.get();
    auto devices = net::co_spawn(net::make_strand(io), tracker.GetOnlineDevices("parallel"), net::use_future).get();
    Check(devices.size() == 1, "concurrent device check and reservation must have one authority");
    for (unsigned i = 0; i < 64; ++i) (void)gate.try_send(IoErrorCode{});
    unsigned admitted = 0;
    for (auto& result : results) admitted += result.get();
    Check(admitted == (same_ip ? 64 : 1), "device admission changed the distinct-IP quota");
    auto remaining = net::co_spawn(net::make_strand(io), tracker.GetOnlineDevices("parallel"), net::use_future).get();
    Check(remaining.empty(), "every joined request must release its online registration");
}
}

int main() {
    net::io_context io;
    auto work = net::make_work_guard(io);
    UserOnlineTracker tracker(net::make_strand(io), 128);
    UserOnlineTracker full(net::make_strand(io), 1);
    app::SessionTrackingState tracking(net::make_strand(io));
    std::array<std::thread, 4> workers;
    for (auto& worker : workers) worker = std::thread([&] { io.run(); });
    int status = 0;
    try {
        net::co_spawn(net::make_strand(io), CheckTraffic(tracking), net::use_future).get();
        net::co_spawn(net::make_strand(io), CheckFullCleanup(full), net::use_future).get();
        CheckConcurrentAdmission(io, tracker, false);
        CheckConcurrentAdmission(io, tracker, true);
        std::cout << "four-thread device admission, reserved cleanup, active/final traffic snapshots PASS\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        status = 1;
    }
    work.reset();
    if (status) io.stop();
    for (auto& worker : workers) worker.join();
    return status;
}
