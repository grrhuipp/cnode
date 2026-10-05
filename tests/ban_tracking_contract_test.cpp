#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/session.hpp"

#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/strand.hpp>
#include <asio/use_future.hpp>
#include <array>
#include <atomic>
#include <future>
#include <memory>
#include <thread>
#include <vector>

namespace {
using namespace acpp;

net::awaitable<int> CheckBan(ConnectionLimiter& limiter, ConnectionLimiter& limits) {
    const std::string tag = "panel/vmess/443";
    const std::string other_tag = "panel/vmess/8443";
    const std::string ip = "192.0.2.1";
    session::Inbound inbound;
    inbound.source_ip = ip;
    auto record = [&]() -> net::awaitable<void> {
        if (inbound.HasProxyProtocolClientIP()) co_await limiter.OnAuthFailTracked(tag, ip);
    };
    co_await record();
    if (co_await limiter.IsBanned(tag, ip)) co_return 1;
    inbound.client_ip_source = "http_header";
    co_await record();
    if (co_await limiter.IsBanned(tag, ip)) co_return 2;
    inbound.client_ip_source = "proxy_protocol";
    inbound.source_ip.clear();
    if (inbound.HasProxyProtocolClientIP()) co_return 3;
    co_await record();
    if (co_await limiter.IsBanned(tag, ip)) co_return 4;
    inbound.source_ip = ip;
    if (!inbound.HasProxyProtocolClientIP()) co_return 5;
    co_await record();
    if (!(co_await limiter.IsBanned(tag, ip))) co_return 6;
    if (co_await limiter.IsBanned(other_tag, ip)) co_return 7;

    auto banned = co_await limiter.AcquireGlobal();
    const auto reason = co_await limiter.AcquireIP(*banned.permit, tag, ip);
    co_await limiter.Release(std::move(*banned.permit));
    if (reason != ConnectionLimiter::RejectReason::IP_BANNED) co_return 8;

    co_await limits.OnAuthFailTracked(tag, ip);
    auto first = co_await limits.AcquireGlobal();
    auto second = co_await limits.AcquireGlobal();
    const auto first_ip = co_await limits.AcquireIP(*first.permit, tag, ip, false);
    const auto second_ip = co_await limits.AcquireIP(*second.permit, tag, ip, false);
    co_await limits.Release(std::move(*second.permit));
    co_await limits.Release(std::move(*first.permit));
    if (first_ip != ConnectionLimiter::RejectReason::NONE) co_return 9;
    if (second_ip != ConnectionLimiter::RejectReason::MAX_CONNECTIONS_PER_IP) co_return 10;
    auto third = co_await limits.AcquireGlobal();
    const auto third_ip = co_await limits.AcquireIP(*third.permit, tag, ip, false);
    co_await limits.Release(std::move(*third.permit));
    if (third_ip != ConnectionLimiter::RejectReason::NONE) co_return 11;
    co_return 0;
}
}

int main() {
    net::io_context io;
    auto work = net::make_work_guard(io);
    RateLimitConfig config{.auth_fail_limit = 1, .auth_fail_window = 60, .auth_ban_seconds = 60};
    auto limiter = std::make_unique<ConnectionLimiter>(net::make_strand(io), config);
    config.max_conn_per_ip = 1;
    auto limits = std::make_unique<ConnectionLimiter>(net::make_strand(io), config);
    auto checked = net::co_spawn(net::make_strand(io), CheckBan(*limiter, *limits), net::use_future);
    std::array<std::thread, 4> workers;
    for (auto& worker : workers) worker = std::thread([&] { io.run(); });
    int result = checked.get();
    if (result == 0) {
        // All callers have distinct session strands. The winning reservation
        // remains live until every other caller has attempted admission.
        RateLimitConfig single{.max_connections = 1};
        auto global = std::make_unique<ConnectionLimiter>(net::make_strand(io), single);
        net::experimental::concurrent_channel<void(IoErrorCode)> release(io, 1);
        std::atomic<unsigned> attempted{0};
        std::promise<void> all_attempted;
        auto ready = all_attempted.get_future();
        std::vector<std::future<bool>> callers;
        for (unsigned i = 0; i < 64; ++i) {
            callers.push_back(net::co_spawn(net::make_strand(io),
                [](ConnectionLimiter* owner, decltype(release)* gate,
                   std::atomic<unsigned>* count, std::promise<void>* ready) -> net::awaitable<bool> {
                    auto admission = co_await owner->AcquireGlobal();
                    const bool admitted = admission.permit.has_value();
                    if (count->fetch_add(1) + 1 == 64) ready->set_value();
                    if (admitted) {
                        co_await gate->async_receive(net::use_awaitable);
                        co_await owner->Release(std::move(*admission.permit));
                    }
                    co_return admitted;
                }(global.get(), &release, &attempted, &all_attempted), net::use_future));
        }
        ready.get();
        (void)release.try_send(IoErrorCode{});
        unsigned admitted = 0;
        for (auto& caller : callers) admitted += caller.get();
        if (admitted != 1) result = 12;
    }
    work.reset();
    for (auto& worker : workers) worker.join();
    return result;
}
