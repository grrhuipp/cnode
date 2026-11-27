#include <gtest/gtest.h>

#include "common/session.hpp"
#include "transport/outbound_target_builder.hpp"
#include "transport/timeout_scheduler.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

class Fd {
public:
    explicit Fd(int fd) : fd_(fd) {
        if (fd_ < 0) throw std::runtime_error("socket failed");
    }
    Fd(Fd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    Fd& operator=(Fd&&) = delete;
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    [[nodiscard]] int Get() const noexcept { return fd_; }
private:
    int fd_;
};

[[nodiscard]] tcp::endpoint LocalAddress(int fd) {
    sockaddr_storage storage{};
    socklen_t size = sizeof(storage);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&storage), &size) != 0) {
        throw std::runtime_error("getsockname failed");
    }
    tcp::endpoint endpoint;
    std::memcpy(endpoint.data(), &storage, size);
    return endpoint;
}

[[nodiscard]] Fd Listen(bool v6, int backlog) {
    Fd listener(::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0));
    int enabled = 1;
    if (v6 && ::setsockopt(listener.Get(), IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) != 0) {
        throw std::runtime_error("IPV6_V6ONLY failed");
    }
    sockaddr_storage storage{};
    socklen_t size = 0;
    if (v6) {
        auto& address = reinterpret_cast<sockaddr_in6&>(storage);
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_loopback;
        size = sizeof(address);
    } else {
        auto& address = reinterpret_cast<sockaddr_in&>(storage);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        size = sizeof(address);
    }
    if (::bind(listener.Get(), reinterpret_cast<sockaddr*>(&storage), size) != 0 ||
        ::listen(listener.Get(), backlog) != 0) {
        throw std::runtime_error("listen failed");
    }
    return listener;
}

[[nodiscard]] Fd ConnectBlocking(const tcp::endpoint& endpoint) {
    Fd client(::socket(endpoint.protocol().family(), SOCK_STREAM, 0));
    if (::connect(client.Get(), endpoint.data(), endpoint.size()) != 0) {
        throw std::runtime_error("filler connect failed");
    }
    return client;
}

// A loopback listener whose accept queue is full. Linux then drops every new
// SYN (tcp_abort_on_overflow=0), so a connect stays in SYN retransmission:
// the deterministic stand-in for a black-holed route.
class BlackholeListener {
public:
    explicit BlackholeListener(bool v6) : listener_(Listen(v6, 1)), endpoint_(LocalAddress(listener_.Get())) {
        // backlog 1 admits two established children before the queue is full.
        fillers_.push_back(ConnectBlocking(endpoint_));
        fillers_.push_back(ConnectBlocking(endpoint_));
        Fd probe(::socket(endpoint_.protocol().family(), SOCK_STREAM | SOCK_NONBLOCK, 0));
        if (::connect(probe.Get(), endpoint_.data(), endpoint_.size()) == 0 || errno != EINPROGRESS) {
            throw std::runtime_error("accept queue did not black-hole the probe SYN");
        }
        pollfd waiting{.fd = probe.Get(), .events = POLLOUT, .revents = 0};
        if (::poll(&waiting, 1, 100) != 0) {
            throw std::runtime_error("accept queue did not black-hole the probe SYN");
        }
    }
    [[nodiscard]] const tcp::endpoint& Endpoint() const noexcept { return endpoint_; }
private:
    Fd listener_;
    tcp::endpoint endpoint_;
    std::vector<Fd> fillers_;
};

class OpenListener {
public:
    explicit OpenListener(bool v6) : listener_(Listen(v6, 16)), endpoint_(LocalAddress(listener_.Get())) {}
    [[nodiscard]] const tcp::endpoint& Endpoint() const noexcept { return endpoint_; }
private:
    Fd listener_;
    tcp::endpoint endpoint_;
};

[[nodiscard]] size_t OpenFdCount() {
    size_t count = 0;
    for ([[maybe_unused]] const auto& entry : std::filesystem::directory_iterator("/proc/self/fd")) ++count;
    return count;
}

struct DialRun {
    transport::DialResult result;
    Clock::duration elapsed{};
    bool aborted = false;
};

class TransportDialer : public testing::Test {
protected:
    TransportDialer() {
        // Create the reactor and Worker timeout scheduler up front so the
        // descriptor baseline only measures dial sockets.
        (void)transport::TimeoutScheduler::ForIoContext(io_);
        tcp::socket warm(io_, tcp::v4());
        net::steady_timer timer(io_, 0s);
        timer.async_wait([](IoErrorCode) {});
        io_.run();
        io_.restart();
    }

    [[nodiscard]] transport::OutboundTransportTarget Target(
        std::vector<tcp::endpoint> endpoints, std::chrono::seconds timeout) const {
        transport::OutboundTransportTarget target;
        target.stream_settings = &settings_;
        target.timeout = timeout;
        for (auto& endpoint : endpoints) {
            target.candidates.push_back(
                transport::OutboundDialCandidate{.endpoint = endpoint, .bind_local = std::nullopt});
        }
        return target;
    }

    // Runs the dial to completion; the io_context must also drain, so a
    // detached attempt or armed timer outliving the dial keeps run() busy.
    DialRun Run(const transport::OutboundTransportTarget& target,
                std::optional<Clock::duration> cancel_after = std::nullopt) {
        DialRun run;
        const auto start = Clock::now();
        net::co_spawn(io_, [&]() -> net::awaitable<void> {
            if (!cancel_after) {
                run.result = co_await transport::DialOutboundTransport(io_, ctx_, target);
            } else {
                using net::experimental::awaitable_operators::operator||;
                net::steady_timer cancel(io_, *cancel_after);
                try {
                    auto outcome = co_await (
                        transport::DialOutboundTransport(io_, ctx_, target) ||
                        cancel.async_wait(net::use_awaitable));
                    if (outcome.index() == 0) run.result = std::move(std::get<0>(outcome));
                    else run.aborted = true;
                } catch (const std::exception&) {
                    run.aborted = true;
                }
            }
            run.elapsed = Clock::now() - start;
            stats_after_dial_ = transport::TimeoutScheduler::ForIoContext(io_).GetResourceStats();
        }, net::detached);
        io_.run();
        drained_after_ = Clock::now() - start;
        return run;
    }

    net::io_context io_;
    common::Context ctx_;
    transport::StreamSettings settings_;
    transport::TimeoutScheduler::ResourceStats stats_after_dial_{};
    Clock::duration drained_after_{};
};

TEST_F(TransportDialer, BlackholedPreferredFamilyFallsBackAfterAttemptDelay) {
    BlackholeListener v6_blackhole(true);
    OpenListener v4_open(false);
    const size_t fds_before = OpenFdCount();

    auto run = Run(Target({v6_blackhole.Endpoint(), v4_open.Endpoint()}, 5s));

    ASSERT_TRUE(run.result.Ok()) << run.result.error_msg;
    EXPECT_EQ(run.result.stream->RemoteEndpoint(), v4_open.Endpoint());
    // RFC 8305 §5: the IPv4 attempt starts after the 250 ms Connection
    // Attempt Delay instead of after the whole IPv6 dial timeout.
    EXPECT_LT(run.elapsed, 2s);
    EXPECT_LT(drained_after_, 2s);
    EXPECT_EQ(stats_after_dial_.active_events, 0u);
    // Only the winning socket survives; the cancelled IPv6 attempt is closed.
    EXPECT_EQ(OpenFdCount(), fds_before + 1);
    run.result.stream.reset();
    EXPECT_EQ(OpenFdCount(), fds_before);
}

TEST_F(TransportDialer, InterleavesAddressFamiliesStartingWithPreferred) {
    BlackholeListener v6_blackhole(true);
    OpenListener v6_open(true);
    OpenListener v4_open(false);

    // Candidate order groups each family; the race alternates families, so
    // the second attempt is the first IPv4 address, not the second IPv6 one.
    auto run = Run(Target({v6_blackhole.Endpoint(), v6_open.Endpoint(), v4_open.Endpoint()}, 5s));

    ASSERT_TRUE(run.result.Ok()) << run.result.error_msg;
    EXPECT_EQ(run.result.stream->RemoteEndpoint(), v4_open.Endpoint());
    EXPECT_LT(run.elapsed, 2s);
}

TEST_F(TransportDialer, AllBlackholedCandidatesFailWithinOneDialDeadline) {
    BlackholeListener first(true);
    BlackholeListener second(false);
    BlackholeListener third(true);
    const size_t fds_before = OpenFdCount();

    auto run = Run(Target({first.Endpoint(), second.Endpoint(), third.Endpoint()}, 1s));

    ASSERT_FALSE(run.result.Ok());
    EXPECT_EQ(run.result.error, common::ErrorCode::DIAL_TIMEOUT);
    EXPECT_GE(run.elapsed, 1s);
    // One deadline bounds the race; per-candidate timeouts would take 3 s.
    EXPECT_LT(run.elapsed, 1800ms);
    EXPECT_LT(drained_after_, 1800ms);
    EXPECT_EQ(stats_after_dial_.active_events, 0u);
    EXPECT_EQ(OpenFdCount(), fds_before);
}

TEST_F(TransportDialer, CancellationJoinsEveryInFlightAttempt) {
    BlackholeListener first(true);
    BlackholeListener second(false);
    BlackholeListener third(true);
    const size_t fds_before = OpenFdCount();

    // Two attempts are in flight when the caller cancels; no further attempt
    // may start and every started one is closed before the dial returns.
    auto run = Run(Target({first.Endpoint(), second.Endpoint(), third.Endpoint()}, 5s), 400ms);

    EXPECT_TRUE(run.aborted);
    EXPECT_LT(run.elapsed, 1500ms);
    EXPECT_LT(drained_after_, 1500ms);
    EXPECT_EQ(stats_after_dial_.active_events, 0u);
    EXPECT_EQ(OpenFdCount(), fds_before);
}

}  // namespace
