#include <gtest/gtest.h>

#include "proxy/freedom/freedom_udp.hpp"
#include "app/dns/dns.hpp"
#include "app/relay.hpp"
#include "transport/async_stream.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <thread>
#include <vector>

namespace {
using namespace std::chrono_literals;
using UdpRequest = proxy::freedom::outbound::UdpRequest;

enum class WriteAbort { RequestCancel, ParentCancellation, Deadline };
enum class Deadline { Idle, Read, Phase };
enum class RelayAbort { Cancellation, Deadline };

TargetAddress Target(const udp::endpoint& endpoint) {
    return TargetAddress(endpoint.address(), endpoint.port());
}

buf::MultiBuffer Packet(const TargetAddress& target, size_t size) {
    std::vector<uint8_t> bytes(size);
    for (size_t i = 0; i < size; ++i) bytes[i] = static_cast<uint8_t>(i * 37);
    buf::MultiBuffer payload;
    EXPECT_TRUE(buf::AppendSpanToMultiBuffer(bytes, payload));
    for (auto* buffer : payload) buffer->SetUDP(target);
    return payload;
}

net::awaitable<void> Pause(net::io_context& io, std::chrono::milliseconds duration) {
    net::steady_timer timer(io, duration);
    co_await timer.async_wait(net::use_awaitable);
}

class DnsPeer final {
public:
    struct Query {
        std::vector<uint8_t> packet;
        udp::endpoint sender;
    };

    explicit DnsPeer(net::io_context& io)
        : socket_(io, udp::endpoint(net::ip::address_v4::loopback(), 0)),
          query_ready_(io) {
        query_ready_.expires_at(std::chrono::steady_clock::time_point::max());
        Receive();
    }

    udp::endpoint Endpoint() const { return socket_.local_endpoint(); }

    net::awaitable<void> WaitForQuery() {
        while (queries_.empty() && !stopped_) {
            query_ready_.expires_at(std::chrono::steady_clock::time_point::max());
            IoErrorCode error;
            co_await query_ready_.async_wait(net::redirect_error(net::use_awaitable, error));
        }
    }

    void ReplyPendingAndEnable() {
        auto pending = queries_;
        auto_reply_ = true;
        for (const auto& query : pending) Reply(query);
    }

    size_t AReplies() const noexcept { return a_replies_; }

    void Stop() {
        stopped_ = true;
        IoErrorCode ignored;
        socket_.close(ignored);
        query_ready_.cancel();
    }

private:
    void Receive() {
        socket_.async_receive_from(net::buffer(buffer_), sender_,
            [this](const IoErrorCode& error, size_t size) {
                if (error || stopped_) return;
                Query query{{buffer_.begin(), buffer_.begin() + size}, sender_};
                queries_.push_back(query);
                query_ready_.cancel();
                if (auto_reply_) Reply(query);
                Receive();
            });
    }

    void Reply(const Query& query) {
        if (query.packet.size() < 17) return;
        auto response = query.packet;
        size_t position = 12;
        while (position < response.size() && response[position] != 0) {
            const auto label_size = response[position++];
            if ((label_size & 0xc0) != 0 || position + label_size >= response.size()) return;
            position += label_size;
        }
        if (position + 5 > response.size()) return;
        ++position;
        const auto qtype = static_cast<uint16_t>((response[position] << 8) | response[position + 1]);
        response.resize(position + 4);
        response[2] = 0x81; // QR and RD
        response[3] = 0x80; // RA, NOERROR
        response[6] = 0;
        response[7] = qtype == 1 ? 1 : 0;
        response[8] = response[9] = response[10] = response[11] = 0;
        if (qtype == 1) {
            response.insert(response.end(), {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4,
                                             127, 0, 0, 1});
        }
        IoErrorCode ignored;
        socket_.send_to(net::buffer(response), query.sender, 0, ignored);
        if (!ignored && qtype == 1) ++a_replies_;
    }

    udp::socket socket_;
    udp::endpoint sender_;
    std::array<uint8_t, 512> buffer_{};
    net::steady_timer query_ready_;
    std::vector<Query> queries_;
    size_t a_replies_ = 0;
    bool auto_reply_ = false;
    bool stopped_ = false;
};

class UdpRequestTest : public testing::Test {
protected:
    net::io_context io;
    DnsPeer dns_peer{io};
    app::dns::DNSWorker dns_worker{
        io, app::dns::Config{.servers = {dns_peer.Endpoint()}}, 8};
    app::dns::DNS dns{dns_worker};
    std::vector<std::shared_ptr<UdpRequest>> requests;

    UdpRequest& Request() {
        requests.push_back(std::make_shared<UdpRequest>(
            io, dns, net::ip::address_v4::loopback()));
        return *requests.back();
    }

    template <typename Task>
    void Run(Task task) {
        std::exception_ptr error;
        bool done = false;
        bool expired = false;
        net::cancellation_signal cancellation;
        net::steady_timer watchdog(io, 8s);
        auto cancel_requests = [&] {
            for (const auto& request : requests) request->Cancel();
        };
        watchdog.async_wait([&](const IoErrorCode& ec) {
            if (!ec) {
                expired = true;
                cancel_requests();
                dns_peer.Stop();
                cancellation.emit(net::cancellation_type::all);
            }
        });
        net::co_spawn(io, task(), net::bind_cancellation_slot(cancellation.slot(),
            [&](std::exception_ptr failure) {
                error = failure;
                done = true;
                cancel_requests();
                dns_peer.Stop();
                watchdog.cancel();
            }));
        io.run();
        EXPECT_TRUE(done);
        EXPECT_FALSE(expired) << "request did not finish within its watchdog";
        if (error) std::rethrow_exception(error);
    }
};

net::awaitable<void> RoundTrip(net::io_context& io, UdpRequest& channel, size_t size) {
    udp::socket peer(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    const auto target = Target(peer.local_endpoint());
    co_await channel.WriteMultiBuffer(Packet(target, size));
    std::vector<uint8_t> received(65535);
    udp::endpoint source;
    const size_t count = co_await peer.async_receive_from(net::buffer(received), source, net::use_awaitable);
    EXPECT_EQ(count, size) << "one MultiBuffer must remain one UDP datagram";
    for (size_t i = 0; i < count; ++i)
        EXPECT_EQ(received[i], static_cast<uint8_t>(i * 37)) << "offset " << i;
    co_await peer.async_send_to(net::buffer(received.data(), count), source, net::use_awaitable);
    auto reply = co_await channel.ReadMultiBuffer();
    const auto datagram = buf::InspectUdpDatagram(reply);
    EXPECT_TRUE(datagram.Valid());
    EXPECT_EQ(datagram.payload_size, size);
    EXPECT_NE(datagram.target, nullptr);
    if (datagram.target) EXPECT_EQ(datagram.target->port, peer.local_endpoint().port());
    size_t offset = 0;
    for (auto* buffer : reply) {
        for (auto byte : buffer->Bytes()) {
            EXPECT_EQ(byte, static_cast<uint8_t>(offset++ * 37));
        }
    }
}

struct Completion {
    bool finished = false;
    std::exception_ptr failure;
};

net::awaitable<void> Join(net::io_context& io, const Completion& completion) {
    while (!completion.finished) co_await Pause(io, 5ms);
}

TEST_F(UdpRequestTest, CancellingOneReaderLeavesOtherRequestsUsable) {
    Run([&]() -> net::awaitable<void> {
        auto& cancelled = Request();
        auto& survivor = Request();
        auto completion = std::make_shared<Completion>();
        net::co_spawn(io, cancelled.ReadMultiBuffer(),
            [completion](std::exception_ptr error, buf::MultiBuffer) {
                completion->failure = error;
                completion->finished = true;
            });
        co_await Pause(io, 20ms);
        const auto started = std::chrono::steady_clock::now();
        cancelled.Cancel();
        co_await Join(io, *completion);
        EXPECT_LT(std::chrono::steady_clock::now() - started, 500ms);
        EXPECT_NE(completion->failure, nullptr);
        if (completion->failure) {
            try { std::rethrow_exception(completion->failure); }
            catch (const transport::LinkError& error) {
                EXPECT_EQ(error.code(), ErrorCode::CANCELLED);
            }
        }
        co_await RoundTrip(io, survivor, 20000);
    });
}

TEST_F(UdpRequestTest, ClosedRequestRejectsNewReads) {
    Run([&]() -> net::awaitable<void> {
        auto& request = Request();
        request.Close();
        bool rejected = false;
        try { co_await request.ReadMultiBuffer(); }
        catch (const transport::LinkError& error) {
            rejected = true;
            EXPECT_EQ(error.code(), ErrorCode::CANCELLED);
        }
        EXPECT_TRUE(rejected);
    });
}

TEST_F(UdpRequestTest, CompletedWriteRetiresItsDeadline) {
    Run([&]() -> net::awaitable<void> {
        auto& request = Request();
        request.SetWriteTimeout(1s);
        co_await RoundTrip(io, request, 32);
        co_await Pause(io, 1100ms);
        EXPECT_FALSE(request.ConsumeWriteTimeout());
        co_await RoundTrip(io, request, 11);
    });
}

class DnsWriteAbortTest : public UdpRequestTest,
                          public testing::WithParamInterface<WriteAbort> {};

TEST_P(DnsWriteAbortTest, AbortedResolutionCannotSendAfterLateDnsResponse) {
    Run([&]() -> net::awaitable<void> {
        const auto abort = GetParam();
        auto& request = Request();
        auto& survivor = Request();
        udp::socket sink(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
        request.SetWriteTimeout(1s);
        auto completion = std::make_shared<Completion>();
        net::cancellation_signal parent;
        net::co_spawn(io, request.WriteMultiBuffer(
            Packet(TargetAddress("cancelled-write.example", sink.local_endpoint().port()), 32)),
            net::bind_cancellation_slot(parent.slot(),
                [completion](std::exception_ptr error) {
                    completion->failure = error;
                    completion->finished = true;
                }));

        // Observe a real DNS exchange before releasing a valid, late A response.
        co_await dns_peer.WaitForQuery();
        if (abort == WriteAbort::RequestCancel) request.Cancel();
        if (abort == WriteAbort::ParentCancellation)
            parent.emit(net::cancellation_type::all);
        if (abort == WriteAbort::Deadline) co_await Pause(io, 1100ms);
        else dns_peer.ReplyPendingAndEnable();

        co_await Join(io, *completion);
        EXPECT_NE(completion->failure, nullptr);
        if (completion->failure) {
            try { std::rethrow_exception(completion->failure); }
            catch (const transport::LinkError& error) {
                EXPECT_EQ(error.code(), ErrorCode::CANCELLED);
            }
        }
        if (abort == WriteAbort::Deadline) {
            EXPECT_TRUE(request.ConsumeWriteTimeout());
            dns_peer.ReplyPendingAndEnable();
        }
        co_await Pause(io, 40ms);
        EXPECT_GT(dns_peer.AReplies(), 0u);
        IoErrorCode error;
        EXPECT_EQ(sink.available(error), 0u);
        EXPECT_FALSE(error);
        co_await RoundTrip(io, survivor, 32);
        co_await Pause(io, 1100ms);
        EXPECT_FALSE(request.ConsumeWriteTimeout()) << "aborted write retained a deadline";
    });
}

INSTANTIATE_TEST_SUITE_P(AbortModes, DnsWriteAbortTest,
    testing::Values(WriteAbort::RequestCancel, WriteAbort::ParentCancellation,
                    WriteAbort::Deadline),
    [](const testing::TestParamInfo<WriteAbort>& info) {
        switch (info.param) {
        case WriteAbort::RequestCancel: return "RequestCancel";
        case WriteAbort::ParentCancellation: return "ParentCancellation";
        case WriteAbort::Deadline: return "Deadline";
        }
        return "Unknown";
    });

class UdpDeadlineTest : public UdpRequestTest,
                        public testing::WithParamInterface<Deadline> {};

TEST_P(UdpDeadlineTest, PendingReadExpiresOnceAtItsDeadline) {
    Run([&]() -> net::awaitable<void> {
        auto& channel = Request();
        PhaseDeadlineHandle phase;
        const auto kind = GetParam();
        if (kind == Deadline::Idle) channel.SetIdleTimeout(1s);
        if (kind == Deadline::Read) channel.SetReadTimeout(1s);
        if (kind == Deadline::Phase) phase = channel.StartPhaseDeadline(1s);
        const auto started = std::chrono::steady_clock::now();
        bool cancelled = false;
        try { co_await channel.ReadMultiBuffer(); }
        catch (const transport::LinkError& error) {
            cancelled = true;
            EXPECT_EQ(error.code(), ErrorCode::CANCELLED);
        }
        const auto elapsed = std::chrono::steady_clock::now() - started;
        EXPECT_TRUE(cancelled);
        EXPECT_GE(elapsed, 800ms);
        EXPECT_LT(elapsed, 3s);
        if (kind == Deadline::Idle) {
            EXPECT_TRUE(channel.ConsumeIdleTimeout());
            EXPECT_FALSE(channel.ConsumeIdleTimeout());
        }
        if (kind == Deadline::Read) {
            EXPECT_TRUE(channel.ConsumeReadTimeout());
            EXPECT_FALSE(channel.ConsumeReadTimeout());
        }
        if (kind == Deadline::Phase) {
            EXPECT_TRUE(phase.Expired());
            channel.ClearPhaseDeadline();
            EXPECT_FALSE(phase.Expired());
            EXPECT_FALSE(channel.ConsumePhaseDeadline());
            EXPECT_FALSE(channel.StartPhaseDeadline(1s));
        }
    });
}

INSTANTIATE_TEST_SUITE_P(Deadlines, UdpDeadlineTest,
    testing::Values(Deadline::Idle, Deadline::Read, Deadline::Phase),
    [](const testing::TestParamInfo<Deadline>& info) {
        switch (info.param) {
        case Deadline::Idle: return "Idle";
        case Deadline::Read: return "Read";
        case Deadline::Phase: return "Phase";
        }
        return "Unknown";
    });

TEST_F(UdpRequestTest, DatagramActivityRefreshesIdleTimeout) {
    Run([&]() -> net::awaitable<void> {
        auto& channel = Request();
        channel.SetIdleTimeout(1s);
        for (int i = 0; i < 3; ++i) {
            co_await Pause(io, 450ms);
            co_await RoundTrip(io, channel, 32);
        }
        EXPECT_FALSE(channel.ConsumeIdleTimeout());
    });
}

TEST_F(UdpRequestTest, ClearedDeadlinesDoNotCancelLaterTraffic) {
    Run([&]() -> net::awaitable<void> {
        auto& channel = Request();
        channel.SetIdleTimeout(1s);
        const auto phase = channel.StartPhaseDeadline(1s);
        channel.ClearPhaseDeadline();
        channel.SetIdleTimeout(0s);
        co_await Pause(io, 1100ms);
        EXPECT_FALSE(phase.Expired());
        EXPECT_FALSE(channel.ConsumeIdleTimeout());
        EXPECT_FALSE(channel.ConsumePhaseDeadline());
        co_await RoundTrip(io, channel, 32);
    });
}

TEST_F(UdpRequestTest, ParentCancellationJoinsReaderWithoutAffectingOtherRequests) {
    Run([&]() -> net::awaitable<void> {
        auto& channel = Request();
        auto& survivor = Request();
        net::cancellation_signal cancellation;
        auto completion = std::make_shared<Completion>();
        net::co_spawn(io, channel.ReadMultiBuffer(),
            net::bind_cancellation_slot(cancellation.slot(),
                [completion](std::exception_ptr error, buf::MultiBuffer) {
                    completion->failure = error;
                    completion->finished = true;
                }));
        co_await Pause(io, 20ms);
        const auto started = std::chrono::steady_clock::now();
        cancellation.emit(net::cancellation_type::all);
        co_await Join(io, *completion);
        EXPECT_LT(std::chrono::steady_clock::now() - started, 500ms);
        EXPECT_NE(completion->failure, nullptr);
        if (completion->failure) {
            try { std::rethrow_exception(completion->failure); }
            // Parent coroutine cancellation is an Asio operation abort, not
            // the LinkError produced by explicitly cancelling the request.
            catch (const IoSystemError& error) {
                EXPECT_EQ(error.code(), io_error::operation_aborted);
            }
        }
        co_await RoundTrip(io, survivor, 32);
        co_await RoundTrip(io, channel, 32);
    });
}

TEST_F(UdpRequestTest, QueuedDeadlineCallbacksDoNotBorrowDestroyedRequests) {
    Run([&]() -> net::awaitable<void> {
        {
            UdpRequest old(io, dns, net::ip::address_v4::loopback());
            old.StartPhaseDeadline(1s);
            std::this_thread::sleep_for(1050ms);
        }
        co_await RoundTrip(io, Request(), 32);
    });
}

TEST_F(UdpRequestTest, MaximumDurationDeadlineDoesNotOverflow) {
    Run([&]() -> net::awaitable<void> {
        auto& current = Request();
        current.StartPhaseDeadline(std::chrono::seconds::max());
        co_await Pause(io, 20ms);
        EXPECT_FALSE(current.ConsumePhaseDeadline());
        co_await RoundTrip(io, current, 32);
    });
}

class OnePacketReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }

    OnePacketReader(TargetAddress target)
        : target_(std::move(target)) {}
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (used_) co_return buf::MultiBuffer{};
        used_ = true;
        co_return Packet(target_, 2000);
    }
private:
    transport::CancellationSource cancellation_;

    TargetAddress target_;
    bool used_ = false;
};

class IgnoreWriter final : public transport::MultiBufferWriter {
public:
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer) override { co_return; }
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer>) override { co_return; }
};

TEST_F(UdpRequestTest, RelayRateLimitAndHalfCloseBudgetPreserveSuccessfulWriteAccounting) {
    Run([&]() -> net::awaitable<void> {
        udp::socket peer(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
        auto& target = Request();
        OnePacketReader input(Target(peer.local_endpoint()));
        IgnoreWriter output;
        session::Context context;
        context.content.network = Network::UDP;
        StatsShard stats;
        const auto started = std::chrono::steady_clock::now();
        const auto result = co_await DoRelayLink(io, input, output, nullptr,
            target, context, stats, RelayConfig{.downlink_only = 1s, .speed_limit = 1000});
        const auto elapsed = std::chrono::steady_clock::now() - started;
        EXPECT_EQ(result.error, ErrorCode::RELAY_TIMEOUT);
        EXPECT_EQ(result.bytes_up, 2000u);
        EXPECT_EQ(result.bytes_down, 0u);
        EXPECT_EQ(stats.Snapshot().bytes_out, 2000u);
        EXPECT_EQ(context.traffic.bytes_up, 2000u);
        EXPECT_GE(elapsed, 1900ms);
        EXPECT_LT(elapsed, 4s);
    });
}

TEST_F(UdpRequestTest, InvalidDatagramRetainsErrorWithoutCountingFailedSend) {
    Run([&]() -> net::awaitable<void> {
        auto& target = Request();
        OnePacketReader input(TargetAddress{});
        IgnoreWriter output;
        session::Context context;
        context.content.network = Network::UDP;
        StatsShard stats;
        const auto result = co_await DoRelayLink(io, input, output, nullptr,
                                               target, context, stats);
        EXPECT_EQ(result.error, ErrorCode::INVALID_ARGUMENT);
        EXPECT_EQ(result.bytes_up, 0u);
        EXPECT_EQ(context.traffic.bytes_up, 0u);
        EXPECT_EQ(stats.Snapshot().bytes_out, 0u);
    });
}

class UdpRelayAbortTest : public UdpRequestTest,
                         public testing::WithParamInterface<RelayAbort> {};

TEST_P(UdpRelayAbortTest, CancellationJoinsRateLimitedRelayWithoutCountingUnsentPayload) {
    Run([&]() -> net::awaitable<void> {
        udp::socket peer(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
        auto& target = Request();
        OnePacketReader input(Target(peer.local_endpoint()));
        IgnoreWriter output;
        session::Context context;
        context.content.network = Network::UDP;
        StatsShard stats;
        net::steady_timer cancellation(io);
        const bool deadline = GetParam() == RelayAbort::Deadline;
        if (deadline) target.StartPhaseDeadline(1s);
        else {
            cancellation.expires_after(50ms);
            cancellation.async_wait([&](const IoErrorCode& error) {
                if (!error) target.Cancel();
            });
        }
        const auto start = std::chrono::steady_clock::now();
        const auto result = co_await DoRelayLink(io, input, output, nullptr,
            target, context, stats, RelayConfig{.speed_limit = 100});
        cancellation.cancel();
        const auto elapsed = std::chrono::steady_clock::now() - start;
        EXPECT_EQ(result.error, deadline ? ErrorCode::RELAY_TIMEOUT : ErrorCode::CANCELLED);
        EXPECT_EQ(result.bytes_up, 0u);
        EXPECT_EQ(context.traffic.bytes_up, 0u);
        EXPECT_EQ(stats.Snapshot().bytes_out, 0u);
        EXPECT_LT(elapsed, deadline ? 1800ms : 500ms);
    });
}

INSTANTIATE_TEST_SUITE_P(AbortModes, UdpRelayAbortTest,
    testing::Values(RelayAbort::Cancellation, RelayAbort::Deadline),
    [](const testing::TestParamInfo<RelayAbort>& info) {
        return info.param == RelayAbort::Deadline ? "Deadline" : "Cancellation";
    });
}  // namespace
