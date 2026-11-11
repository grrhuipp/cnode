#include <gtest/gtest.h>

#include "app/dns/dns_internal.hpp"
#include "common/allocator.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>
#include <array>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;
using ::app::dns::DNS;
using ::app::dns::DnsResult;

struct Peer {
    struct Query { std::vector<uint8_t> bytes; ::udp::endpoint sender; };
    explicit Peer(net::io_context& io, bool ipv6 = false)
        : socket(io, {ipv6 ? net::ip::address(net::ip::address_v6::loopback()) :
                     net::ip::address(net::ip::address_v4::loopback()), 0}), foreign(io) {
        foreign.open(socket.local_endpoint().protocol());
        Receive();
    }
    void Stop() { socket.close(); foreign.close(); }
    void Receive() {
        socket.async_receive_from(net::buffer(buffer), sender, [&](::IoErrorCode ec, size_t size) {
            if (ec) return;
            ++packets;
            ports.insert(sender.port());
            const uint16_t id = (buffer[0] << 8) | buffer[1];
            auto& used = ids[sender.port()];
            duplicate_id |= used.test(id);
            used.set(id);
            std::string name;
            size_t pos = 12;
            while (pos < size && buffer[pos]) {
                const auto n = buffer[pos++];
                if (!name.empty()) name += '.';
                name.append(reinterpret_cast<const char*>(buffer.data() + pos), n);
                pos += n;
            }
            auto& group = queries[name];
            group.push_back({{buffer.begin(), buffer.begin() + size}, sender});
            // A serial resolver cannot satisfy this barrier. It must submit all
            // three A samples and AAAA before any response is made available.
            if (group.size() == batch_size && !hold && name != "timeout.example") Flush(name);
            Receive();
        });
    }
    void Flush(const std::string& name) {
        auto group = std::move(queries.at(name));
        queries.erase(name);
        EXPECT_EQ(group.size(), batch_size) << "all queries must be outstanding together";
        int ordinal = 4;
        for (auto it = group.rbegin(); it != group.rend(); ++it) {
            auto packet = it->bytes;
            const bool v6 = packet[packet.size() - 3] == 28;
            packet[2] = 0x81;
            packet[3] = refuse ? 0x82 : negative ? 0x83 : 0x80;
            if (!refuse && !negative && !nodata &&
                (malformed_type == 0 || malformed_type == (v6 ? 28 : 1))) {
                packet[7] = 1;
                const uint8_t size = v6 ? 16 : 4;
                const uint32_t ttl = ttl_type == 0 || ttl_type == (v6 ? 28 : 1)
                    ? answer_ttl.value_or(static_cast<uint32_t>(ordinal * 10)) : 60;
                packet.insert(packet.end(), {0xc0, 0x0c, 0, static_cast<uint8_t>(v6 ? 28 : 1),
                    0, 1, static_cast<uint8_t>(ttl >> 24), static_cast<uint8_t>(ttl >> 16),
                    static_cast<uint8_t>(ttl >> 8), static_cast<uint8_t>(ttl), 0, size});
                if (v6) {
                    const auto bytes = net::ip::make_address_v6("2001:db8::1").to_bytes();
                    packet.insert(packet.end(), bytes.begin(), bytes.end());
                } else packet.insert(packet.end(), {192, 0, 2, static_cast<uint8_t>(ordinal)});
                if (malformed_type == (v6 ? 28 : 1)) {
                    packet[it->bytes.size() + 11] = static_cast<uint8_t>(size - 1);
                    packet.pop_back();
                }
            }
            --ordinal;
            if (noise) {
                auto wrong = packet;
                uint16_t unused = static_cast<uint16_t>(((wrong[0] ^ 0x80) << 8) | wrong[1]);
                while (ids[it->sender.port()].test(unused)) ++unused;
                wrong[0] = static_cast<uint8_t>(unused >> 8);
                wrong[1] = static_cast<uint8_t>(unused);
                socket.send_to(net::buffer(wrong), it->sender);
                wrong = packet;
                wrong[13] = 'z'; // same transaction, different question
                if (!refuse && !negative) wrong.back() = 99;
                socket.send_to(net::buffer(wrong), it->sender);
                wrong = packet;
                wrong[it->bytes.size() - 3] ^= 1; // different QTYPE
                socket.send_to(net::buffer(wrong), it->sender);
                wrong = packet;
                wrong[12] = 0xc0; wrong[13] = 12; // compression pointer cycle
                socket.send_to(net::buffer(wrong), it->sender);
                // A correct transaction/question from an unconfigured endpoint.
                wrong = packet;
                wrong.back() = 99;
                foreign.send_to(net::buffer(wrong), it->sender);
            }
            socket.send_to(net::buffer(packet), it->sender);
        }
        // The resolver's next process-layer allocation after the full answer
        // set arrives is its cache write.
        if (fault_cache_write) ::memory::reject_next_process_allocation = true;
    }
    ::udp::socket socket, foreign;
    ::udp::endpoint sender;
    std::array<uint8_t, 512> buffer{};
    std::map<std::string, std::vector<Query>> queries;
    std::set<uint16_t> ports;
    std::map<uint16_t, std::bitset<65536>> ids;
    size_t packets = 0, batch_size = 4;
    bool hold = false, refuse = false, negative = false, nodata = false;
    bool noise = false, duplicate_id = false, fault_cache_write = false;
    int malformed_type = 0;
    std::optional<uint32_t> answer_ttl;
    int ttl_type = 0;
};

::app::dns::Config Config(Peer& peer) {
    ::app::dns::Config c;
    c.servers = {peer.socket.local_endpoint()}; c.min_ttl = 1; c.timeout_sec = 1;
    return c;
}

template<class Service>
void JoinService(net::io_context& io, Service& service) {
    io.restart();
    auto joined = net::co_spawn(io, service.AsyncJoin(), net::use_future);
    io.run();
    joined.get();
}

class DnsDatagramQueries : public testing::TestWithParam<bool> {
protected:
    void Run(net::awaitable<void> scenario) {
        bool done = false;
        std::exception_ptr failure;
        net::co_spawn(io, std::move(scenario), [&](std::exception_ptr error) {
            failure = error;
            done = true;
            peer.Stop();
        });
        io.run_for(4s);
        const bool completed_before_cleanup = done;
        peer.Stop();
        JoinService(io, worker);
        EXPECT_TRUE(completed_before_cleanup) << "DNS 查询未在截止前完成";
        if (failure) std::rethrow_exception(failure);
    }
    net::io_context io;
    Peer peer{io, GetParam()};
    ::app::dns::DNSWorker worker{io, Config(peer), 8};
    DNS dns{worker};
};

TEST_P(DnsDatagramQueries, ValidatesOutOfOrderAnswersAndCachesCanonicalNames) {
    peer.noise = true;
    auto run = [&]() -> net::awaitable<void> {
        const auto result = co_await dns.Resolve("first.example");
        const std::vector<net::ip::address> expected{
            net::ip::make_address("192.0.2.1"), net::ip::make_address("192.0.2.2"),
            net::ip::make_address("192.0.2.3"), net::ip::make_address("2001:db8::1")};
        EXPECT_TRUE(result.Ok());
        EXPECT_EQ(result.addresses, expected);
        EXPECT_EQ(result.ttl, 10u);
        const auto cached = co_await dns.Resolve("FIRST.EXAMPLE.");
        EXPECT_TRUE(cached.Ok());
        EXPECT_TRUE(cached.from_cache);
        EXPECT_EQ(cached.addresses, expected);
        EXPECT_EQ(peer.packets, 4u);
        const auto second = co_await dns.Resolve("second.example");
        EXPECT_TRUE(second.Ok());
        EXPECT_EQ(peer.packets, 8u);
        EXPECT_EQ(peer.ports.size(), 1u);
    };
    Run(run());
}

TEST_P(DnsDatagramQueries, NxDomainIsCachedWithoutRepeatingUpstreamQueries) {
    peer.negative = true;
    auto run = [&]() -> net::awaitable<void> {
        const auto first = co_await dns.Resolve("negative.example");
        EXPECT_EQ(first.error, ::common::ErrorCode::DNS_NO_RECORD);
        const auto cached = co_await dns.Resolve("negative.example");
        EXPECT_EQ(cached.error, ::common::ErrorCode::DNS_NO_RECORD);
        EXPECT_TRUE(cached.from_cache);
        EXPECT_EQ(peer.packets, 4u);
    };
    Run(run());
}

TEST_P(DnsDatagramQueries, NoDataReasonSurvivesNegativeCaching) {
    peer.nodata = true;
    auto run = [&]() -> net::awaitable<void> {
        const auto first = co_await dns.Resolve("nodata.example");
        EXPECT_EQ(first.error, ::common::ErrorCode::DNS_NO_RECORD);
        EXPECT_NE(first.error_msg.find("NODATA"), std::string::npos);
        const auto cached = co_await dns.Resolve("nodata.example");
        EXPECT_EQ(cached.error, ::common::ErrorCode::DNS_NO_RECORD);
        EXPECT_TRUE(cached.from_cache);
        EXPECT_NE(cached.error_msg.find("NODATA"), std::string::npos);
        EXPECT_EQ(cached.error_msg.find("NXDOMAIN"), std::string::npos);
        EXPECT_EQ(peer.packets, 4u);
    };
    Run(run());
}

class DnsDatagramIsolation : public testing::TestWithParam<bool> {};
TEST_P(DnsDatagramIsolation, OneRequestEndingDoesNotCancelAnotherQuery) {
    const bool cancel = GetParam();
    net::io_context io;
    Peer peer(io);
    peer.hold = cancel;
    ::app::dns::DNSWorker worker(io, Config(peer), 8);
    DNS dns(worker);
    net::cancellation_signal signal;
    std::array<DnsResult, 2> answers;
    std::array<std::exception_ptr, 2> errors;
    size_t completed = 0;
    auto finish = [&](size_t i) { return [&, i](std::exception_ptr e, DnsResult result) {
        errors[i] = e; answers[i] = std::move(result);
        if (++completed == 2) peer.Stop();
    }; };
    net::co_spawn(io, dns.Resolve("timeout.example"), net::bind_cancellation_slot(signal.slot(), finish(0)));
    net::co_spawn(io, dns.Resolve("other.example"), finish(1));
    net::steady_timer timer(io, 40ms);
    if (cancel) timer.async_wait([&](::IoErrorCode ec) {
        if (!ec) { signal.emit(net::cancellation_type::terminal); peer.Flush("other.example"); }
    });
    io.run_for(3s);
    const bool completed_before_cleanup = completed == 2;
    peer.Stop();
    JoinService(io, worker);
    EXPECT_TRUE(completed_before_cleanup);
    EXPECT_EQ(completed, 2u);
    EXPECT_FALSE(errors[1]);
    EXPECT_TRUE(answers[1].Ok());
    if (cancel) {
        EXPECT_TRUE(errors[0] || answers[0].error == ::common::ErrorCode::CANCELLED);
    } else {
        EXPECT_FALSE(errors[0]);
        EXPECT_EQ(answers[0].error, ::common::ErrorCode::DNS_TIMEOUT);
    }
    EXPECT_EQ(peer.ports.size(), 1) << "concurrent requests must multiplex one socket";
}

class DnsSameDomainCancellation : public testing::TestWithParam<size_t> {};
TEST_P(DnsSameDomainCancellation, CancellingOneWaiterPreservesSharedUdpAnswerForSurvivor) {
    const auto cancelled = GetParam();
    net::io_context io;
    Peer peer(io);
    peer.hold = true;
    ::app::dns::DNSWorker worker(io, Config(peer), 8);
    std::array<net::cancellation_signal, 2> signals;
    std::array<DnsResult, 2> answers;
    std::array<std::exception_ptr, 2> errors;
    std::array<bool, 2> completed{};
    bool expired = false;
    net::steady_timer watchdog(io, 2s);
    watchdog.async_wait([&](::IoErrorCode ec) {
        if (!ec) { expired = true; worker.RequestStop(); }
    });
    auto start = [&](size_t i) {
        net::co_spawn(io, worker.Resolve("same.example"),
            net::bind_cancellation_slot(signals[i].slot(),
                [&, i](std::exception_ptr error, DnsResult result) {
                    errors[i] = error;
                    answers[i] = std::move(result);
                    completed[i] = true;
                }));
    };
    start(0);
    while (peer.packets != 4 && !expired) io.run_one();
    EXPECT_FALSE(expired) << "leader must send all four real UDP questions";
    start(1);
    io.poll(); // Drain ready admission work while upstream replies remain held.
    signals[cancelled].emit(net::cancellation_type::terminal);
    io.poll();
    EXPECT_TRUE(completed[cancelled]);
    EXPECT_FALSE(completed[1 - cancelled]);
    EXPECT_TRUE(errors[cancelled] || answers[cancelled].error == ::common::ErrorCode::CANCELLED) << "cancelled same-domain waiter must observe cancellation";
    if (!expired) peer.Flush("same.example");
    while (!completed[1 - cancelled] && !expired) io.run_one();
    EXPECT_FALSE(expired);
    EXPECT_FALSE(errors[1 - cancelled]);
    EXPECT_TRUE(answers[1 - cancelled].Ok());
    EXPECT_EQ(answers[1 - cancelled].addresses.size(), 4u);
    EXPECT_EQ(peer.packets, 4u);
    bool joined = false;
    std::exception_ptr join_error;
    net::co_spawn(io, worker.AsyncJoin(), [&](std::exception_ptr error) {
        join_error = error;
        joined = true;
        watchdog.cancel();
        peer.Stop();
    });
    io.run();
    if (join_error) std::rethrow_exception(join_error);
    EXPECT_TRUE(joined);
    EXPECT_FALSE(expired);
}

struct MalformedAnswer {
    int type;
    bool fallback;
};
class DnsMalformedAnswer : public testing::TestWithParam<MalformedAnswer> {};
TEST_P(DnsMalformedAnswer, RejectsInvalidAddressLengthWithoutPoisoningCache) {
    const auto [type, fallback] = GetParam();
    net::io_context io;
    Peer first(io), second(io);
    first.malformed_type = type;
    auto config = Config(first);
    if (fallback) config.servers.push_back(second.socket.local_endpoint());
    ::app::dns::DNSWorker worker(io, config, 8);
    std::exception_ptr failure;
    bool done = false;
    auto run = [&]() -> net::awaitable<void> {
        auto result = co_await worker.Resolve("malformed.example");
        if (fallback) {
            EXPECT_TRUE(result.Ok());
            EXPECT_FALSE(result.from_cache);
            EXPECT_EQ(first.packets, 4u);
            EXPECT_EQ(second.packets, 4u);
            result = co_await worker.Resolve("malformed.example");
            EXPECT_TRUE(result.Ok());
            EXPECT_TRUE(result.from_cache);
            EXPECT_EQ(first.packets, 4u);
            EXPECT_EQ(second.packets, 4u);
        } else {
            EXPECT_EQ(result.error, ::common::ErrorCode::DNS_FORMAT_ERROR);
            result = co_await worker.Resolve("malformed.example");
            EXPECT_EQ(result.error, ::common::ErrorCode::DNS_FORMAT_ERROR);
            EXPECT_FALSE(result.from_cache);
            EXPECT_EQ(first.packets, 8u);
            EXPECT_EQ(second.packets, 0u);
        }
        co_await worker.AsyncJoin();
    };
    net::co_spawn(io, run(), [&](std::exception_ptr error) {
        failure = error; done = true; first.Stop(); second.Stop();
    });
    io.run_for(3s);
    const bool completed_before_cleanup = done;
    first.Stop();
    second.Stop();
    JoinService(io, worker);
    EXPECT_TRUE(completed_before_cleanup);
    if (failure) std::rethrow_exception(failure);
    EXPECT_TRUE(done) << "malformed fallback test timed out";
}

TEST(DnsDatagram, RefusedUpstreamFallsBackAfterOutstandingQueriesFinish) {
    net::io_context io;
    Peer first(io), second(io);
    first.refuse = true;
    auto config = Config(first);
    config.servers.push_back(second.socket.local_endpoint());
    ::app::dns::DNSWorker worker(io, config, 8);
    DNS dns(worker);
    bool ok = false;
    net::co_spawn(io, dns.Resolve("fallback.example"), [&](std::exception_ptr e, DnsResult result) {
        ok = !e && result.Ok(); first.Stop(); second.Stop();
    });
    io.run_for(3s);
    first.Stop();
    second.Stop();
    JoinService(io, worker);
    EXPECT_TRUE(ok);
    EXPECT_EQ(first.packets, 4u);
    EXPECT_EQ(second.packets, 4u);
}

TEST(DnsDatagram, ExhaustedTransactionIdsRotatePortWithoutReuse) {
    net::io_context io;
    Peer peer(io);
    peer.batch_size = 1;
    auto transport = std::make_shared<::app::dns::DatagramExchange>(io, peer.socket.local_endpoint());
    std::exception_ptr error;
    bool done = false;
    auto run = [&]() -> net::awaitable<void> {
        std::array<uint8_t, 19> query{0,0,1,0,0,1,0,0,0,0,0,0,1,'r',0,0,1,0,1};
        for (size_t i = 0; i < 65537; ++i) {
            auto result = co_await transport->Exchange(query, 1s);
            EXPECT_FALSE(result.error);
            EXPECT_GT(result.size, 12u);
        }
    };
    net::co_spawn(io, run(), [&](std::exception_ptr e) { error = e; done = true; peer.Stop(); });
    io.run_for(12s);
    const bool completed_before_cleanup = done;
    peer.Stop();
    JoinService(io, *transport);
    EXPECT_TRUE(completed_before_cleanup);
    EXPECT_TRUE(done);
    EXPECT_EQ(peer.packets, 65537u);
    EXPECT_EQ(peer.ports.size(), 2u);
    EXPECT_FALSE(peer.duplicate_id);
    if (error) std::rethrow_exception(error);
}

TEST(DnsDatagram, CacheWriteFailurePreservesAnswerAndLaterWriteRecovers) {
    const auto rejected = ::memory::rejected_process_allocations;
    net::io_context io;
    Peer peer(io);
    ::app::dns::DNSWorker worker(io, Config(peer), 8);
    DNS dns(worker);
    std::exception_ptr error;
    bool done = false;
    auto run = [&]() -> net::awaitable<void> {
        peer.fault_cache_write = true;
        auto result = co_await dns.Resolve("cache-fault.example");
        peer.fault_cache_write = false;
        const bool fault_consumed = !::memory::reject_next_process_allocation;
        ::memory::reject_next_process_allocation = false;
        const auto failed_stats = co_await worker.GetCacheStats();
        EXPECT_TRUE(result.Ok());
        EXPECT_EQ(result.addresses.size(), 4u);
        EXPECT_TRUE(fault_consumed);
        EXPECT_GT(::memory::rejected_process_allocations, rejected);
        EXPECT_EQ(failed_stats.entries, 0u);
        result = co_await dns.Resolve("cache-fault.example");
        const auto recovered_stats = co_await worker.GetCacheStats();
        EXPECT_TRUE(result.Ok());
        EXPECT_EQ(result.addresses.size(), 4u);
        EXPECT_EQ(recovered_stats.entries, 1u);
    };
    net::co_spawn(io, run(), [&](std::exception_ptr e) { error = e; done = true; peer.Stop(); });
    io.run_for(3s);
    ::memory::reject_next_process_allocation = false;
    const bool completed_before_cleanup = done;
    peer.Stop();
    JoinService(io, worker);
    EXPECT_TRUE(completed_before_cleanup);
    EXPECT_TRUE(done) << "cache fault test timed out";
    if (error) std::rethrow_exception(error);
}

TEST(DnsDatagram, ServiceStopJoinsQueriesAndRejectsLateRepliesWithoutFallback) {
    net::io_context io;
    Peer peer(io), fallback(io);
    peer.hold = true;
    auto config = Config(peer);
    config.servers.push_back(fallback.socket.local_endpoint());
    config.timeout_sec = 30;
    auto worker = std::make_unique<::app::dns::DNSWorker>(io, config, 8);
    std::array<DnsResult, 5> answers;
    std::array<std::exception_ptr, 5> errors;
    size_t completed = 0;
    for (size_t i = 0; i < answers.size(); ++i) {
        net::co_spawn(io, worker->Resolve(i < 3 ? "shared.example" :
                                         i == 3 ? "second.example" : "third.example"),
            [&, i](std::exception_ptr error, DnsResult result) {
                errors[i] = error;
                answers[i] = std::move(result);
                ++completed;
            });
    }
    net::steady_timer watchdog(io, 2s);
    bool expired = false;
    watchdog.async_wait([&](::IoErrorCode ec) {
        if (!ec) { expired = true; worker->RequestStop(); }
    });
    while (peer.packets != 12 && !expired) io.run_one();
    EXPECT_FALSE(expired) << "all DNS leaders must reach their upstream before service stop";
    worker->RequestStop();
    worker->RequestStop();
    // Real late datagrams must neither revive a stopped receive nor trigger
    // fallback to another configured upstream.
    for (const auto& [name, group] : peer.queries) {
        for (const auto& query : group) {
            auto reply = query.bytes;
            reply[2] = 0x81;
            reply[3] = 0x83;
            ::IoErrorCode ignored;
            peer.socket.send_to(net::buffer(reply), query.sender, 0, ignored);
        }
    }
    bool joined = false;
    std::exception_ptr join_error;
    auto stop = [&]() -> net::awaitable<void> {
        const auto rejected = co_await worker->Resolve("192.0.2.9");
        EXPECT_EQ(rejected.error, ::common::ErrorCode::CANCELLED) << "stopped DNS must reject even a literal without doing new work";
        co_await worker->AsyncJoin();
        co_await worker->AsyncJoin();
        worker.reset();
    };
    net::co_spawn(io, stop(), [&](std::exception_ptr error) {
        join_error = error;
        joined = true;
        watchdog.cancel();
        peer.Stop();
        fallback.Stop();
    });
    io.run();
    EXPECT_FALSE(expired);
    EXPECT_TRUE(joined);
    EXPECT_EQ(completed, answers.size());
    if (join_error) std::rethrow_exception(join_error);
    for (size_t i = 0; i < answers.size(); ++i) {
        EXPECT_FALSE(errors[i]) << i;
        EXPECT_EQ(answers[i].error, ::common::ErrorCode::CANCELLED) << i;
    }
    EXPECT_EQ(peer.packets, 12u);
    EXPECT_EQ(fallback.packets, 0u);
}

class DnsDatagramStop : public testing::TestWithParam<bool> {};
TEST_P(DnsDatagramStop, JoinsReceiveOwnerAndRejectsNewExchanges) {
    const bool active = GetParam();
    net::io_context io;
    Peer peer(io);
    peer.hold = true;
    peer.batch_size = 1;
    auto transport = std::make_shared<::app::dns::DatagramExchange>(
        io, peer.socket.local_endpoint());
    std::weak_ptr weak = transport;
    std::array<uint8_t, 19> query{0,0,1,0,0,1,0,0,0,0,0,0,1,'r',0,0,1,0,1};
    bool query_done = !active;
    std::exception_ptr query_error;
    ::IoErrorCode reply_error;
    if (active) {
        net::co_spawn(io, transport->Exchange(query, 30s),
            [&](std::exception_ptr error, ::app::dns::DatagramExchange::Reply reply) {
                query_error = error;
                reply_error = reply.error;
                query_done = true;
            });
    }
    net::steady_timer watchdog(io, 2s);
    bool expired = false;
    watchdog.async_wait([&](::IoErrorCode ec) {
        if (!ec) { expired = true; transport->RequestStop(); }
    });
    while (active && peer.packets != 1 && !expired) io.run_one();
    EXPECT_FALSE(expired) << "the datagram exchange must start real receive I/O";
    transport->RequestStop();
    transport->RequestStop();
    bool joined = false;
    std::exception_ptr join_error;
    auto stop = [&]() -> net::awaitable<void> {
        co_await transport->AsyncJoin();
        const auto rejected = co_await transport->Exchange(query, 30s);
        EXPECT_EQ(rejected.error, ::io_error::operation_aborted) << "a stopped exchange must not reopen its socket";
        transport.reset();
        EXPECT_TRUE(weak.expired()) << "join must release the actual receive callback's captured owner";
    };
    net::co_spawn(io, stop(), [&](std::exception_ptr error) {
        joined = true;
        join_error = error;
        watchdog.cancel();
        peer.Stop();
    });
    io.run();
    EXPECT_FALSE(expired);
    EXPECT_TRUE(joined);
    EXPECT_TRUE(query_done);
    EXPECT_FALSE(query_error);
    if (join_error) std::rethrow_exception(join_error);
    if (active) EXPECT_EQ(reply_error, ::io_error::operation_aborted);
    EXPECT_EQ(peer.packets, (active ? 1 : 0)) << "zero-query stop and late rejected queries must not send datagrams";
}

TEST(DnsDatagram, AllocationFailureUnwindsBeforeStopAndJoin) {
    const auto rejected = ::memory::rejected_process_allocations;
    net::io_context io;
    Peer peer(io);
    auto transport = std::make_shared<::app::dns::DatagramExchange>(
        io, peer.socket.local_endpoint());
    std::weak_ptr weak = transport;
    std::array<uint8_t, 19> query{0,0,1,0,0,1,0,0,0,0,0,0,1,'r',0,0,1,0,1};
    bool failed = false, joined = false;
    std::exception_ptr failure;
    auto run = [&]() -> net::awaitable<void> {
        // Query registration is the exchange's first process-layer allocation.
        ::memory::reject_next_process_allocation = true;
        try {
            (void)co_await transport->Exchange(query, 30s);
        } catch (const std::bad_alloc&) {
            failed = true;
        }
        ::memory::reject_next_process_allocation = false;
        transport->RequestStop();
        co_await transport->AsyncJoin();
        transport.reset();
        EXPECT_TRUE(weak.expired()) << "failed exchange startup must retain no receive owner";
    };
    net::co_spawn(io, run(), [&](std::exception_ptr error) {
        failure = error;
        joined = true;
        peer.Stop();
    });
    io.run_for(2s);
    ::memory::reject_next_process_allocation = false;
    if (failure) std::rethrow_exception(failure);
    EXPECT_TRUE(joined);
    EXPECT_TRUE(failed);
    EXPECT_GT(::memory::rejected_process_allocations, rejected);
    EXPECT_EQ(peer.packets, 0u);
}
}
INSTANTIATE_TEST_SUITE_P(TransportFamily, DnsDatagramQueries, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) { return info.param ? "Ipv6" : "Ipv4"; });
INSTANTIATE_TEST_SUITE_P(RequestEnd, DnsDatagramIsolation, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) { return info.param ? "Cancellation" : "Timeout"; });
INSTANTIATE_TEST_SUITE_P(WaiterRole, DnsSameDomainCancellation, testing::Values(size_t{0}, size_t{1}),
    [](const testing::TestParamInfo<size_t>& info) { return info.param == 0 ? "Leader" : "Follower"; });
INSTANTIATE_TEST_SUITE_P(Upstreams, DnsMalformedAnswer, testing::Values(
    MalformedAnswer{1, false}, MalformedAnswer{28, false},
    MalformedAnswer{1, true}, MalformedAnswer{28, true}),
    [](const testing::TestParamInfo<MalformedAnswer>& info) {
        return std::string(info.param.type == 1 ? "A" : "Aaaa") +
            (info.param.fallback ? "WithFallback" : "WithoutFallback");
    });
INSTANTIATE_TEST_SUITE_P(Startup, DnsDatagramStop, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) { return info.param ? "PendingQuery" : "Unused"; });

struct TtlCase {
    uint32_t wire;
    uint32_t expected;
    int type = 0;
};
class DnsTtl : public testing::TestWithParam<TtlCase> {};

TEST_P(DnsTtl, PreservesAddressesButDoesNotCacheZeroTtl) {
    const auto [wire_ttl, expected_ttl, affected_type] = GetParam();
    net::io_context io;
    Peer peer(io);
    peer.answer_ttl = wire_ttl;
    peer.ttl_type = affected_type;
    auto config = Config(peer);
    config.min_ttl = 60;
    config.max_ttl = 3600;
    ::app::dns::DNSWorker worker(io, config, 8);
    DNS dns(worker);
    bool done = false;
    std::exception_ptr error;
    auto run = [&]() -> net::awaitable<void> {
        const auto first = co_await dns.Resolve("ttl.example");
        const auto second = co_await dns.Resolve("TTL.EXAMPLE.");
        const std::vector<net::ip::address> expected{
            net::ip::make_address("192.0.2.1"), net::ip::make_address("192.0.2.2"),
            net::ip::make_address("192.0.2.3"), net::ip::make_address("2001:db8::1")};
        EXPECT_EQ(first.addresses, expected);
        EXPECT_EQ(second.addresses, expected);
        EXPECT_EQ(first.ttl, expected_ttl);
        EXPECT_EQ(second.from_cache, expected_ttl != 0);
        EXPECT_EQ(peer.packets, expected_ttl == 0 ? 8u : 4u);
        if (expected_ttl == 0) EXPECT_EQ(second.ttl, 0);
        co_await worker.AsyncJoin();
    };
    net::co_spawn(io, run(), [&](std::exception_ptr failure) {
        error = failure;
        done = true;
        peer.Stop();
    });
    io.run_for(3s);
    const bool completed_before_cleanup = done;
    peer.Stop();
    JoinService(io, worker);
    EXPECT_TRUE(completed_before_cleanup);
    EXPECT_TRUE(done);
    if (error) std::rethrow_exception(error);
}

INSTANTIATE_TEST_SUITE_P(WireBoundaries, DnsTtl, testing::Values(
    TtlCase{0, 0}, TtlCase{60, 60}, TtlCase{0x7fffffffu, 0x7fffffffu},
    TtlCase{0x80000000u, 0}, TtlCase{0xffffffffu, 0},
    TtlCase{0x80000000u, 0, 1}, TtlCase{0x80000000u, 0, 28}),
    [](const testing::TestParamInfo<TtlCase>& info) {
        return "raw_" + std::to_string(info.param.wire) + "_type_" + std::to_string(info.param.type);
    });
