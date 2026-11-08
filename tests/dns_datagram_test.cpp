#include <gtest/gtest.h>

#include "app/dns/dns_worker.hpp"
#include "common/allocator.hpp"
#include "app/dns/datagram_exchange.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <array>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;
using ::app::dns::DNS;
using ::app::dns::DnsResult;
void Require(bool yes, const char* why) { if (!yes) throw std::runtime_error(why); }

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
        Require(group.size() == batch_size, "all queries must be outstanding together");
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
    }
    ::udp::socket socket, foreign;
    ::udp::endpoint sender;
    std::array<uint8_t, 512> buffer{};
    std::map<std::string, std::vector<Query>> queries;
    std::set<uint16_t> ports;
    std::map<uint16_t, std::bitset<65536>> ids;
    size_t packets = 0, batch_size = 4;
    bool hold = false, refuse = false, negative = false, nodata = false;
    bool noise = false, duplicate_id = false;
    int malformed_type = 0;
    std::optional<uint32_t> answer_ttl;
    int ttl_type = 0;
};

::app::dns::Config Config(Peer& peer) {
    ::app::dns::Config c;
    c.servers = {peer.socket.local_endpoint()}; c.min_ttl = 1; c.timeout_sec = 1;
    return c;
}

void TestQueries(bool ipv6) {
    net::io_context io;
    Peer peer(io, ipv6);
    peer.noise = true;
    ::app::dns::DNSWorker worker(io, Config(peer), 8);
    DNS dns(worker);
    std::exception_ptr error;
    bool done = false;
    auto run = [&]() -> net::awaitable<void> {
        auto result = co_await dns.Resolve("first.example");
        Require(result.Ok() && result.addresses.size() == 4 && result.ttl == 10,
                "out-of-order responses must preserve multi-address union and minimum TTL");
        Require(result.addresses[0] == net::ip::make_address("192.0.2.1") &&
                result.addresses[3] == net::ip::make_address("2001:db8::1"),
                "unrelated, wrong-question and foreign packets must not poison results");
        auto cached = co_await dns.Resolve("FIRST.EXAMPLE.");
        Require(cached.Ok() && cached.from_cache && peer.packets == 4,
                "canonical names must share the one cache");
        result = co_await dns.Resolve("second.example");
        Require(result.Ok() && peer.packets == 8 && peer.ports.size() == 1,
                "separate resolutions must reuse the same connected UDP socket");
        peer.negative = true;
        result = co_await dns.Resolve("negative.example");
        Require(result.error == ::ErrorCode::DNS_NO_RECORD, "NXDOMAIN must be retained");
        result = co_await dns.Resolve("negative.example");
        Require(result.from_cache && peer.packets == 12, "negative answers must be cached");
        peer.negative = false;
        peer.nodata = true;
        result = co_await dns.Resolve("nodata.example");
        Require(result.error == ::ErrorCode::DNS_NO_RECORD &&
                    result.error_msg.find("NODATA") != std::string::npos,
                "an existing name without addresses must be distinguished from NXDOMAIN");
        result = co_await dns.Resolve("nodata.example");
        Require(result.from_cache && peer.packets == 16 &&
                    result.error_msg.find("NODATA") != std::string::npos &&
                    result.error_msg.find("NXDOMAIN") == std::string::npos,
                "negative cache must not turn NODATA into NXDOMAIN");
    };
    net::co_spawn(io, run(), [&](std::exception_ptr e) { error = e; done = true; peer.Stop(); });
    io.run_for(4s);
    Require(done, "parallel DNS query test timed out");
    if (error) std::rethrow_exception(error);
}

void TestIsolation(bool cancel) {
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
    Require(completed == 2 && !errors[1] && answers[1].Ok(),
            "one cancellation/timeout must not cancel another query's shared socket");
    Require(cancel ? (errors[0] || !answers[0].Ok()) : answers[0].error == ::ErrorCode::DNS_TIMEOUT,
            "cancelled or expired requests must return promptly");
    Require(peer.ports.size() == 1, "concurrent requests must multiplex one socket");
}

void TestSameDomainCancellation(size_t cancelled) {
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
        if (!ec) { expired = true; io.stop(); }
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
    Require(!expired, "leader must send all four real UDP questions");
    start(1);
    io.poll(); // Drain ready admission work while upstream replies remain held.
    signals[cancelled].emit(net::cancellation_type::terminal);
    io.poll();
    Require(completed[cancelled] && !completed[1 - cancelled],
            "only the cancelled same-domain waiter may finish before the UDP reply");
    Require(errors[cancelled] || answers[cancelled].error == ::ErrorCode::CANCELLED,
            "cancelled same-domain waiter must observe cancellation");
    peer.Flush("same.example");
    while (!completed[1 - cancelled] && !expired) io.run_one();
    Require(!expired && !errors[1 - cancelled] && answers[1 - cancelled].Ok() &&
                answers[1 - cancelled].addresses.size() == 4 && peer.packets == 4,
            "surviving same-domain waiter must receive the original real UDP answer");
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
    Require(joined && !expired, "same-domain cancellation must leave join quiescent");
}

void TestMalformedFallback(int type, bool fallback) {
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
            Require(result.Ok() && !result.from_cache && first.packets == 4 && second.packets == 4,
                    "malformed address length must try the healthy fallback");
            result = co_await worker.Resolve("malformed.example");
            Require(result.Ok() && result.from_cache && first.packets == 4 && second.packets == 4,
                    "fallback success must enter the positive cache, never a negative cache");
        } else {
            Require(result.error == ::ErrorCode::DNS_FORMAT_ERROR &&
                        result.error_msg.find(type == 1 ? "A record has invalid RDLENGTH 3" :
                                                        "AAAA record has invalid RDLENGTH 15") != std::string::npos,
                    "malformed address length must retain a precise format-error reason");
            result = co_await worker.Resolve("malformed.example");
            Require(result.error == ::ErrorCode::DNS_FORMAT_ERROR && !result.from_cache &&
                        first.packets == 8 && second.packets == 0,
                    "malformed answers must never poison the negative cache");
        }
        co_await worker.AsyncJoin();
    };
    net::co_spawn(io, run(), [&](std::exception_ptr error) {
        failure = error; done = true; first.Stop(); second.Stop();
    });
    io.run_for(3s);
    if (failure) std::rethrow_exception(failure);
    Require(done, "malformed fallback test timed out");
}

void TestFallback() {
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
    Require(ok && first.packets == 4 && second.packets == 4,
            "failed upstream must fall back after all started queries are joined");
}

void TestIdRotation() {
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
            Require(!result.error && result.size > 12, "ID retirement must preserve replies");
        }
    };
    net::co_spawn(io, run(), [&](std::exception_ptr e) { error = e; done = true; peer.Stop(); });
    io.run_for(12s);
    Require(done && peer.packets == 65537 && peer.ports.size() == 2 && !peer.duplicate_id,
            "65536 unique IDs must rotate the source port, never reuse a live socket's ID");
    if (error) std::rethrow_exception(error);
}

class CacheFault : public std::pmr::memory_resource {
public:
    explicit CacheFault(std::pmr::memory_resource* resource) : upstream(resource) {}
    size_t faults = 0;
    bool fail_next = false;
private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (fail_next || (!faults && bytes == 4 * sizeof(net::ip::address))) {
            fail_next = false;
            ++faults;
            throw std::bad_alloc();
        }
        return upstream->allocate(bytes, alignment);
    }
    void do_deallocate(void* p, size_t bytes, size_t alignment) override { upstream->deallocate(p, bytes, alignment); }
    bool do_is_equal(const std::pmr::memory_resource& r) const noexcept override { return &r == this; }
    std::pmr::memory_resource* upstream;
};

void TestCacheFailure() {
    CacheFault resource(std::pmr::get_default_resource());
    const auto original = std::pmr::set_default_resource(&resource);
    try {
        net::io_context io;
        Peer peer(io);
        ::app::dns::DNSWorker worker(io, Config(peer), 8);
        DNS dns(worker);
        std::exception_ptr error;
        bool done = false;
        auto run = [&]() -> net::awaitable<void> {
            auto result = co_await dns.Resolve("cache-fault.example");
            const auto failed_stats = co_await worker.GetCacheStats();
            Require(result.Ok() && resource.faults == 1 && failed_stats.entries == 0,
                    "cache allocation failure must not discard the acquired answer");
            result = co_await dns.Resolve("cache-fault.example");
            const auto recovered_stats = co_await worker.GetCacheStats();
            Require(result.Ok() && recovered_stats.entries == 1,
                    "cache must recover after write failure");
        };
        net::co_spawn(io, run(), [&](std::exception_ptr e) { error = e; done = true; peer.Stop(); });
        io.run_for(3s);
        Require(done, "cache fault test timed out");
        if (error) std::rethrow_exception(error);
    } catch (...) { std::pmr::set_default_resource(original); throw; }
    std::pmr::set_default_resource(original);
}

void TestServiceStopJoin() {
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
        if (!ec) { expired = true; io.stop(); }
    });
    while (peer.packets != 12 && !expired) io.run_one();
    Require(!expired, "all DNS leaders must reach their upstream before service stop");
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
        Require(rejected.error == ::ErrorCode::CANCELLED,
                "stopped DNS must reject even a literal without doing new work");
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
    Require(!expired && joined && completed == answers.size(),
            "stop must join every accepted leader and subscriber promptly");
    if (join_error) std::rethrow_exception(join_error);
    for (size_t i = 0; i < answers.size(); ++i) {
        Require(!errors[i] && answers[i].error == ::ErrorCode::CANCELLED,
                "service cancellation must survive leader and subscriber completion");
    }
    Require(peer.packets == 12 && fallback.packets == 0,
            "late responses and cancellation must not restart queries or upstream fallback");
}

void TestDatagramStopJoin(bool active) {
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
        if (!ec) { expired = true; io.stop(); }
    });
    while (active && peer.packets != 1 && !expired) io.run_one();
    Require(!expired, "the datagram exchange must start real receive I/O");
    transport->RequestStop();
    transport->RequestStop();
    bool joined = false;
    std::exception_ptr join_error;
    auto stop = [&]() -> net::awaitable<void> {
        co_await transport->AsyncJoin();
        const auto rejected = co_await transport->Exchange(query, 30s);
        Require(rejected.error == ::io_error::operation_aborted,
                "a stopped exchange must not reopen its socket");
        transport.reset();
        Require(weak.expired(),
                "join must release the actual receive callback's captured owner");
    };
    net::co_spawn(io, stop(), [&](std::exception_ptr error) {
        joined = true;
        join_error = error;
        watchdog.cancel();
        peer.Stop();
    });
    io.run();
    Require(!expired && joined && query_done && !query_error,
            "exchange and receive completions must both finish before destruction");
    if (join_error) std::rethrow_exception(join_error);
    Require(!active || reply_error == ::io_error::operation_aborted,
            "the stopped pending query must retain cancellation");
    Require(peer.packets == (active ? 1 : 0),
            "zero-query stop and late rejected queries must not send datagrams");
}

void TestDatagramAllocationFailureJoin() {
    CacheFault resource(std::pmr::get_default_resource());
    const auto original = std::pmr::set_default_resource(&resource);
    try {
        net::io_context io;
        Peer peer(io);
        auto transport = std::make_shared<::app::dns::DatagramExchange>(
            io, peer.socket.local_endpoint());
        std::weak_ptr weak = transport;
        std::array<uint8_t, 19> query{0,0,1,0,0,1,0,0,0,0,0,0,1,'r',0,0,1,0,1};
        resource.fail_next = true;
        bool failed = false, joined = false;
        std::exception_ptr failure;
        auto run = [&]() -> net::awaitable<void> {
            try {
                (void)co_await transport->Exchange(query, 30s);
            } catch (const std::bad_alloc&) {
                failed = true;
            }
            transport->RequestStop();
            co_await transport->AsyncJoin();
            transport.reset();
            Require(weak.expired(), "failed exchange startup must retain no receive owner");
        };
        net::co_spawn(io, run(), [&](std::exception_ptr error) {
            failure = error;
            joined = true;
            peer.Stop();
        });
        io.run_for(2s);
        if (failure) std::rethrow_exception(failure);
        Require(joined && failed && resource.faults == 1 && peer.packets == 0,
                "query registration allocation failure must unwind before stop and join");
    } catch (...) {
        std::pmr::set_default_resource(original);
        throw;
    }
    std::pmr::set_default_resource(original);
}
}
TEST(DnsDatagram, Contract) {
    ::memory::ConfigureProcessAllocator();
    try {
        TestQueries(false); TestQueries(true); TestIsolation(true); TestIsolation(false);
        TestSameDomainCancellation(0); TestSameDomainCancellation(1);
        TestMalformedFallback(1, true); TestMalformedFallback(28, true);
        TestMalformedFallback(1, false); TestMalformedFallback(28, false);
        TestFallback(); TestCacheFailure(); TestIdRotation();
        TestServiceStopJoin(); TestDatagramStopJoin(false); TestDatagramStopJoin(true);
        TestDatagramAllocationFailureJoin();
    }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; FAIL() << e.what(); }
    std::cout << "DNS parallel sampling / socket reuse / validation / isolation / fallback / cache: PASS\n";
}

struct TtlCase {
    uint32_t wire;
    uint32_t expected;
    int type = 0;
};
class DnsTtl : public testing::TestWithParam<TtlCase> {};

TEST_P(DnsTtl, PreservesAddressesButDoesNotCacheZeroTtl) {
    ::memory::ConfigureProcessAllocator();
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
