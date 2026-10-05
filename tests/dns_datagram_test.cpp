#include "acppnode/app/dns/dns_service.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/common/allocator.hpp"
#include "data_allocation_probe.hpp"
#include "app/dns/datagram_exchange.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <array>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>

namespace {
namespace net = acpp::net;
using namespace std::chrono_literals;
using acpp::app::dns::DNS;
using acpp::app::dns::DnsResult;
class TimeoutSchedulerScope final {
public:
    explicit TimeoutSchedulerScope(net::any_io_executor executor) : executor_(std::move(executor)) {
        acpp::TimeoutScheduler::Install(executor_);
    }
    ~TimeoutSchedulerScope() { acpp::TimeoutScheduler::ReleaseForExecutor(executor_); }
private:
    net::any_io_executor executor_;
};
void Require(bool yes, const char* why) { if (!yes) throw std::runtime_error(why); }

class DNSServiceRun final {
public:
    DNSServiceRun(net::io_context& io, acpp::app::dns::DNSService& service)
        : io_(io), service_(service), stopped_(io, 1) {
        net::co_spawn(io_, service_.Run(), [this](std::exception_ptr error) {
            stopped_.try_send(error);
        });
    }

    template <typename Handler>
    void CloseAndJoin(std::exception_ptr error, Handler handler) {
        net::co_spawn(io_, CloseAndJoinOwned(), [error, handler = std::move(handler)](std::exception_ptr close_error) mutable {
            handler(error ? error : close_error);
        });
    }

private:
    net::awaitable<void> CloseAndJoinOwned() {
        co_await service_.Close();
        auto [run_error] = co_await stopped_.async_receive(net::as_tuple(net::use_awaitable));
        if (run_error) std::rethrow_exception(run_error);
    }

    net::io_context& io_;
    acpp::app::dns::DNSService& service_;
    net::experimental::concurrent_channel<void(std::exception_ptr)> stopped_;
};

struct Peer {
    struct Query { std::vector<uint8_t> bytes; acpp::udp::endpoint sender; };
    explicit Peer(net::io_context& io, bool ipv6 = false)
        : socket(io, {ipv6 ? net::ip::address(net::ip::address_v6::loopback()) :
                     net::ip::address(net::ip::address_v4::loopback()), 0}), foreign(io) {
        foreign.open(socket.local_endpoint().protocol());
        Receive();
    }
    void Stop() { socket.close(); foreign.close(); }
    void Receive() {
        socket.async_receive_from(net::buffer(buffer), sender, [&](acpp::IoErrorCode ec, size_t size) {
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
            if (!refuse && !negative) {
                packet[7] = 1;
                const uint8_t size = v6 ? 16 : 4;
                packet.insert(packet.end(), {0xc0, 0x0c, 0, static_cast<uint8_t>(v6 ? 28 : 1),
                    0, 1, 0, 0, 0, static_cast<uint8_t>(ordinal * 10), 0, size});
                if (v6) {
                    const auto bytes = net::ip::make_address_v6("2001:db8::1").to_bytes();
                    packet.insert(packet.end(), bytes.begin(), bytes.end());
                } else packet.insert(packet.end(), {192, 0, 2, static_cast<uint8_t>(ordinal)});
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
    acpp::udp::socket socket, foreign;
    acpp::udp::endpoint sender;
    std::array<uint8_t, 512> buffer{};
    std::map<std::string, std::vector<Query>> queries;
    std::set<uint16_t> ports;
    std::map<uint16_t, std::bitset<65536>> ids;
    size_t packets = 0, batch_size = 4;
    bool hold = false, refuse = false, negative = false, noise = false, duplicate_id = false;
};

acpp::app::dns::Config Config(Peer& peer) {
    acpp::app::dns::Config c;
    c.servers = {peer.socket.local_endpoint()}; c.min_ttl = 1; c.timeout_sec = 1;
    return c;
}

void TestQueries(bool ipv6) {
    net::io_context io;
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    Peer peer(io, ipv6);
    peer.noise = true;
    acpp::app::dns::DNSService worker(io.get_executor(), Config(peer), 8);
    DNSServiceRun service_run(io, worker);
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
        Require(result.error == acpp::ErrorCode::DNS_NO_RECORD, "NXDOMAIN must be retained");
        result = co_await dns.Resolve("negative.example");
        Require(result.from_cache && peer.packets == 12, "negative answers must be cached");
    };
    net::co_spawn(io, run(), [&](std::exception_ptr e) {
        service_run.CloseAndJoin(e, [&](std::exception_ptr close_error) {
            error = close_error; done = true; peer.Stop();
        });
    });
    io.run_for(4s);
    Require(done, "parallel DNS query test timed out");
    if (error) std::rethrow_exception(error);
}

void TestIsolation(bool cancel) {
    net::io_context io;
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    Peer peer(io);
    peer.hold = cancel;
    acpp::app::dns::DNSService worker(io.get_executor(), Config(peer), 8);
    DNSServiceRun service_run(io, worker);
    DNS dns(worker);
    net::cancellation_signal signal;
    std::array<DnsResult, 2> answers;
    std::array<std::exception_ptr, 2> errors;
    bool service_closed = false;
    size_t completed = 0;
    auto finish = [&](size_t i) { return [&, i](std::exception_ptr e, DnsResult result) {
        errors[i] = e; answers[i] = std::move(result);
        if (++completed == 2) service_run.CloseAndJoin({}, [&](std::exception_ptr close_error) {
            service_closed = !close_error;
            if (close_error) errors[0] = close_error;
            peer.Stop();
        });
    }; };
    net::co_spawn(io, dns.Resolve("timeout.example"), net::bind_cancellation_slot(signal.slot(), finish(0)));
    net::co_spawn(io, dns.Resolve("other.example"), finish(1));
    net::steady_timer timer(io, 40ms);
    if (cancel) timer.async_wait([&](acpp::IoErrorCode ec) {
        if (!ec) { signal.emit(net::cancellation_type::terminal); peer.Flush("other.example"); }
    });
    io.run_for(3s);
    Require(completed == 2 && service_closed && !errors[1] && answers[1].Ok(),
            "one cancellation/timeout must not cancel another query's shared socket");
    Require(cancel ? (errors[0] || !answers[0].Ok()) : answers[0].error == acpp::ErrorCode::DNS_TIMEOUT,
            "cancelled or expired requests must return promptly");
    Require(peer.ports.size() == 1, "concurrent requests must multiplex one socket");
}

void TestFallback() {
    net::io_context io;
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    Peer first(io), second(io);
    first.refuse = true;
    auto config = Config(first);
    config.servers.push_back(second.socket.local_endpoint());
    acpp::app::dns::DNSService worker(io.get_executor(), config, 8);
    DNSServiceRun service_run(io, worker);
    DNS dns(worker);
    bool ok = false;
    net::co_spawn(io, dns.Resolve("fallback.example"), [&](std::exception_ptr e, DnsResult result) {
        service_run.CloseAndJoin(e, [&, result = std::move(result)](std::exception_ptr close_error) {
            ok = !close_error && result.Ok(); first.Stop(); second.Stop();
        });
    });
    io.run_for(3s);
    Require(ok && first.packets == 4 && second.packets == 4,
            "failed upstream must fall back after all started queries are joined");
}

void TestIdRotation() {
    net::io_context io;
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    Peer peer(io);
    peer.batch_size = 1;
    auto transport = std::make_shared<acpp::app::dns::DatagramExchange>(io.get_executor(), peer.socket.local_endpoint());
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

std::size_t cache_faults = 0;
bool RejectCacheWrite(std::size_t bytes, std::size_t) noexcept {
    if (!cache_faults && bytes == 4 * sizeof(net::ip::address)) {
        ++cache_faults;
        return true;
    }
    return false;
}

void TestCacheFailure() {
    cache_faults = 0;
    DataAllocationProbe probe(RejectCacheWrite);
    {
        net::io_context io;
        TimeoutSchedulerScope scheduler_scope(io.get_executor());
        Peer peer(io);
        acpp::app::dns::DNSService worker(io.get_executor(), Config(peer), 8);
        DNSServiceRun service_run(io, worker);
        DNS dns(worker);
        std::exception_ptr error;
        bool done = false;
        auto run = [&]() -> net::awaitable<void> {
            auto result = co_await dns.Resolve("cache-fault.example");
            const auto failed_stats = co_await worker.GetCacheStats();
            Require(result.Ok() && cache_faults == 1 && failed_stats.entries == 0,
                    "cache allocation failure must not discard the acquired answer");
            result = co_await dns.Resolve("cache-fault.example");
            const auto recovered_stats = co_await worker.GetCacheStats();
            Require(result.Ok() && recovered_stats.entries == 1,
                    "cache must recover after write failure");
        };
        net::co_spawn(io, run(), [&](std::exception_ptr e) {
            service_run.CloseAndJoin(e, [&](std::exception_ptr close_error) {
                error = close_error; done = true; peer.Stop();
            });
        });
        io.run_for(3s);
        Require(done, "cache fault test timed out");
        if (error) std::rethrow_exception(error);
    }
}
}
int main() {
    acpp::memory::ConfigureProcessAllocator();
    try { TestQueries(false); TestQueries(true); TestIsolation(true); TestIsolation(false); TestFallback(); TestCacheFailure(); TestIdRotation(); }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
    std::cout << "DNS parallel sampling / socket reuse / validation / isolation / fallback / cache: PASS\n";
}
