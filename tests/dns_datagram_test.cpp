#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/allocator.hpp"
#include "app/dns/datagram_exchange.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
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
void Require(bool yes, const char* why) { if (!yes) throw std::runtime_error(why); }

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

DNS::Config Config(Peer& peer) {
    DNS::Config c;
    c.servers = {peer.socket.local_endpoint()}; c.min_ttl = 1; c.timeout_sec = 1;
    return c;
}

void TestQueries(bool ipv6) {
    net::io_context io;
    Peer peer(io, ipv6);
    peer.noise = true;
    DNS dns(io, Config(peer));
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
    net::co_spawn(io, run(), [&](std::exception_ptr e) { error = e; done = true; peer.Stop(); });
    io.run_for(4s);
    Require(done, "parallel DNS query test timed out");
    if (error) std::rethrow_exception(error);
}

void TestIsolation(bool cancel) {
    net::io_context io;
    Peer peer(io);
    peer.hold = cancel;
    DNS dns(io, Config(peer));
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
    if (cancel) timer.async_wait([&](acpp::IoErrorCode ec) {
        if (!ec) { signal.emit(net::cancellation_type::terminal); peer.Flush("other.example"); }
    });
    io.run_for(3s);
    Require(completed == 2 && !errors[1] && answers[1].Ok(),
            "one cancellation/timeout must not cancel another query's shared socket");
    Require(cancel ? (errors[0] || !answers[0].Ok()) : answers[0].error == acpp::ErrorCode::DNS_TIMEOUT,
            "cancelled or expired requests must return promptly");
    Require(peer.ports.size() == 1, "concurrent requests must multiplex one socket");
}

void TestFallback() {
    net::io_context io;
    Peer first(io), second(io);
    first.refuse = true;
    auto config = Config(first);
    config.servers.push_back(second.socket.local_endpoint());
    DNS dns(io, config);
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
    auto transport = std::make_shared<acpp::app::dns::DatagramExchange>(io, peer.socket.local_endpoint());
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
private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (!faults && bytes == 4 * sizeof(net::ip::address)) { ++faults; throw std::bad_alloc(); }
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
        DNS dns(io, Config(peer));
        std::exception_ptr error;
        bool done = false;
        auto run = [&]() -> net::awaitable<void> {
            auto result = co_await dns.Resolve("cache-fault.example");
            Require(result.Ok() && resource.faults == 1 && dns.GetCacheStats().entries == 0,
                    "cache allocation failure must not discard the acquired answer");
            result = co_await dns.Resolve("cache-fault.example");
            Require(result.Ok() && dns.GetCacheStats().entries == 1,
                    "cache must recover after write failure");
        };
        net::co_spawn(io, run(), [&](std::exception_ptr e) { error = e; done = true; peer.Stop(); });
        io.run_for(3s);
        Require(done, "cache fault test timed out");
        if (error) std::rethrow_exception(error);
    } catch (...) { std::pmr::set_default_resource(original); throw; }
    std::pmr::set_default_resource(original);
}
}
int main() {
    acpp::memory::ConfigureProcessAllocator();
    try { TestQueries(false); TestQueries(true); TestIsolation(true); TestIsolation(false); TestFallback(); TestCacheFailure(); TestIdRotation(); }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
    std::cout << "DNS parallel sampling / socket reuse / validation / isolation / fallback / cache: PASS\n";
}
