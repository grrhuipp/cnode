#include <gtest/gtest.h>

#include "app/dns_internal.hpp"
#include "common/allocator.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>
#include <array>
#include <functional>
#include <list>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <asio/detached.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;
using ::app::DNS;
using ::app::DnsResult;

// Builds answers from the echoed question only: resolver queries carry an EDNS
// OPT record after it. Like a real server, a UDP answer larger than the
// advertised payload (512 without OPT, RFC 6891 §6.2.3) is sent with TC=1.
struct Peer {
    struct Query {
        std::vector<uint8_t> bytes;
        ::udp::endpoint sender;
        size_t question_size = 0;
        size_t udp_limit = 512;
        bool has_opt = false;
        bool plain = false;
    };
    explicit Peer(net::io_context& io, bool ipv6 = false)
        : socket(io, {ipv6 ? net::ip::address(net::ip::address_v6::loopback()) :
                     net::ip::address(net::ip::address_v4::loopback()), 0}), foreign(io), acceptor(io) {
        foreign.open(socket.local_endpoint().protocol());
        Receive();
    }
    void Stop() {
        socket.close(); foreign.close(); acceptor.close();
        for (auto& stream : held_streams) stream.close();
    }
    // TCP shares the UDP port number, as a real upstream does.
    void ServeStream() {
        const auto endpoint = socket.local_endpoint();
        acceptor.open(endpoint.protocol() == ::udp::v6() ? ::tcp::v6() : ::tcp::v4());
        acceptor.bind({endpoint.address(), endpoint.port()});
        acceptor.listen();
        net::co_spawn(acceptor.get_executor(), AcceptStreams(), net::detached);
    }
    static Query Inspect(std::vector<uint8_t> bytes, ::udp::endpoint sender = {}) {
        Query query{std::move(bytes), sender};
        size_t pos = 12;
        while (pos < query.bytes.size() && query.bytes[pos]) pos += query.bytes[pos] + 1;
        query.question_size = pos + 1 + 4;
        const size_t opt = query.question_size;
        if (query.bytes[11] == 1 && query.bytes.size() >= opt + 11 && query.bytes[opt] == 0 &&
            query.bytes[opt + 1] == 0 && query.bytes[opt + 2] == 41) {
            query.has_opt = true;
            query.udp_limit = std::max<size_t>(512, (query.bytes[opt + 3] << 8) | query.bytes[opt + 4]);
        }
        query.plain = query.bytes[10] == 0 && query.bytes[11] == 0 &&
                      query.bytes.size() == query.question_size;
        return query;
    }
    std::vector<uint8_t> Answer(const Query& query, int ordinal) const {
        std::vector<uint8_t> packet(query.bytes.begin(), query.bytes.begin() + query.question_size);
        packet[10] = packet[11] = 0;
        const bool v6 = packet[packet.size() - 3] == 28;
        packet[2] = 0x81;
        if (reject_edns && query.has_opt) {
            packet[3] = 0x81;  // FORMERR without OPT: responder lacks EDNS.
            if (reject_without_question) {
                packet.resize(12);
                std::fill(packet.begin() + 4, packet.end(), 0);
            }
            return packet;
        }
        packet[3] = refuse ? 0x82 : negative ? 0x83 : 0x80;
        if ((negative || nodata) && !omit_soa) AppendSoa(packet);
        if (refuse || negative || nodata ||
            (malformed_type != 0 && malformed_type != (v6 ? 28 : 1))) return packet;
        const size_t count = bulk_answers ? bulk_answers : 1;
        packet[6] = static_cast<uint8_t>(count >> 8);
        packet[7] = static_cast<uint8_t>(count);
        const uint8_t size = v6 ? 16 : 4;
        const uint32_t ttl = ttl_type == 0 || ttl_type == (v6 ? 28 : 1)
            ? answer_ttl.value_or(static_cast<uint32_t>(ordinal * 10)) : 60;
        for (size_t i = 0; i < count; ++i) {
            packet.insert(packet.end(), {0xc0, 0x0c, 0, static_cast<uint8_t>(v6 ? 28 : 1),
                0, 1, static_cast<uint8_t>(ttl >> 24), static_cast<uint8_t>(ttl >> 16),
                static_cast<uint8_t>(ttl >> 8), static_cast<uint8_t>(ttl), 0, size});
            if (v6) {
                auto bytes = net::ip::make_address_v6("2001:db8::1").to_bytes();
                if (bulk_answers) bytes.back() = static_cast<uint8_t>(i + 1);
                packet.insert(packet.end(), bytes.begin(), bytes.end());
            } else if (bulk_answers) {
                packet.insert(packet.end(), {198, 51, 100, static_cast<uint8_t>(i + 1)});
            } else {
                packet.insert(packet.end(), {192, 0, 2, static_cast<uint8_t>(ordinal)});
            }
        }
        if (malformed_type == (v6 ? 28 : 1)) {
            packet[query.question_size + 11] = static_cast<uint8_t>(size - 1);
            packet.pop_back();
        }
        return packet;
    }
    // Authority-section SOA (RFC 2308 §3). Owner is the parent of QNAME via a
    // compression pointer, or an unrelated zone; MNAME and RNAME are root.
    void AppendSoa(std::vector<uint8_t>& packet) const {
        packet[9] = 1;  // NSCOUNT
        if (unrelated_soa) {
            const auto owner = WireNameOf("other.test");
            packet.insert(packet.end(), owner.begin(), owner.end());
        } else {
            packet.insert(packet.end(), {0xc0, static_cast<uint8_t>(12 + 1 + packet[12])});
        }
        AppendU16(packet, 6);
        AppendU16(packet, 1);
        AppendU32(packet, soa_ttl);
        AppendU16(packet, 22);
        packet.insert(packet.end(), {0, 0});
        for (uint32_t field : {1u, 7200u, 900u, 1209600u, soa_minimum}) AppendU32(packet, field);
    }
    static std::vector<uint8_t> WireNameOf(std::string_view name) {
        std::vector<uint8_t> wire;
        size_t start = 0;
        while (start < name.size()) {
            const size_t dot = std::min(name.find('.', start), name.size());
            wire.push_back(static_cast<uint8_t>(dot - start));
            wire.insert(wire.end(), name.begin() + start, name.begin() + dot);
            start = dot + 1;
        }
        wire.push_back(0);
        return wire;
    }
    static void AppendU16(std::vector<uint8_t>& out, uint16_t value) {
        out.insert(out.end(), {static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)});
    }
    static void AppendU32(std::vector<uint8_t>& out, uint32_t value) {
        AppendU16(out, static_cast<uint16_t>(value >> 16));
        AppendU16(out, static_cast<uint16_t>(value));
    }
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
            group.push_back(Inspect({buffer.begin(), buffer.begin() + size}, sender));
            if (group.back().plain) ++plain_queries;
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
            auto packet = answer_override ? answer_override(*it) : Answer(*it, ordinal);
            if (!ignore_udp_limit && packet.size() > it->udp_limit) {
                packet.resize(it->question_size);
                packet[2] |= 0x02;
                std::fill(packet.begin() + 6, packet.begin() + 12, 0);
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
                wrong[it->question_size - 3] ^= 1; // different QTYPE
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
        if (fault_cache_write) ::common::reject_next_process_allocation = true;
    }
    net::awaitable<void> AcceptStreams() {
        for (;;) {
            auto [ec, stream] = co_await acceptor.async_accept(net::as_tuple(net::use_awaitable));
            if (ec) co_return;
            ++stream_connections;
            net::co_spawn(acceptor.get_executor(), AnswerStream(std::move(stream)), net::detached);
        }
    }
    net::awaitable<void> AnswerStream(::tcp::socket stream) {
        std::array<uint8_t, 2> length{};
        auto [prefix_error, prefix_size] = co_await net::async_read(
            stream, net::buffer(length), net::as_tuple(net::use_awaitable));
        if (prefix_error) co_return;
        std::vector<uint8_t> bytes((length[0] << 8) | length[1]);
        auto [query_error, query_size] = co_await net::async_read(
            stream, net::buffer(bytes), net::as_tuple(net::use_awaitable));
        if (query_error) co_return;
        ++stream_queries;
        if (stall_stream) {
            // Never answer; count when the resolver closes its end.
            auto& held = held_streams.emplace_back(std::move(stream));
            std::array<uint8_t, 1> probe{};
            (void)co_await net::async_read(held, net::buffer(probe), net::as_tuple(net::use_awaitable));
            ++stream_closed;
            co_return;
        }
        const auto packet = Answer(Inspect(std::move(bytes)), 4);
        length = {static_cast<uint8_t>(packet.size() >> 8), static_cast<uint8_t>(packet.size())};
        const std::array<net::const_buffer, 2> reply{net::buffer(length), net::buffer(packet)};
        (void)co_await net::async_write(stream, reply, net::as_tuple(net::use_awaitable));
    }
    ::udp::socket socket, foreign;
    ::tcp::acceptor acceptor;
    std::list<::tcp::socket> held_streams;
    ::udp::endpoint sender;
    std::array<uint8_t, 512> buffer{};
    std::map<std::string, std::vector<Query>> queries;
    std::set<uint16_t> ports;
    std::map<uint16_t, std::bitset<65536>> ids;
    size_t packets = 0, batch_size = 4, bulk_answers = 0;
    size_t stream_connections = 0, stream_queries = 0, stream_closed = 0, plain_queries = 0;
    bool hold = false, refuse = false, negative = false, nodata = false;
    bool reject_edns = false, reject_without_question = false;
    bool omit_soa = false, unrelated_soa = false, ignore_udp_limit = false;
    bool noise = false, duplicate_id = false, fault_cache_write = false, stall_stream = false;
    uint32_t soa_ttl = 900, soa_minimum = 120;
    std::function<std::vector<uint8_t>(const Query&)> answer_override;
    int malformed_type = 0;
    std::optional<uint32_t> answer_ttl;
    int ttl_type = 0;
};

::app::DnsConfig Config(Peer& peer) {
    ::app::DnsConfig c;
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
    ::app::DNSWorker worker{io, Config(peer), 8};
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

std::vector<net::ip::address> BulkAddresses(size_t count) {
    std::vector<net::ip::address> addresses;
    for (size_t i = 1; i <= count; ++i) {
        addresses.push_back(net::ip::address_v4({198, 51, 100, static_cast<uint8_t>(i)}));
    }
    for (size_t i = 1; i <= count; ++i) {
        auto bytes = net::ip::make_address_v6("2001:db8::").to_bytes();
        bytes.back() = static_cast<uint8_t>(i);
        addresses.push_back(net::ip::address_v6(bytes));
    }
    return addresses;
}

// 40 AAAA records (1151 bytes) exceed 512 but fit the advertised 1232.
TEST_P(DnsDatagramQueries, AnswerBeyond512BytesFitsAdvertisedUdpPayload) {
    peer.bulk_answers = 40;
    auto run = [&]() -> net::awaitable<void> {
        const auto result = co_await dns.Resolve("large.example");
        EXPECT_TRUE(result.Ok()) << result.error_msg;
        EXPECT_EQ(result.addresses, BulkAddresses(40));
        EXPECT_EQ(peer.packets, 4u);
    };
    Run(run());
}

// Bulk answers exceed 1232 bytes; each family keeps the 64-address budget.
TEST_P(DnsDatagramQueries, TruncatedAnswerIsRetriedOverTcp) {
    peer.ServeStream();
    peer.bulk_answers = 100;
    auto run = [&]() -> net::awaitable<void> {
        const auto result = co_await dns.Resolve("truncated.example");
        EXPECT_TRUE(result.Ok()) << result.error_msg;
        EXPECT_EQ(result.addresses, BulkAddresses(64));
        EXPECT_EQ(peer.packets, 4u);
        EXPECT_EQ(peer.stream_queries, 4u) << "every truncated answer must be retried over TCP";
    };
    Run(run());
}

TEST_P(DnsDatagramQueries, UpstreamWithoutEdnsIsAskedAgainWithoutOpt) {
    peer.reject_edns = true;
    auto run = [&]() -> net::awaitable<void> {
        const auto result = co_await dns.Resolve("plain.example");
        EXPECT_TRUE(result.Ok()) << result.error_msg;
        EXPECT_EQ(result.addresses.size(), 4u);
        EXPECT_EQ(peer.packets, 8u) << "each FORMERR answer earns exactly one plain retry";
        EXPECT_EQ(peer.plain_queries, 4u) << "retries must drop both ARCOUNT and the OPT bytes";
    };
    Run(run());
}

TEST_P(DnsDatagramQueries, QuestionlessEdnsRejectionStillTriggersPlainRetry) {
    peer.reject_edns = true;
    peer.reject_without_question = true;
    auto run = [&]() -> net::awaitable<void> {
        const auto result = co_await dns.Resolve("bare.example");
        EXPECT_TRUE(result.Ok()) << result.error_msg;
        EXPECT_EQ(result.addresses.size(), 4u);
        EXPECT_EQ(peer.plain_queries, 4u);
    };
    Run(run());
}

TEST_P(DnsDatagramQueries, OversizedDatagramIsRetriedOverTcp) {
    peer.ServeStream();
    peer.bulk_answers = 100;
    peer.ignore_udp_limit = true;  // Violates the advertised 1232 bytes.
    auto run = [&]() -> net::awaitable<void> {
        const auto result = co_await dns.Resolve("oversized.example");
        EXPECT_TRUE(result.Ok()) << result.error_msg;
        EXPECT_EQ(result.addresses, BulkAddresses(64));
        EXPECT_EQ(peer.stream_queries, 4u);
    };
    Run(run());
}

struct Record {
    std::string owner;
    uint16_t type;
    uint32_t ttl;
    std::vector<uint8_t> rdata;
};
Record Cname(std::string owner, std::string_view target, uint32_t ttl) {
    return {std::move(owner), 5, ttl, Peer::WireNameOf(target)};
}
Record Address(std::string owner, bool v6, uint8_t last, uint32_t ttl) {
    std::vector<uint8_t> rdata;
    if (v6) {
        const auto bytes = net::ip::make_address_v6("2001:db8::").to_bytes();
        rdata.assign(bytes.begin(), bytes.end());
    } else {
        rdata = {192, 0, 2, 0};
    }
    rdata.back() = last;
    return {std::move(owner), static_cast<uint16_t>(v6 ? 28 : 1), ttl, std::move(rdata)};
}
bool AsksAaaa(const Peer::Query& query) { return query.bytes[query.question_size - 3] == 28; }
std::vector<uint8_t> AnswerWith(const Peer::Query& query, const std::vector<Record>& records) {
    std::vector<uint8_t> packet(query.bytes.begin(), query.bytes.begin() + query.question_size);
    packet[2] = 0x81;
    packet[3] = 0x80;
    std::fill(packet.begin() + 6, packet.begin() + 12, 0);
    packet[7] = static_cast<uint8_t>(records.size());
    for (const auto& record : records) {
        const auto owner = Peer::WireNameOf(record.owner);
        packet.insert(packet.end(), owner.begin(), owner.end());
        Peer::AppendU16(packet, record.type);
        Peer::AppendU16(packet, 1);
        Peer::AppendU32(packet, record.ttl);
        Peer::AppendU16(packet, static_cast<uint16_t>(record.rdata.size()));
        packet.insert(packet.end(), record.rdata.begin(), record.rdata.end());
    }
    return packet;
}

// Owner names differ in case from the question (RFC 4343). The address that
// precedes its owner's CNAME and the record outside the chain are not trusted.
TEST_P(DnsDatagramQueries, CnameChainKeepsOnlyRecordsOnTheChain) {
    peer.answer_override = [](const Peer::Query& query) {
        const bool v6 = AsksAaaa(query);
        return AnswerWith(query, {
            Address("ALIAS.example", v6, 9, 300),
            Cname("alias.EXAMPLE", "Mid.Example", 300),
            Address("evil.example", v6, 66, 300),
            Cname("mid.example", "end.example", 50),
            Address("end.example", v6, 77, 200),
        });
    };
    auto run = [&]() -> net::awaitable<void> {
        const auto result = co_await dns.Resolve("alias.example");
        EXPECT_TRUE(result.Ok()) << result.error_msg;
        const std::vector<net::ip::address> expected{
            net::ip::make_address("192.0.2.77"), net::ip::make_address("2001:db8::4d")};
        EXPECT_EQ(result.addresses, expected);
        EXPECT_EQ(result.ttl, 50u) << "the chain's CNAME TTLs bound the answer";
    };
    Run(run());
}

// RFC 1034 sets no order between RRsets; 1.1.1.1 shipped this ordering in
// January 2026. Addresses first, then the chain from its far end.
TEST_P(DnsDatagramQueries, ReorderedAnswerSectionStillFollowsTheChain) {
    peer.answer_override = [](const Peer::Query& query) {
        const bool v6 = AsksAaaa(query);
        return AnswerWith(query, {
            Address("end.example", v6, 77, 200),
            Cname("mid.example", "end.example", 60),
            Cname("alias.example", "mid.example", 300),
        });
    };
    auto run = [&]() -> net::awaitable<void> {
        const auto result = co_await dns.Resolve("alias.example");
        EXPECT_TRUE(result.Ok()) << result.error_msg;
        const std::vector<net::ip::address> expected{
            net::ip::make_address("192.0.2.77"), net::ip::make_address("2001:db8::4d")};
        EXPECT_EQ(result.addresses, expected);
        EXPECT_EQ(result.ttl, 60u);
    };
    Run(run());
}

TEST_P(DnsDatagramQueries, CnameLoopIsServerFailureAndNotCached) {
    peer.answer_override = [](const Peer::Query& query) {
        const bool v6 = AsksAaaa(query);
        return AnswerWith(query, {
            Cname("loop.example", "back.example", 300),
            Cname("back.example", "loop.example", 300),
            Address("loop.example", v6, 1, 300),
        });
    };
    auto run = [&]() -> net::awaitable<void> {
        const auto first = co_await dns.Resolve("loop.example");
        EXPECT_EQ(first.error, ::common::ErrorCode::DNS_SERVER_FAILED) << first.error_msg;
        EXPECT_NE(first.error_msg.find("loops"), std::string::npos) << first.error_msg;
        const auto second = co_await dns.Resolve("loop.example");
        EXPECT_FALSE(second.from_cache);
        EXPECT_EQ(peer.packets, 8u);
    };
    Run(run());
}

TEST_P(DnsDatagramQueries, NegativeAnswerTtlIsSoaMinimumBound) {
    peer.negative = true;
    auto run = [&]() -> net::awaitable<void> {
        const auto first = co_await dns.Resolve("soa.example");
        EXPECT_EQ(first.error, ::common::ErrorCode::DNS_NO_RECORD);
        EXPECT_EQ(first.ttl, 120u) << "min(SOA TTL 900, MINIMUM 120)";
        peer.soa_ttl = 30;
        const auto cached = co_await dns.Resolve("soa.example");
        EXPECT_TRUE(cached.from_cache);
        EXPECT_LE(cached.ttl, 120u);
        const auto lower = co_await dns.Resolve("soa-ttl.example");
        EXPECT_EQ(lower.ttl, 30u) << "a SOA TTL below MINIMUM wins";
    };
    Run(run());
}

class DnsNegativeWithoutZoneSoa : public testing::TestWithParam<bool> {};
TEST_P(DnsNegativeWithoutZoneSoa, IsNotCached) {
    net::io_context io;
    Peer peer(io);
    peer.negative = true;
    peer.omit_soa = !GetParam();
    peer.unrelated_soa = GetParam();
    ::app::DNSWorker worker(io, Config(peer), 8);
    DNS dns(worker);
    bool done = false;
    std::exception_ptr failure;
    auto run = [&]() -> net::awaitable<void> {
        const auto first = co_await dns.Resolve("nosoa.example");
        EXPECT_EQ(first.error, ::common::ErrorCode::DNS_NO_RECORD);
        EXPECT_EQ(first.ttl, 0u);
        const auto second = co_await dns.Resolve("nosoa.example");
        EXPECT_EQ(second.error, ::common::ErrorCode::DNS_NO_RECORD);
        EXPECT_FALSE(second.from_cache);
        EXPECT_EQ(peer.packets, 8u);
    };
    net::co_spawn(io, run(), [&](std::exception_ptr error) {
        failure = error;
        done = true;
        peer.Stop();
    });
    io.run_for(3s);
    const bool completed_before_cleanup = done;
    peer.Stop();
    JoinService(io, worker);
    EXPECT_TRUE(completed_before_cleanup);
    if (failure) std::rethrow_exception(failure);
}

enum class StreamRetryEnd { Deadline, ServiceStop, WaiterCancel };
class DnsStalledStreamRetry : public testing::TestWithParam<StreamRetryEnd> {};
TEST_P(DnsStalledStreamRetry, ClosesEveryUpstreamConnection) {
    const auto end = GetParam();
    net::io_context io;
    Peer peer(io);
    peer.ServeStream();
    peer.bulk_answers = 100;
    peer.stall_stream = true;
    auto config = Config(peer);
    // Only the deadline variant may rely on the exchange timeout.
    if (end != StreamRetryEnd::Deadline) config.timeout_sec = 30;
    ::app::DNSWorker worker(io, config, 8);
    std::optional<DnsResult> answer;
    std::exception_ptr error;
    net::cancellation_signal signal;
    net::co_spawn(io, worker.Resolve("stalled.example"), net::bind_cancellation_slot(signal.slot(),
        [&](std::exception_ptr e, DnsResult result) {
            error = e;
            answer = std::move(result);
        }));
    net::steady_timer watchdog(io, 4s);
    bool expired = false;
    watchdog.async_wait([&](::IoErrorCode ec) {
        if (!ec) { expired = true; worker.RequestStop(); }
    });
    while (peer.stream_queries != 4 && !expired) io.run_one();
    EXPECT_FALSE(expired) << "truncated answers must reach the upstream over TCP";
    if (end == StreamRetryEnd::ServiceStop) worker.RequestStop();
    if (end == StreamRetryEnd::WaiterCancel) signal.emit(net::cancellation_type::terminal);
    while ((!answer || peer.stream_closed != 4) && !expired) io.run_one();
    EXPECT_FALSE(expired) << "the resolver must close every upstream TCP connection itself";
    bool joined = false;
    net::co_spawn(io, worker.AsyncJoin(), [&](std::exception_ptr join_error) {
        EXPECT_FALSE(join_error);
        joined = true;
        watchdog.cancel();
        peer.Stop();
    });
    io.run();
    EXPECT_TRUE(joined);
    ASSERT_TRUE(answer);
    if (end == StreamRetryEnd::Deadline) {
        EXPECT_FALSE(error);
        EXPECT_EQ(answer->error, ::common::ErrorCode::DNS_TIMEOUT);
        EXPECT_NE(answer->error_msg.find("TCP retry"), std::string::npos) << answer->error_msg;
    } else {
        EXPECT_TRUE(error || answer->error == ::common::ErrorCode::CANCELLED);
    }
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
    ::app::DNSWorker worker(io, Config(peer), 8);
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
    ::app::DNSWorker worker(io, Config(peer), 8);
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
    ::app::DNSWorker worker(io, config, 8);
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
    ::app::DNSWorker worker(io, config, 8);
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
    auto transport = std::make_shared<::app::UpstreamExchange>(io, peer.socket.local_endpoint());
    std::exception_ptr error;
    bool done = false;
    auto run = [&]() -> net::awaitable<void> {
        std::array<uint8_t, 19> query{0,0,1,0,0,1,0,0,0,0,0,0,1,'r',0,0,1,0,1};
        for (size_t i = 0; i < 65537; ++i) {
            auto result = co_await transport->ExchangeDatagram(query, 1s);
            EXPECT_FALSE(result.error);
            EXPECT_GT(result.bytes.size(), 12u);
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
    const auto rejected = ::common::rejected_process_allocations;
    net::io_context io;
    Peer peer(io);
    ::app::DNSWorker worker(io, Config(peer), 8);
    DNS dns(worker);
    std::exception_ptr error;
    bool done = false;
    auto run = [&]() -> net::awaitable<void> {
        peer.fault_cache_write = true;
        auto result = co_await dns.Resolve("cache-fault.example");
        peer.fault_cache_write = false;
        const bool fault_consumed = !::common::reject_next_process_allocation;
        ::common::reject_next_process_allocation = false;
        const auto failed_stats = co_await worker.GetCacheStats();
        EXPECT_TRUE(result.Ok());
        EXPECT_EQ(result.addresses.size(), 4u);
        EXPECT_TRUE(fault_consumed);
        EXPECT_GT(::common::rejected_process_allocations, rejected);
        EXPECT_EQ(failed_stats.entries, 0u);
        result = co_await dns.Resolve("cache-fault.example");
        const auto recovered_stats = co_await worker.GetCacheStats();
        EXPECT_TRUE(result.Ok());
        EXPECT_EQ(result.addresses.size(), 4u);
        EXPECT_EQ(recovered_stats.entries, 1u);
    };
    net::co_spawn(io, run(), [&](std::exception_ptr e) { error = e; done = true; peer.Stop(); });
    io.run_for(3s);
    ::common::reject_next_process_allocation = false;
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
    auto worker = std::make_unique<::app::DNSWorker>(io, config, 8);
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
    auto transport = std::make_shared<::app::UpstreamExchange>(
        io, peer.socket.local_endpoint());
    std::weak_ptr weak = transport;
    std::array<uint8_t, 19> query{0,0,1,0,0,1,0,0,0,0,0,0,1,'r',0,0,1,0,1};
    bool query_done = !active;
    std::exception_ptr query_error;
    ::IoErrorCode reply_error;
    if (active) {
        net::co_spawn(io, transport->ExchangeDatagram(query, 30s),
            [&](std::exception_ptr error, ::app::UpstreamExchange::Reply reply) {
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
        const auto rejected = co_await transport->ExchangeDatagram(query, 30s);
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
    const auto rejected = ::common::rejected_process_allocations;
    net::io_context io;
    Peer peer(io);
    auto transport = std::make_shared<::app::UpstreamExchange>(
        io, peer.socket.local_endpoint());
    std::weak_ptr weak = transport;
    std::array<uint8_t, 19> query{0,0,1,0,0,1,0,0,0,0,0,0,1,'r',0,0,1,0,1};
    bool failed = false, joined = false;
    std::exception_ptr failure;
    auto run = [&]() -> net::awaitable<void> {
        // Query registration is the exchange's first process-layer allocation.
        ::common::reject_next_process_allocation = true;
        try {
            (void)co_await transport->ExchangeDatagram(query, 30s);
        } catch (const std::bad_alloc&) {
            failed = true;
        }
        ::common::reject_next_process_allocation = false;
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
    ::common::reject_next_process_allocation = false;
    if (failure) std::rethrow_exception(failure);
    EXPECT_TRUE(joined);
    EXPECT_TRUE(failed);
    EXPECT_GT(::common::rejected_process_allocations, rejected);
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
INSTANTIATE_TEST_SUITE_P(Authority, DnsNegativeWithoutZoneSoa, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) { return info.param ? "UnrelatedSoa" : "NoSoa"; });
INSTANTIATE_TEST_SUITE_P(Outcome, DnsStalledStreamRetry, testing::Values(
    StreamRetryEnd::Deadline, StreamRetryEnd::ServiceStop, StreamRetryEnd::WaiterCancel),
    [](const testing::TestParamInfo<StreamRetryEnd>& info) {
        return info.param == StreamRetryEnd::Deadline ? "Deadline" :
            info.param == StreamRetryEnd::ServiceStop ? "ServiceStop" : "WaiterCancel";
    });

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
    ::app::DNSWorker worker(io, config, 8);
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
