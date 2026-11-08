#include "quic_peer.hpp"
#include "udp_wire.hpp"

#include <bitset>

namespace cnode::e2e::quic {
namespace {
std::string UdpWire(uint32_t session, uint16_t packet, uint8_t fragment,
                    uint8_t count, std::string_view target, std::string_view payload) {
    if (target.size() >= 64) throw std::runtime_error("UDP fixture target budget");
    return BigEndian(session, 4) + BigEndian(packet, 2) + static_cast<char>(fragment) +
        static_cast<char>(count) + static_cast<char>(target.size()) +
        std::string(target) + std::string(payload);
}

class QuicUdpFrameBudget : public ::testing::TestWithParam<uint64_t> {};

TEST_P(QuicUdpFrameBudget, DownlinkPreservesSourcesWithinPeerFrameBudget) {
    TempDir root;
    auto next_hop = Socket::BindUdp();
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    Configure(root.Path(), HysteriaInbound(port), {
        {"protocol", "shadowsocks"},
        {"settings", {{"servers", Json::array({{{"address", "127.0.0.1"},
            {"port", next_hop.Port()}, {"method", "aes-128-gcm"}, {"password", "secret"}}})}}}});
    reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForLog("server started");
    const auto frame_limit = GetParam();
    Peer peer(port, "smoke-secret", frame_limit);
    const auto host = std::string(63, 'a') + "." + std::string(63, 'b') + "." +
        std::string(63, 'c') + "." + std::string(61, 'd');
    constexpr uint32_t session = 0x11223344;
    const auto request_header = SocksAddress(53);
    std::optional<udp::Datagram> origin;
    auto read_reply = [&](uint32_t expected_session, std::string_view expected_source) {
        std::array<std::string, 256> parts;
        std::bitset<256> received;
        uint8_t count = 0;
        uint16_t packet_id = 0;
        for (size_t index = 0; count == 0 || index < count; ++index) {
            const auto wire = peer.ReadDatagram();
            udp::Require(wire.size() >= 9 && wire.size() < frame_limit, "HY2 frame exceeds peer budget");
            const auto view = std::string_view(wire);
            udp::Require(ReadBigEndian(view.substr(0, 4)) == expected_session, "HY2 reply changed session");
            const auto current_packet = static_cast<uint16_t>(ReadBigEndian(view.substr(4, 2)));
            const auto current_count = static_cast<uint8_t>(wire[7]);
            const auto fragment = current_count == 1 ? uint8_t{0} : static_cast<uint8_t>(wire[6]);
            if (count == 0) { count = current_count; packet_id = current_packet; }
            udp::Require(count != 0 && current_count == count && current_packet == packet_id &&
                fragment < count && !received.test(fragment), "HY2 fragment identity changed");
            const size_t width = size_t{1} << (static_cast<uint8_t>(wire[8]) >> 6);
            udp::Require(width <= wire.size() - 8, "truncated HY2 address length");
            size_t length = static_cast<uint8_t>(wire[8]) & 0x3f;
            for (size_t byte = 1; byte < width; ++byte)
                length = (length << 8) | static_cast<uint8_t>(wire[8 + byte]);
            udp::Require(length <= wire.size() - 8 - width, "truncated HY2 reply address");
            udp::Require(view.substr(8 + width, length) == expected_source,
                "HY2 fragment lost its source address");
            parts[fragment] = view.substr(8 + width + length);
            received.set(fragment);
        }
        std::string result;
        for (size_t fragment = 0; fragment < count; ++fragment) result += parts[fragment];
        return result;
    };
    auto exchange = [&](std::string_view request, std::string_view response, std::string_view response_host) {
        peer.SendDatagram(UdpWire(session, 7, 0, 1, "127.0.0.1:53", request));
        auto packet = udp::Receive(next_hop);
        udp::Require(udp::LegacyDecrypt(packet.payload) == request_header + std::string(request),
            "HY2 to SS changed target or payload");
        if (origin) udp::Require(origin->SameEndpoint(packet), "HY2 session replaced its SS socket");
        else {
            origin.emplace();
            origin->address = packet.address;
            origin->address_size = packet.address_size;
        }
        udp::Reply(next_hop, packet,
            udp::LegacyEncrypt(SocksAddress(54321, response_host) + std::string(response)));
        const bool ipv6 = response_host.find(':') != std::string_view::npos;
        std::string expected_source;
        expected_source.reserve(response_host.size() + 8);
        if (ipv6) expected_source.push_back('[');
        expected_source.append(response_host);
        if (ipv6) expected_source.push_back(']');
        expected_source.append(":54321");
        EXPECT_EQ(read_reply(session, expected_source), response);
    };
    const std::string_view reply_host = frame_limit == 18 ? std::string_view("a") : std::string_view(host);
    const auto response = frame_limit == 18 || frame_limit == 272
        ? std::string{} : udp::Sequence(frame_limit == 273 ? 128 : 3200);
    exchange("first-response", response, reply_host);
    if (!response.empty()) exchange("empty-response", {}, reply_host);
    exchange("after-first-response", frame_limit == 18 ? std::string_view{} : "still-usable",
        frame_limit == 18 ? "b" : "127.0.0.1");
    if (frame_limit >= 272) exchange("ipv6-source", udp::Sequence(1300), "2001:db8::1234");
    if (frame_limit <= 273) {
        peer.SendDatagram(UdpWire(session, 7, 0, 1, "127.0.0.1:53", "unrepresentable-response"));
        auto rejected = udp::Receive(next_hop);
        udp::Require(udp::LegacyDecrypt(rejected.payload) == request_header + "unrepresentable-response",
            "unrepresentable reply lost its request context");
        udp::Reply(next_hop, rejected, udp::LegacyEncrypt(SocksAddress(54321, reply_host) +
            udp::Sequence(frame_limit == 273 ? 257 : 1)));
        constexpr auto sibling = session + 1;
        peer.SendDatagram(UdpWire(sibling, 7, 0, 1, "127.0.0.1:53", "sibling-request"));
        auto sibling_packet = udp::Receive(next_hop);
        udp::Require(udp::LegacyDecrypt(sibling_packet.payload) == request_header + "sibling-request",
            "sibling request did not survive the oversized reply");
        const std::string_view sibling_host = frame_limit == 18 ? "c" : "127.0.0.1";
        const std::string_view sibling_reply = frame_limit == 18 ? "" : "sibling-usable";
        udp::Reply(next_hop, sibling_packet,
            udp::LegacyEncrypt(SocksAddress(54321, sibling_host) + std::string(sibling_reply)));
        EXPECT_EQ(read_reply(sibling, std::string(sibling_host) + ":54321"), sibling_reply);
    }
    EXPECT_FALSE(peer.Closed());
    EXPECT_EQ(server.Stop(), 0);
}

INSTANTIATE_TEST_SUITE_P(AdvertisedLimit, QuicUdpFrameBudget,
    ::testing::Values(uint64_t{65535}, uint64_t{512}, uint64_t{273}, uint64_t{272}, uint64_t{18}),
    [](const auto& info) { return "bytes_" + std::to_string(info.param); });

TEST(QuicUdp, UnfragmentedIdsAreIgnoredWithoutBreakingFragmentedPackets) {
    TempDir root;
    auto target = Socket::BindUdp();
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    auto inbound = HysteriaInbound(port);
    inbound["sniffing"]["enabled"] = true;
    Configure(root.Path(), std::move(inbound),
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForLog("server started");
    Peer peer(port);
    const auto address = "127.0.0.1:" + std::to_string(target.Port());
    constexpr uint32_t session = 0x10203040;
    constexpr uint16_t packet = 0xbeef;
    uint16_t origin_port = 0;
    std::string_view phase = "send";
    auto exchange = [&](std::string_view expected, bool empty_reply = false) {
        std::string actual;
        sockaddr_in source{};
        phase = "uplink target";
        peer.Wait([&] {
            std::array<char, 4096> bytes{};
            socklen_t length = sizeof(source);
            const auto count = ::recvfrom(target.Fd(), bytes.data(), bytes.size(), MSG_DONTWAIT,
                reinterpret_cast<sockaddr*>(&source), &length);
            if (count < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return false;
                throw std::system_error(errno, std::generic_category(), "receive relayed UDP");
            }
            actual.assign(bytes.data(), static_cast<size_t>(count));
            return true;
        });
        EXPECT_EQ(actual, expected);
        ASSERT_EQ(source.sin_family, AF_INET);
        if (origin_port == 0) origin_port = source.sin_port;
        EXPECT_EQ(source.sin_port, origin_port) << "same session replaced its outbound socket";
        const auto response = empty_reply ? std::string{} : "reply:" + actual;
        const auto sent = ::sendto(target.Fd(), response.data(), response.size(), MSG_NOSIGNAL,
            reinterpret_cast<const sockaddr*>(&source), sizeof(source));
        ASSERT_EQ(sent, static_cast<ssize_t>(response.size()));
        phase = "downlink reply";
        const auto reply = peer.ReadDatagram();
        ASSERT_GE(reply.size(), 9u);
        EXPECT_EQ(ReadBigEndian(std::string_view(reply).substr(0, 4)), session);
        EXPECT_EQ(static_cast<uint8_t>(reply[7]), 1);
        const size_t width = size_t{1} << (static_cast<uint8_t>(reply[8]) >> 6);
        ASSERT_GE(reply.size(), 8 + width);
        size_t address_size = static_cast<uint8_t>(reply[8]) & 0x3f;
        for (size_t i = 1; i < width; ++i)
            address_size = (address_size << 8) | static_cast<uint8_t>(reply[8 + i]);
        ASSERT_LE(address_size, reply.size() - 8 - width);
        EXPECT_EQ(std::string_view(reply).substr(8 + width, address_size), address);
        EXPECT_EQ(std::string_view(reply).substr(8 + width + address_size), response);
    };
    try {
        peer.SendDatagram(UdpWire(session, packet, 255, 1, address, {}));
        exchange({}, true);
    } catch (const std::exception& error) {
        throw std::runtime_error("zero first datagram phase=" + std::string(phase) + ": " + error.what());
    }
    for (const uint8_t fragment : {uint8_t{0}, uint8_t{1}, uint8_t{255}}) {
        SCOPED_TRACE(static_cast<unsigned>(fragment));
        auto payload = "single-" + std::to_string(fragment);
        for (uint8_t byte = 0; byte != 37; ++byte)
            payload.push_back(static_cast<char>(byte));
        // Reusing Packet ID is intentional: it is irrelevant for single packets.
        try {
            phase = "send";
            peer.SendDatagram(UdpWire(session, packet, fragment, 1, address, payload));
            exchange(payload);
        } catch (const std::exception& error) {
            throw std::runtime_error("single fragment=" + std::to_string(fragment) +
                " phase=" + std::string(phase) + ": " + error.what());
        }
    }
    peer.SendDatagram(UdpWire(session, packet, 1, 2, {}, "fragment-tail"));
    peer.SendDatagram(UdpWire(session, packet, 0, 2, address, "fragment-head:"));
    exchange("fragment-head:fragment-tail");
    peer.SendDatagram(UdpWire(session, packet, 0, 2, address, {}));
    peer.SendDatagram(UdpWire(session, packet, 1, 2, {}, {}));
    exchange({}, true);
    for (uint8_t empty_fragment = 0; empty_fragment < 3; ++empty_fragment) {
        SCOPED_TRACE("empty fragment=" + std::to_string(empty_fragment));
        std::array<std::string_view, 3> parts{"head:", "middle:", "tail"};
        parts[empty_fragment] = {};
        const std::string expected = std::string(parts[0]) + std::string(parts[1]) +
            std::string(parts[2]);
        const auto id = static_cast<uint16_t>(packet + 16 + empty_fragment);
        for (const uint8_t fragment : {uint8_t{2}, uint8_t{1}, uint8_t{0}}) {
            if (fragment == empty_fragment) continue;
            peer.SendDatagram(UdpWire(session, id, fragment, 3,
                fragment == 0 ? std::string_view(address) : std::string_view{}, parts[fragment]));
        }
        try {
            if (empty_fragment == 2) {
                peer.SendDatagram(UdpWire(session, packet, 0, 1, address, "waiting-for-empty-tail"));
                exchange("waiting-for-empty-tail");
            }
            peer.SendDatagram(UdpWire(session, id, empty_fragment, 3,
                empty_fragment == 0 ? std::string_view(address) : std::string_view{}, {}));
            exchange(expected);
        } catch (const std::exception& error) {
            throw std::runtime_error("empty fragment=" + std::to_string(empty_fragment) +
                " phase=" + std::string(phase) + ": " + error.what());
        }
    }
    // Repeating an empty fragment must not stand in for a missing fragment.
    const auto incomplete = static_cast<uint16_t>(packet + 32);
    peer.SendDatagram(UdpWire(session, incomplete, 1, 3, {}, {}));
    peer.SendDatagram(UdpWire(session, incomplete, 1, 3, {}, {}));
    peer.SendDatagram(UdpWire(session, incomplete, 0, 3, address, "not-complete"));
    peer.SendDatagram(UdpWire(session, packet, 0, 1, address, "complete-after-duplicate"));
    exchange("complete-after-duplicate");
    std::string maximum;
    for (unsigned fragment = 0; fragment < 255; ++fragment)
        maximum.push_back(static_cast<char>(fragment));
    const auto maximum_id = static_cast<uint16_t>(packet + 33);
    for (int fragment = 254; fragment >= 0; --fragment) {
        peer.SendDatagram(UdpWire(session, maximum_id, static_cast<uint8_t>(fragment), 255,
            fragment == 0 ? std::string_view(address) : std::string_view{},
            std::string_view(maximum).substr(static_cast<size_t>(fragment), 1)));
        peer.Pump(Milliseconds(1));
    }
    exchange(maximum);
    peer.SendDatagram(UdpWire(session, packet, 255, 1, address, "after-fragments"));
    exchange("after-fragments");
    peer.SendDatagram(UdpWire(session, packet, 255, 1, address, {}));
    exchange({}, true);
    EXPECT_FALSE(peer.Closed());
    EXPECT_EQ(server.Stop(), 0);
}

enum class FragmentDeadline { Idle, Overall, Progress };
class QuicFragmentExpiry : public ::testing::TestWithParam<FragmentDeadline> {};

TEST_P(QuicFragmentExpiry, EnforcesIdleAndOverallBudgetsWithoutClosingAssociation) {
    TempDir root;
    auto target = Socket::BindUdp();
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    Configure(root.Path(), HysteriaInbound(port),
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    auto config = Json::parse(ReadFile(root.Path() / "config.json"));
    config["timeouts"]["connIdle"] = 120;
    WriteJson(root.Path(), "config.json", config);
    reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForLog("server started");
    Peer peer(port);
    const auto address = "127.0.0.1:" + std::to_string(target.Port());
    constexpr uint32_t session = 0x50607080;
    constexpr uint16_t packet = 0x1234;
    uint16_t origin_port = 0;
    auto receive = [&](std::string_view expected) {
        std::string actual;
        sockaddr_in source{};
        peer.Wait([&] {
            std::array<char, 4096> bytes{};
            socklen_t length = sizeof(source);
            const auto count = ::recvfrom(target.Fd(), bytes.data(), bytes.size(), MSG_DONTWAIT,
                reinterpret_cast<sockaddr*>(&source), &length);
            if (count < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return false;
                throw std::system_error(errno, std::generic_category(), "receive fragment deadline UDP");
            }
            actual.assign(bytes.data(), static_cast<size_t>(count));
            return true;
        });
        ASSERT_EQ(actual, expected);
        ASSERT_EQ(source.sin_family, AF_INET);
        if (origin_port == 0) origin_port = source.sin_port;
        EXPECT_EQ(source.sin_port, origin_port) << "fragment expiration closed the UDP association";
    };
    auto control = [&](std::string_view payload) {
        peer.SendDatagram(UdpWire(session, 0, 0, 1, address, payload));
        receive(payload);
    };
    const auto scenario = GetParam();
    const uint8_t count = scenario == FragmentDeadline::Overall ? 9 :
        scenario == FragmentDeadline::Progress ? 4 : 2;
    peer.SendDatagram(UdpWire(session, packet, 0, count, address, "head:"));
    control("accepted-incomplete-packet");
    const auto started = std::chrono::steady_clock::now();
    auto pump_until = [&](auto deadline) {
        while (std::chrono::steady_clock::now() < deadline) peer.Pump(Milliseconds(20));
    };
    if (scenario != FragmentDeadline::Idle) {
        // Each fresh index renews inactivity, but cannot renew the total budget.
        for (uint8_t fragment = 1; fragment < count - 1; ++fragment) {
            pump_until(started + std::chrono::seconds(2 * fragment));
            peer.SendDatagram(UdpWire(session, packet, fragment, count, {}, "still-incomplete:"));
            control("unrelated-traffic-continues");
        }
        pump_until(started + (scenario == FragmentDeadline::Overall ? 16s : 6s));
    } else {
        // No new packet can be responsible for waking expiration during this gap.
        pump_until(started + 6s);
    }
    peer.SendDatagram(UdpWire(session, packet, count - 1, count, {}, "late-tail"));
    if (scenario == FragmentDeadline::Progress)
        receive("head:still-incomplete:still-incomplete:late-tail");
    control("after-expired-fragments");
    peer.SendDatagram(UdpWire(session, packet + 1, 1, 2, {}, "fresh-tail"));
    peer.SendDatagram(UdpWire(session, packet + 1, 0, 2, address, "fresh-head:"));
    receive("fresh-head:fresh-tail");
    EXPECT_FALSE(peer.Closed());
    EXPECT_EQ(server.Stop(), 0);
}

INSTANTIATE_TEST_SUITE_P(Deadline, QuicFragmentExpiry,
    ::testing::Values(FragmentDeadline::Idle, FragmentDeadline::Overall, FragmentDeadline::Progress),
    [](const auto& info) {
        if (info.param == FragmentDeadline::Idle) return "idle";
        return info.param == FragmentDeadline::Overall ? "overall" : "progress";
    });

TEST(QuicUdp, ShutdownJoinsSessionWaitingForDnsWithLaterInput) {
    TempDir root;
    DnsBlackhole dns;
    Targets control([](Socket& socket) {
        for (;;) {
            const auto bytes = socket.Read(16384, 30s);
            if (bytes.empty()) break;
            socket.Write(bytes);
        }
    });
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    Configure(root.Path(), HysteriaInbound(port),
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    auto config = Json::parse(ReadFile(root.Path() / "config.json"));
    config["dns"] = {{"servers", Json::array({"127.77.0.2:" + std::to_string(dns.socket.Port())})},
                     {"timeout", 60}};
    config["timeouts"] = {{"handshake", 10}, {"connIdle", 120}, {"write", 10}};
    WriteJson(root.Path(), "config.json", config);
    reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForLog("server started");
    Peer peer(port);
    constexpr std::string_view host = "queued-cancel.test";
    const auto address = std::string(host) + ":53";
    peer.SendDatagram(UdpWire(99, 0, 0, 1, address, "first"));
    peer.Wait([&] { return dns.Observed(host); });
    std::string payload(700, 'q');
    for (uint16_t packet = 1; packet <= 128; ++packet) {
        payload[0] = static_cast<char>(packet);
        peer.SendDatagram(UdpWire(99, packet, 0, 1, address, payload));
    }
    const auto stream = peer.Open("127.0.0.1:" + std::to_string(control.Port()),
                                  "control-before-shutdown");
    peer.Wait([&] { return peer.Payload(stream) == "control-before-shutdown"; });
    EXPECT_FALSE(peer.Closed());
    EXPECT_EQ(server.Stop(8s), 0);
    control.Join();
}
} // namespace
} // namespace cnode::e2e::quic
