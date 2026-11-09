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

TEST(QuicUdp, ConcurrentMultiSessionMigrationAndEphemeralAnyTlsStreams) {
    TempDir root, upstream_root;
    Targets tcp_target([](Socket& socket) {
        for (;;) {
            const auto bytes = socket.Read(16384, 30s);
            if (bytes.empty()) break;
            socket.Write(bytes);
        }
    });
    auto udp_target = Socket::BindUdp();
    Socket dns_socket = Socket::BindUdp(0, "127.77.0.53");
    std::atomic<size_t> dns_queries{0};
    std::atomic<bool> stop_dns{false};
    PeerThread dns_responder([&] {
        while (!stop_dns.load()) {
            pollfd descriptor{dns_socket.Fd(), POLLIN, 0};
            if (::poll(&descriptor, 1, 10) <= 0) continue;
            for (size_t step = 0; step < 32; ++step) {
                std::array<uint8_t, 4096> bytes{};
                sockaddr_in source{};
                socklen_t length = sizeof(source);
                const auto count = ::recvfrom(dns_socket.Fd(), bytes.data(), bytes.size(),
                    MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&source), &length);
                if (count < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    throw std::system_error(errno, std::generic_category(), "receive DNS query");
                }
                if (count < 17) continue;
                ++dns_queries;
                std::string reply(reinterpret_cast<const char*>(bytes.data()), static_cast<size_t>(count));
                const bool is_a = static_cast<uint8_t>(reply[reply.size() - 4]) == 0 &&
                    static_cast<uint8_t>(reply[reply.size() - 3]) == 1;
                reply[2] = static_cast<char>(0x81);
                reply[3] = static_cast<char>(0x80);
                reply[4] = 0;
                reply[5] = 1;
                reply[6] = 0;
                reply[7] = is_a ? 1 : 0;
                for (size_t i = 8; i < 12; ++i) reply[i] = 0;
                if (is_a) {
                    constexpr std::array<uint8_t, 16> answer{
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1};
                    reply.append(reinterpret_cast<const char*>(answer.data()), answer.size());
                }
                (void)::sendto(dns_socket.Fd(), reply.data(), reply.size(), MSG_NOSIGNAL,
                    reinterpret_cast<const sockaddr*>(&source), sizeof(source));
            }
        }
    });
    struct DnsGuard {
        std::atomic<bool>& stop;
        PeerThread& thread;
        ~DnsGuard() {
            stop = true;
            try { thread.Join(); } catch (...) {}
        }
    } dns_guard{stop_dns, dns_responder};
    auto upstream_reservation = Socket::Listen();
    const auto upstream_port = upstream_reservation.Port();
    Configure(upstream_root.Path(),
        {{"protocol", "anytls"}, {"listen", "127.0.0.1"}, {"port", upstream_port},
            {"settings", {{"clients", Json::array({{{"password", "secret"}}})}}},
            {"streamSettings", TlsSettings(true)}},
        {{"protocol", "freedom"}, {"settings", Json::object()}}, 4);
    auto upstream_config = Json::parse(ReadFile(upstream_root.Path() / "config.json"));
    upstream_config["dns"] = {
        {"servers", Json::array({"127.77.0.53:" + std::to_string(dns_socket.Port())})},
        {"timeout", 5}, {"cacheSize", 1024}};
    WriteJson(upstream_root.Path(), "config.json", upstream_config);
    upstream_reservation.Close();
    Child upstream({Binary().string(), "--config-dir", upstream_root.Path().string()},
        upstream_root.Path() / "upstream.log");
    upstream.WaitForLog("server started");
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    auto vless_reservation = Socket::Listen();
    const auto vless_port = vless_reservation.Port();
    udp::PortReservation ss_reservation(true);
    const auto ss_port = ss_reservation.port;
    const auto ss_key = udp::Sequence(16);

    auto panel_node_reservation = Socket::Listen();
    const auto panel_node_port = panel_node_reservation.Port();
    Socket panel_listener = Socket::Listen();
    std::atomic<int> panel_phase{0};
    std::atomic<size_t> panel_user_pulls{0};
    std::atomic<size_t> panel_reports{0};
    std::atomic<bool> stop_panel{false};
    static constexpr std::string_view PanelUserA = "11111111-1111-4111-8111-111111111111";
    static constexpr std::string_view PanelUserB = "22222222-2222-4222-8222-222222222222";
    PeerThread panel_responder([&] {
        while (!stop_panel.load()) {
            pollfd descriptor{panel_listener.Fd(), POLLIN, 0};
            if (::poll(&descriptor, 1, 10) <= 0) continue;
            Socket client;
            try { client = panel_listener.Accept(200ms); }
            catch (...) { continue; }
            try {
                std::string request;
                while (request.find("\r\n\r\n") == std::string::npos) {
                    const auto chunk = client.Read(4096, 500ms);
                    if (chunk.empty()) break;
                    request += chunk;
                }
                if (request.empty()) continue;
                int status = 200;
                std::string body = R"({"data":true})";
                std::string etag;
                if (request.starts_with("POST ")) {
                    ++panel_reports;
                } else if (request.find("/config?") != std::string::npos) {
                    etag = "panel-cfg-v1";
                    body = Json({{"server_port", panel_node_port}, {"network", "tcp"}, {"tls", 0},
                        {"base_config", {{"pull_interval", 1}, {"push_interval", 1}}}}).dump();
                } else if (request.find("/user?") != std::string::npos) {
                    const int phase = panel_phase.load();
                    if (phase == 2) {
                        status = 503;
                        body = R"({"message":"panel maintenance"})";
                    } else {
                        const auto active_user = phase == 0 ? PanelUserA : PanelUserB;
                        etag = phase == 0 ? "users-a" : "users-b";
                        body = Json({{"users", Json::array({{{"id", phase + 1}, {"uuid", active_user},
                            {"speed_limit", nullptr}, {"device_limit", 0}}})}}).dump();
                    }
                    ++panel_user_pulls;
                }
                std::string response = "HTTP/1.1 " + std::to_string(status) +
                    (status == 200 ? " OK\r\n" : " Service Unavailable\r\n") +
                    "Content-Type: application/json\r\nConnection: close\r\n";
                if (!etag.empty()) response += "ETag: \"" + etag + "\"\r\n";
                response += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
                client.Write(response, 500ms);
            } catch (...) {}
        }
    });
    struct PanelGuard {
        std::atomic<bool>& stop;
        PeerThread& thread;
        ~PanelGuard() {
            stop = true;
            try { thread.Join(); } catch (...) {}
        }
    } panel_guard{stop_panel, panel_responder};
    auto hy2_inbound = HysteriaInbound(port);
    hy2_inbound["tag"] = "hy2-in";
    hy2_inbound["sniffing"]["enabled"] = true;
    hy2_inbound["settings"]["upMbps"] = 1000;
    hy2_inbound["settings"]["downMbps"] = 1000;
    hy2_inbound["fallbackTag"] = "anytls-out";

    Json vless_inbound = {{"tag", "vless-in"}, {"protocol", "vless"},
        {"listen", "127.0.0.1"}, {"port", vless_port}, {"fallbackTag", "anytls-out"},
        {"settings", {{"decryption", "none"},
            {"clients", Json::array({{{"id", UserId}}})}}}};

    Json ss_inbound = {{"tag", "ss-udp-in"}, {"protocol", "shadowsocks"},
        {"listen", "127.0.0.1"}, {"port", ss_port}, {"outboundTag", "direct-out"},
        {"settings", {{"method", "2022-blake3-aes-128-gcm"},
            {"clients", Json::array({{{"password", udp::Base64(ss_key)}}})}}}};

    WriteJson(root.Path(), "config.json", {
        {"workers", 4},
        {"dns", {{"servers", Json::array({"127.77.0.53:" + std::to_string(dns_socket.Port())})},
                 {"timeout", 5}, {"cacheSize", 1024}}},
        {"timeouts", {{"handshake", 10}, {"dial", 10}, {"read", 15}, {"write", 30},
                      {"connIdle", 60}, {"uplinkOnly", 5}, {"downlinkOnly", 5}}},
        {"panels", Json::array({{{"name", "full-app"}, {"type", "V2board"},
            {"apiHost", "http://127.0.0.1:" + std::to_string(panel_listener.Port())},
            {"key", "panel-secret"}, {"nodeIDs", {1}}, {"nodeType", "vless"},
            {"fallbackTag", "anytls-out"}}})},
        {"log", {{"enable", true}, {"loglevel", "debug"},
                 {"logDir", (root.Path() / "logs").string()}}}});
    WriteJson(root.Path(), "inbounds.json",
        Json::array({std::move(hy2_inbound), std::move(vless_inbound), std::move(ss_inbound)}));
    WriteJson(root.Path(), "outbounds.json", Json::array({
        {{"tag", "anytls-out"}, {"protocol", "anytls"},
            {"settings", {{"address", "127.0.0.1"}, {"port", upstream_port},
                {"password", "secret"}, {"minIdleSession", 2}}},
            {"streamSettings", TlsSettings(false)}},
        {{"tag", "direct-out"}, {"protocol", "freedom"}, {"settings", Json::object()}},
        {{"tag", "block-out"}, {"protocol", "blackhole"}, {"settings", Json::object()}}}));
    WriteJson(root.Path(), "routing.json", {{"rules", Json::array({
        {{"domain", Json::array({"domain:anytls.route.test"})}, {"outboundTag", "anytls-out"}},
        {{"domain", Json::array({"domain:direct.route.test"})}, {"outboundTag", "direct-out"}},
        {{"domain", Json::array({"domain:blocked.route.test"})}, {"outboundTag", "block-out"}}})}});
    reservation.Close();
    vless_reservation.Close();
    ss_reservation.Release();
    panel_node_reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()},
        root.Path() / "child.log");
    server.WaitForLog("server started");
    Until([&] { return panel_user_pulls.load() >= 1; }, 10s);

    constexpr size_t client_count = 8;
    constexpr size_t rounds = 12;
    const auto direct_tcp_address = "direct.route.test:" + std::to_string(tcp_target.Port());
    const auto anytls_tcp_address = "anytls.route.test:" + std::to_string(tcp_target.Port());
    const auto blocked_tcp_address = "blocked.route.test:" + std::to_string(tcp_target.Port());
    const auto udp_address = "127.0.0.1:" + std::to_string(udp_target.Port());


    struct SessionState {
        std::unique_ptr<Peer> peer;
        int64_t persistent_stream = -1;
        std::string persistent_expected;
        uint32_t udp_session = 0;
        uint16_t origin_udp_port = 0;
    };
    std::vector<SessionState> clients;
    clients.reserve(client_count);
    for (size_t i = 0; i < client_count; ++i) {
        SessionState state;
        state.peer = std::make_unique<Peer>(port);
        const auto init = "init-" + std::to_string(i) + ":";
        state.persistent_stream = state.peer->Open(direct_tcp_address, init);
        state.persistent_expected = init;
        state.udp_session = static_cast<uint32_t>(0x2000 + i);
        clients.push_back(std::move(state));
    }
    Peer stalled_peer(port);
    const auto stalled_stream = stalled_peer.Open(anytls_tcp_address, "stalled-init:");
    stalled_peer.Wait([&] {
        return stalled_peer.PayloadEquals(stalled_stream, "stalled-init:");
    });
    for (size_t attempt = 0; attempt < 16; ++attempt) {
        const auto path = stalled_peer.AddPath();
        stalled_peer.BlockPath(path, true);
        stalled_peer.SwitchPath(path);
        stalled_peer.Send(stalled_stream, "probe");
        stalled_peer.Pump(Milliseconds(1));
    }
    Socket ss_udp_target = Socket::BindUdp();
    udp::Client ss_client(ss_port, ss_udp_target.Port(), true, false,
                          "127.0.0.1", "aes");
    uint16_t ss_origin_port = 0;

    auto pump_all = [&] {
        for (auto& client : clients) client.peer->Pump(Milliseconds(1));
        for (size_t step = 0; step < 32; ++step) {
            std::array<char, 4096> bytes{};
            sockaddr_in source{};
            socklen_t length = sizeof(source);
            const auto count = ::recvfrom(udp_target.Fd(), bytes.data(), bytes.size(),
                MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&source), &length);
            if (count < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                throw std::system_error(errno, std::generic_category(), "receive concurrent UDP");
            }
            std::string reply(bytes.data(), static_cast<size_t>(count));
            reply.append(reinterpret_cast<const char*>(&source.sin_port), 2);
            const auto sent = ::sendto(udp_target.Fd(), reply.data(), reply.size(), MSG_NOSIGNAL,
                reinterpret_cast<const sockaddr*>(&source), sizeof(source));
            ASSERT_EQ(sent, static_cast<ssize_t>(reply.size()));
        }
    };

    auto decode_udp_reply = [](std::string_view wire, uint32_t expected_session,
                               std::string_view expected_address) {
        udp::Require(wire.size() >= 9 &&
            ReadBigEndian(wire.substr(0, 4)) == expected_session &&
            static_cast<uint8_t>(wire[7]) == 1, "concurrent HY2 UDP header mismatch");
        const size_t width = size_t{1} << (static_cast<uint8_t>(wire[8]) >> 6);
        udp::Require(width <= wire.size() - 8, "truncated concurrent HY2 UDP address width");
        size_t length = static_cast<uint8_t>(wire[8]) & 0x3f;
        for (size_t i = 1; i < width; ++i)
            length = (length << 8) | static_cast<uint8_t>(wire[8 + i]);
        udp::Require(length <= wire.size() - 8 - width &&
            wire.substr(8 + width, length) == expected_address,
            "concurrent HY2 UDP source address mismatch");
        return std::string(wire.substr(8 + width + length));
    };

    for (size_t round = 0; round < rounds; ++round) {
        for (size_t i = 0; i < clients.size(); ++i) {
            if ((round & 1) == 0) {
                const auto path = clients[i].peer->AddPath();
                clients[i].peer->SwitchPath(path);
            } else {
                clients[i].peer->SwitchPath(0);
            }
        }
        std::vector<int64_t> ephemeral_streams(clients.size(), -1);
        std::vector<std::string> ephemeral_expected(clients.size());
        std::vector<std::string> udp_expected(clients.size());
        for (size_t i = 0; i < clients.size(); ++i) {
            auto& client = clients[i];
            const auto chunk = "p-" + std::to_string(i) + "-" + std::to_string(round) + ":";
            client.peer->Send(client.persistent_stream, chunk);
            client.persistent_expected += chunk;

            const size_t payload_bytes = (round % 4) == 0 ? 72 * 1024 : 1024;
            ephemeral_expected[i] = "ephemeral-" + std::to_string(i) + "-" +
                std::to_string(round) + ":" +
                std::string(payload_bytes, static_cast<char>('a' + (round % 26)));
            ephemeral_streams[i] = client.peer->Open(anytls_tcp_address, ephemeral_expected[i]);

            if ((round % 3) == 0) {
                const auto reset_id = client.peer->Open(anytls_tcp_address, "aborted-request");
                client.peer->Reset(reset_id);
                const auto blocked_id = client.peer->Open(blocked_tcp_address, "blocked-request");
                (void)blocked_id;
            }

            udp_expected[i] = "udp-" + std::to_string(i) + "-" + std::to_string(round);
            const auto packet_id = static_cast<uint16_t>(round * 8 + 1);
            if ((round & 1) == 0) {
                client.peer->SendDatagram(UdpWire(
                    client.udp_session, packet_id, 0, 1, udp_address, udp_expected[i]));
            } else {
                const auto head = udp_expected[i].substr(0, 4);
                const auto tail = udp_expected[i].substr(4);
                client.peer->SendDatagram(UdpWire(
                    client.udp_session, packet_id, 1, 2, {}, tail));
                client.peer->SendDatagram(UdpWire(
                    client.udp_session, packet_id, 0, 2, udp_address, head));
            }
        }
        if (round == 0) {
            auto panel_socket = Socket::Connect(panel_node_port);
            const std::string payload = "panel-user-a-round-0";
            panel_socket.Write(VlessRequest(
                tcp_target.Port(), payload, 1, "anytls.route.test", PanelUserA));
            EXPECT_EQ(panel_socket.ReadExact(2 + payload.size()),
                std::string(2, '\0') + payload);
        } else if (round == 4) {
            const auto pulls_before = panel_user_pulls.load();
            panel_phase.store(1);
            Until([&] {
                pump_all();
                return panel_user_pulls.load() > pulls_before;
            }, 5s);
            auto panel_socket = Socket::Connect(panel_node_port);
            const std::string payload = "panel-user-b-round-4";
            panel_socket.Write(VlessRequest(
                tcp_target.Port(), payload, 1, "anytls.route.test", PanelUserB));
            EXPECT_EQ(panel_socket.ReadExact(2 + payload.size()),
                std::string(2, '\0') + payload);
        } else if (round == 8) {
            const auto pulls_before = panel_user_pulls.load();
            panel_phase.store(2);
            Until([&] {
                pump_all();
                return panel_user_pulls.load() > pulls_before;
            }, 5s);
            auto panel_socket = Socket::Connect(panel_node_port);
            const std::string payload = "panel-user-b-survives-503";
            panel_socket.Write(VlessRequest(
                tcp_target.Port(), payload, 1, "anytls.route.test", PanelUserB));
            EXPECT_EQ(panel_socket.ReadExact(2 + payload.size()),
                std::string(2, '\0') + payload);

            auto vless_socket = Socket::Connect(vless_port);
            const std::string vless_payload = "vless-static-round-8";
            vless_socket.Write(VlessRequest(
                tcp_target.Port(), vless_payload, 1, "anytls.route.test"));
            EXPECT_EQ(vless_socket.ReadExact(2 + vless_payload.size()),
                std::string(2, '\0') + vless_payload);
        }
        ss_client.socket = std::make_shared<Socket>(Socket::BindUdp());
        const std::string ss_payload = "ss2022-round-" + std::to_string(round);
        (void)ss_client.Send(ss_payload);
        auto ss_received = udp::Receive(ss_udp_target);
        EXPECT_EQ(ss_received.payload, ss_payload);
        const auto* ss_sin = reinterpret_cast<const sockaddr_in*>(&ss_received.address);
        if (ss_origin_port == 0) ss_origin_port = ss_sin->sin_port;
        EXPECT_EQ(ss_sin->sin_port, ss_origin_port)
            << "SS2022 passive migration replaced its outbound UDP socket";
        udp::Reply(ss_udp_target, ss_received, "ss2022-reply-" + std::to_string(round));
        ss_client.Expect("ss2022-reply-" + std::to_string(round));

        const auto deadline = std::chrono::steady_clock::now() + 15s;
        auto next_udp_retry = std::chrono::steady_clock::now() + 200ms;
        std::vector<bool> ephemeral_closing(clients.size(), false);
        std::vector<bool> udp_done(clients.size(), false);
        for (;;) {
            if (std::chrono::steady_clock::now() >= deadline) {
                for (size_t i = 0; i < clients.size(); ++i) {
                    std::cerr << "timeout round=" << round << " client=" << i
                              << " persistent_ok=" << clients[i].peer->PayloadEquals(
                                     clients[i].persistent_stream, clients[i].persistent_expected)
                              << " ephemeral_ok=" << clients[i].peer->PayloadEquals(
                                     ephemeral_streams[i], ephemeral_expected[i])
                              << " ephemeral_closed=" << clients[i].peer->StreamClosed(ephemeral_streams[i])
                              << " udp_done=" << udp_done[i]
                              << " (" << clients[i].peer->DescribeStream(ephemeral_streams[i]) << ")\n";
                }
                tcp_target.Join();
                FAIL() << "concurrent migration round=" << round << " timed out";
            }
            pump_all();
            const auto now = std::chrono::steady_clock::now();
            const bool retry_udp = now >= next_udp_retry;
            if (retry_udp) next_udp_retry = now + 200ms;
            bool all_done = true;
            for (size_t i = 0; i < clients.size(); ++i) {
                auto& client = clients[i];
                if (!client.peer->PayloadEquals(client.persistent_stream, client.persistent_expected))
                    all_done = false;
                if (client.peer->PayloadEquals(ephemeral_streams[i], ephemeral_expected[i])) {
                    if (!ephemeral_closing[i]) {
                        client.peer->Send(ephemeral_streams[i], "", true);
                        ephemeral_closing[i] = true;
                    }
                    if (!client.peer->StreamClosed(ephemeral_streams[i]))
                        all_done = false;
                } else {
                    all_done = false;
                }
                if (!udp_done[i]) {
                    if (client.peer->HasDatagram()) {
                        const auto wire = client.peer->ReadDatagram();
                        const auto body = decode_udp_reply(wire, client.udp_session, udp_address);
                        ASSERT_EQ(body.size(), udp_expected[i].size() + 2);
                        EXPECT_EQ(body.substr(0, udp_expected[i].size()), udp_expected[i]);
                        uint16_t port_bytes = 0;
                        std::memcpy(&port_bytes, body.data() + udp_expected[i].size(), 2);
                        if (client.origin_udp_port == 0) client.origin_udp_port = port_bytes;
                        EXPECT_EQ(port_bytes, client.origin_udp_port)
                            << "concurrent migration replaced AnyTLS UoT UDP association";
                        udp_done[i] = true;
                    } else {
                        if (retry_udp) {
                            const auto packet_id = static_cast<uint16_t>(round * 8 + 1);
                            client.peer->SendDatagram(UdpWire(
                                client.udp_session, packet_id, 0, 1, udp_address, udp_expected[i]));
                        }
                        all_done = false;
                    }
                }
            }
            if (all_done) break;
        }
    }

    for (auto& client : clients) {
        EXPECT_FALSE(client.peer->Closed());
        client.peer->Send(client.persistent_stream, "", true);
    }
    const auto close_deadline = std::chrono::steady_clock::now() + 10s;
    for (;;) {
        ASSERT_LT(std::chrono::steady_clock::now(), close_deadline);
        pump_all();
        const bool closed = std::all_of(clients.begin(), clients.end(), [](const auto& client) {
            return client.peer->StreamClosed(client.persistent_stream);
        });
        if (closed) break;
    }
    EXPECT_EQ(server.Stop(10s), 0);
    EXPECT_EQ(upstream.Stop(10s), 0);
    tcp_target.Join();
    std::string logs = ReadFile(server.LogPath());
    for (const auto& entry : std::filesystem::directory_iterator(root.Path() / "logs")) {
        if (entry.is_regular_file()) logs += ReadFile(entry.path());
    }
    EXPECT_NE(logs.find("QUIC passive handoff committed"), std::string::npos);
    EXPECT_NE(logs.find("path_evidence=challenge"), std::string::npos);
    EXPECT_NE(logs.find("path_evidence=reused"), std::string::npos);
    EXPECT_GT(dns_queries.load(), 0u);
    EXPECT_NE(logs.find("UDP passive handoff"), std::string::npos);
    EXPECT_GT(panel_user_pulls.load(), 2u);
    EXPECT_GT(panel_reports.load(), 0u);
}
} // namespace
} // namespace cnode::e2e::quic
