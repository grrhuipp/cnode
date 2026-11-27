#include "quic_peer.hpp"
#include "udp_wire.hpp"

#include <set>

namespace cnode::e2e::quic {
namespace {

std::string UdpWire(uint32_t session, uint16_t packet, uint8_t fragment,
                    uint8_t count, std::string_view target, std::string_view payload) {
    return BigEndian(session, 4) + BigEndian(packet, 2) + static_cast<char>(fragment) +
        static_cast<char>(count) + udp::QuicVarint(target.size()) +
        std::string(target) + std::string(payload);
}

// A connection reassembles at most 64 packets at once. A new packet beyond
// that evicts the one started first, never a newer packet still in progress.
TEST(QuicFragmentEviction, OverflowEvictsOldestIncompletePacket) {
    TempDir root;
    auto target = Socket::BindUdp();
    auto reservation = Socket::ReserveUdp();
    const auto port = reservation.Port();
    Configure(root.Path(), HysteriaInbound(port),
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForServerStart();
    Peer peer(port);
    const auto address = "127.0.0.1:" + std::to_string(target.Port());
    constexpr uint32_t session = 0x0badcafe;
    constexpr uint16_t kPending = 64;
    auto receive = [&] {
        std::string actual;
        peer.Wait([&] {
            std::array<char, 4096> bytes{};
            const auto count = ::recv(target.Fd(), bytes.data(), bytes.size(), MSG_DONTWAIT);
            if (count < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return false;
                throw std::system_error(errno, std::generic_category(), "receive relayed UDP");
            }
            actual.assign(bytes.data(), static_cast<size_t>(count));
            return true;
        });
        return actual;
    };
    // Packet ID 0xffff is the single-fragment control channel of this session.
    auto control = [&](std::string_view payload) {
        peer.SendDatagram(UdpWire(session, 0xffff, 0, 1, address, payload));
        EXPECT_EQ(receive(), payload);
    };
    control("session-open");
    for (uint16_t packet = 0; packet < kPending; ++packet)
        peer.SendDatagram(UdpWire(session, packet, 0, 2, address, "head-" + std::to_string(packet) + ":"));
    // Heads are processed in order before this datagram is relayed.
    control("heads-buffered");
    peer.SendDatagram(UdpWire(session, kPending, 0, 2, address, "head-" + std::to_string(kPending) + ":"));
    control("overflow-buffered");
    // Completions shrink the table, so these tails evict nothing. Packet 0's
    // tail goes last: it completes the packet only if its head survived.
    for (uint16_t packet = 1; packet <= kPending; ++packet)
        peer.SendDatagram(UdpWire(session, packet, 1, 2, {}, "tail"));
    peer.SendDatagram(UdpWire(session, 0, 1, 2, {}, "tail"));
    peer.SendDatagram(UdpWire(session, 0xffff, 0, 1, address, "tails-sent"));
    std::set<std::string> delivered;
    for (;;) {
        auto payload = receive();
        if (payload == "tails-sent") break;
        EXPECT_TRUE(delivered.insert(std::move(payload)).second) << "duplicate reassembled packet";
    }
    std::set<std::string> expected;
    for (uint16_t packet = 1; packet <= kPending; ++packet)
        expected.insert("head-" + std::to_string(packet) + ":tail");
    EXPECT_EQ(delivered, expected) << "eviction did not drop exactly the oldest packet (head-0)";
    EXPECT_FALSE(peer.Closed());
    EXPECT_EQ(server.Stop(), 0);
}

}  // namespace
}  // namespace cnode::e2e::quic
