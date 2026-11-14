#include "udp_wire.hpp"

namespace cnode::e2e::udp {
namespace {

// A VLESS Mux.Cool connection speaking XUDP the way Xray's client does
// (common/mux): every UDP flow is a NEW frame carrying the flow's Global ID.
class XudpConnection {
public:
    XudpConnection(uint16_t port, std::string_view user)
        : socket_(Socket::Connect(port)) {
        // VLESS request, command Mux: no address follows the command.
        socket_.Write(std::string(1, '\0') + UuidBytes(user) + std::string(1, '\0') + "\x03");
    }

    void New(uint16_t sid, uint16_t target, std::string_view global_id, std::string_view payload) {
        const auto meta = BigEndian(sid, 2) + "\x01\x01\x02" + BigEndian(target, 2) +
            "\x01" + std::string("\x7f\x00\x00\x01", 4) + std::string(global_id);
        socket_.Write(BigEndian(meta.size(), 2) + meta + BigEndian(payload.size(), 2) +
                      std::string(payload));
    }

    void Keep(uint16_t sid, std::string_view payload) {
        const auto meta = BigEndian(sid, 2) + "\x02\x01";
        socket_.Write(BigEndian(meta.size(), 2) + meta + BigEndian(payload.size(), 2) +
                      std::string(payload));
    }

    struct Frame {
        uint16_t sid = 0;
        uint8_t status = 0;
        std::string payload;
    };

    // The next frame other than keep-alive.
    Frame Next(Milliseconds timeout = 5s) {
        if (!response_) {
            Require(socket_.ReadExact(2, timeout) == std::string(2, '\0'), "VLESS response header");
            response_ = true;
        }
        for (;;) {
            const auto meta = socket_.ReadExact(
                static_cast<size_t>(ReadBigEndian(socket_.ReadExact(2, timeout))), timeout);
            Require(meta.size() >= 4, "short Mux frame metadata");
            Frame frame{static_cast<uint16_t>(ReadBigEndian(meta.substr(0, 2))),
                        static_cast<uint8_t>(meta[2]), {}};
            if ((static_cast<uint8_t>(meta[3]) & 0x01) != 0) {
                frame.payload = socket_.ReadExact(
                    static_cast<size_t>(ReadBigEndian(socket_.ReadExact(2, timeout))), timeout);
            }
            if (frame.status != 4) return frame;
        }
    }

    void ExpectReply(uint16_t sid, std::string_view payload) {
        const auto frame = Next();
        Require(frame.sid == sid && frame.status == 2 && frame.payload == payload,
                "XUDP reply changed or reached the wrong sub-session");
    }

    void ExpectEnd(uint16_t sid) {
        const auto frame = Next();
        Require(frame.sid == sid && frame.status == 3, "taken-over sub-session did not end");
    }

    void Close() { socket_.Close(); }

private:
    Socket socket_;
    bool response_ = false;
};

TEST(Xudp, GlobalIdKeepsOneOutboundAcrossConnectionsAndWorkers) {
    TempDir root;
    PortReservation reservation;
    auto target = Socket::BindUdp();
    // Four Workers: each reconnect lands on a Worker chosen by the kernel's
    // SO_REUSEPORT hash, so the rounds below cross Workers with near
    // certainty while they always run the same assertions.
    Configure(root.Path(),
        {{"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", reservation.port},
         // A Global ID is scoped by the user identity (ID, email) the inbound
         // reports for the connection.
         {"settings", {{"clients", Json::array({{{"id", UserId}, {"email", "first@xudp"}},
                                                {{"id", SecondUser}, {"email", "second@xudp"}}})}}}},
        {{"protocol", "freedom"}, {"settings", Json::object()}}, 4);
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started");

    const std::string flow_id("\x11\x22\x33\x44\x55\x66\x77\x88", 8);
    auto first = std::make_unique<XudpConnection>(reservation.port, UserId);
    first->New(1, target.Port(), flow_id, "round-0");
    const auto origin = Receive(target);
    Require(origin.payload == "round-0", "first XUDP datagram changed");
    Reply(target, origin, "reply-0");
    first->ExpectReply(1, "reply-0");

    // Each new connection takes the flow over: same outbound source, replies
    // to the newest sub-session, and the previous sub-session ends.
    auto current = std::move(first);
    for (int round = 1; round <= 8; ++round) {
        SCOPED_TRACE(round);
        auto next = std::make_unique<XudpConnection>(reservation.port, UserId);
        const auto payload = "round-" + std::to_string(round);
        next->New(static_cast<uint16_t>(round + 1), target.Port(), flow_id, payload);
        const auto datagram = Receive(target);
        EXPECT_EQ(datagram.payload, payload);
        EXPECT_TRUE(datagram.SameEndpoint(origin)) << "the flow changed its outbound";
        current->ExpectEnd(static_cast<uint16_t>(round));
        const auto reply = "reply-" + std::to_string(round);
        Reply(target, datagram, reply);
        next->ExpectReply(static_cast<uint16_t>(round + 1), reply);
        next->Keep(static_cast<uint16_t>(round + 1), payload + "-again");
        EXPECT_TRUE(Receive(target).SameEndpoint(origin));
        // A closed connection leaves the flow waiting for the next one.
        if (round % 2 == 0) current->Close();
        current = std::move(next);
    }

    // Another Global ID, or the same one from another user, is another flow.
    auto other = std::make_unique<XudpConnection>(reservation.port, UserId);
    other->New(1, target.Port(), std::string("\x01\x02\x03\x04\x05\x06\x07\x08", 8), "other-id");
    const auto other_id = Receive(target);
    EXPECT_EQ(other_id.payload, "other-id");
    EXPECT_FALSE(other_id.SameEndpoint(origin));
    auto stranger = std::make_unique<XudpConnection>(reservation.port, SecondUser);
    stranger->New(1, target.Port(), flow_id, "other-user");
    const auto other_user = Receive(target);
    EXPECT_EQ(other_user.payload, "other-user");
    EXPECT_FALSE(other_user.SameEndpoint(origin));
    EXPECT_FALSE(other_user.SameEndpoint(other_id));
    EXPECT_FALSE(Readable(target.Fd(), 100ms));
    EXPECT_EQ(child.Stop(), 0);
}

}  // namespace
}  // namespace cnode::e2e::udp
