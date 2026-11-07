#include "http2_peer.hpp"

namespace cnode::e2e::http2 {
namespace {
struct TargetState { std::atomic<bool> go{false}, closed{false}, drained{false}; std::atomic<size_t> sent{0}; };
class Http2Substream : public testing::TestWithParam<std::tuple<bool, std::string>> {};
TEST_P(Http2Substream, LogicalLifecycleDoesNotCancelSiblingOrPhysicalAdmission) {
    auto [tls, mode] = GetParam();
    std::mutex mutex;
    std::map<char, std::shared_ptr<TargetState>> states;
    Targets target([&](Socket& socket) {
        auto tag = socket.ReadExact(1)[0];
        auto state = std::make_shared<TargetState>();
        { std::lock_guard lock(mutex); states[tag] = state; }
        try {
            socket.Write(Ready);
            if (tag == 'A') {
                Until([&] { return state->go.load(); });
                int size = 4096; setsockopt(socket.Fd(), SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
                for (int i = 0; i < 1024; ++i) { socket.Write(std::string(65536, 'A')); state->sent += 65536; }
                state->drained = true;
            }
            for (;;) { auto bytes = socket.Read(); if (bytes.empty()) break; socket.Write(bytes); }
        } catch (...) { state->closed = true; if (tag != 'A') throw; return; }
        state->closed = true;
    });
    auto state = [&](char tag) { std::lock_guard lock(mutex); return states.at(tag); };
    auto has = [&](char tag) { std::lock_guard lock(mutex); return states.contains(tag); };
    Node node; node.Setup("grpc", tls);
    if (mode == "slow-handshake" || mode == "quota-one") PatchConfig(node.root.Path(), [&](Json& config) {
        if (mode == "slow-handshake") config["timeouts"]["handshake"] = 1;
        else config["limits"] = {{"maxConnections", 1}, {"maxConnectionsPerIP", 1}};
    });
    node.Start();
    Peer peer(node.port, tls);
    int receive_buffer = 65536; setsockopt(peer.wire.Fd(), SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer));
    if (mode == "slow-handshake") {
        peer.wire.Write(Frame(1, 4, 1, Headers("grpc", tls))); peer.Send(1, std::string(1, '\0'));
        peer.Open(3, target.Port(), "S"); peer.Message(3, Response);
        peer.Wait([&] { return peer.Terminal(1); }, 4s);
        EXPECT_FALSE(peer.closed); peer.Send(3, Echo); peer.Message(3, Response + Echo);
        peer.Open(5, target.Port(), "N"); peer.Message(5, Response); peer.Ping("deadline");
    } else if (mode == "quota-one") {
        peer.Open(1, target.Port(), "V"); peer.Message(1, Response);
        peer.Open(3, target.Port(), "S"); peer.Wait([&] { return peer.Terminal(3); }, 3s);
        EXPECT_FALSE(has('S')); EXPECT_FALSE(peer.closed);
        peer.Send(1, Echo); peer.Message(1, Response + Echo); peer.Reset(1);
        Until([&] { return state('V')->closed.load(); }, 3s); peer.Ping("now-idle");
        // Admission must reject a second physical socket before TLS negotiation.
        auto rejected = Socket::Connect(node.port);
        rejected.Write(std::string(Preface) + Frame(4));
        try { EXPECT_TRUE(rejected.Read(1, 3s).empty()); }
        catch (const std::system_error& error) { EXPECT_EQ(error.code().value(), ECONNRESET); }
        peer.Open(5, target.Port(), "N"); peer.Message(5, Response);
        peer.wire.Close(); Until([&] { return state('N')->closed.load(); }, 3s);
        std::unique_ptr<Peer> recovered;
        Until([&] {
            try {
                auto candidate = std::make_unique<Peer>(node.port, tls);
                candidate->Wait([&] { return candidate->Has(4, 0) || candidate->closed; }, 3s);
                if (!candidate->closed) { recovered = std::move(candidate); return true; }
            } catch (const std::exception&) {}
            return false;
        }, 5s);
        recovered->Open(1, target.Port(), "R"); recovered->Message(1, Response); recovered->Ping("quota-ok");
    } else {
        peer.Open(1, target.Port(), mode == "blocked-reset" ? "A" : "V", mode == "half-close");
        peer.Open(3, target.Port(), "S"); peer.Message(1, Response); peer.Message(3, Response); peer.Ping("prepared");
        if (mode == "blocked-reset") {
            auto victim = state('A'); victim->go = true;
            size_t previous = victim->sent; auto stable = Clock::now();
            Until([&] {
                Require(!victim->drained && !victim->closed, "target flood drained/closed instead of blocking");
                auto now = Clock::now(); auto current = victim->sent.load();
                if (current != previous) { previous = current; stable = now; }
                return current > 0 && now - stable >= 300ms;
            }, 10s);
            EXPECT_FALSE(victim->drained); EXPECT_FALSE(victim->closed);
        }
        if (mode != "half-close") { peer.Reset(1); peer.Reset(1); peer.Reset(1); }
        peer.Send(3, Echo); peer.Message(3, Response + Echo); peer.Ping("survived");
        auto barrier = peer.frames.size();
        peer.Open(5, target.Port(), "N"); peer.Message(5, Response); peer.Ping("recovery");
        if (mode == "half-close") {
            peer.Wait([&] { return peer.Ended(1); });
            EXPECT_TRUE(std::any_of(peer.frames.begin(), peer.frames.end(), [](const auto& f) { return f.type == 1 && (f.flags & 1) && f.stream == 1; }));
        } else {
            for (size_t i = barrier; i < peer.frames.size(); ++i) EXPECT_NE(peer.frames[i].stream, 1U);
            Until([&] { return state(mode == "blocked-reset" ? 'A' : 'V')->closed.load(); }, 5s);
        }
        EXPECT_FALSE(peer.closed);
    }
    EXPECT_TRUE(node.child->Running()); target.Join();
}
INSTANTIATE_TEST_SUITE_P(TcpAndTls, Http2Substream, testing::Combine(testing::Bool(), testing::Values(
    std::string("idle-reset"), std::string("blocked-reset"), std::string("half-close"), std::string("slow-handshake"), std::string("quota-one"))));
} // namespace
} // namespace cnode::e2e::http2
