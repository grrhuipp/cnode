#include "quic_peer.hpp"

#include <atomic>
#include <cerrno>
#include <stdexcept>
#include <system_error>

namespace cnode::e2e::quic {
namespace {

void Exchange(Peer& peer, int64_t stream, std::string_view bytes, std::string& expected) {
    expected += bytes;
    peer.Send(stream, bytes);
    peer.WaitPayload(stream, expected);
}

enum class Retirement { ClientReset, InputBackpressure };
class QuicInputCredit : public testing::TestWithParam<Retirement> {};

TEST_P(QuicInputCredit, RetiredRequestCannotExhaustUnrelatedStreams) {
    TempDir root;
    const bool client_reset = GetParam() == Retirement::ClientReset;
    DnsBlackhole dns(!client_reset);
    std::atomic<unsigned> targets_opened = 0;
    Targets target([&](Socket& socket) {
        ++targets_opened;
        for (;;) {
            const auto bytes = socket.Read(65536, 30s);
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
    config["timeouts"] = {{"handshake", 10}, {"connIdle", 120}, {"write", 10},
                           {"uplinkOnly", 1}, {"downlinkOnly", 1}};
    WriteJson(root.Path(), "config.json", config);
    reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForLog("server started");
    Peer peer(port);
    const std::string target_address = "127.0.0.1:" + std::to_string(target.Port());
    const auto control = peer.Open(target_address);
    std::string expected;
    Exchange(peer, control, "control-ready", expected);

    const size_t rounds = client_reset ? 272 : 40;
    const size_t size = client_reset ? 64 * 1024 : 768 * 1024;
    std::string payload(size, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251);
    for (size_t round = 0; round < rounds; ++round) {
        try {
            if (!client_reset) dns.Hold();
            const std::string host = "hold-" + std::to_string(round) + ".credit.test";
            const auto stream = peer.Open(host + ":" + std::to_string(target.Port()), "x");
            peer.Wait([&] { return dns.Observed(host); });
            peer.Send(stream, payload, !client_reset);
            if (client_reset) {
                peer.WaitStream(stream, [&] { return peer.AllAcknowledged(stream); }, 3s);
                peer.Reset(stream);
                peer.WaitClosed(stream, 3s);
            } else {
                // DNS has not released an address, so no production consumer
                // can drain this request. Exhaust the actual advertised window,
                // not an arbitrary delay or a reset-as-success budget check.
                peer.WaitStream(stream, [&] {
                    return peer.StreamSendCredit(stream) == 0 &&
                        peer.Submitted(stream) < peer.Queued(stream) &&
                        peer.Acknowledged(stream) == peer.Submitted(stream);
                }, 3s);
                EXPECT_GT(peer.Submitted(stream), 0u) << peer.DescribeStream(stream);
                EXPECT_GT(peer.SendCredit(), 0u) << peer.DescribeStream(stream);
                EXPECT_FALSE(peer.StreamClosed(stream)) << peer.DescribeStream(stream);
                Exchange(peer, control, "|while-input-blocked", expected);
                dns.Release();
                const std::string echoed = "x" + payload;
                peer.WaitStream(stream, [&] {
                    dns.Observed(host); // Answer any later A/AAAA question too.
                    return peer.StreamClosed(stream) && peer.PayloadEquals(stream, echoed);
                }, 10s);
                peer.WaitPayload(stream, echoed, true);
                EXPECT_TRUE(peer.AllAcknowledged(stream)) << peer.DescribeStream(stream);
            }
            // This uses the original stream and QUIC connection, not a reconnect.
            Exchange(peer, control, "|" + std::to_string(round), expected);
        } catch (const std::exception& error) {
            throw std::runtime_error("QUIC credit round " + std::to_string(round) + ": " + error.what());
        }
    }
    const auto fresh = peer.Open(target_address, "new-stream-after-retirement");
    peer.WaitPayload(fresh, "new-stream-after-retirement");
    EXPECT_FALSE(peer.Closed());
    EXPECT_EQ(peer.Payload(control), expected);
    EXPECT_EQ(targets_opened.load(), client_reset ? 2u : static_cast<unsigned>(rounds + 2));
    peer.Reset(fresh);
    peer.Reset(control);
    peer.WaitClosed(fresh);
    peer.WaitClosed(control);
    EXPECT_EQ(server.Stop(), 0);
    target.Join();
}

INSTANTIATE_TEST_SUITE_P(TerminalPaths, QuicInputCredit,
    testing::Values(Retirement::ClientReset, Retirement::InputBackpressure),
    [](const testing::TestParamInfo<Retirement>& info) {
        return info.param == Retirement::ClientReset ? "ClientReset" : "InputBackpressure";
    });

TEST(QuicInputCredit, NormalFinKeepsConnectionReusableBeyondItsInitialWindow) {
    TempDir root;
    Targets target([](Socket& socket) {
        for (;;) {
            const auto bytes = socket.Read(65536, 30s);
            if (bytes.empty()) break;
            socket.Write(bytes);
        }
    });
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    Configure(root.Path(), HysteriaInbound(port),
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForLog("server started");
    Peer peer(port);
    const std::string address = "127.0.0.1:" + std::to_string(target.Port());
    std::string payload(2 * 1024 * 1024, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251);
    for (size_t round = 0; round < 9; ++round) {
        const auto stream = peer.Open(address);
        peer.Send(stream, payload, true);
        peer.WaitPayload(stream, payload, true, 10s);
        EXPECT_TRUE(peer.AllAcknowledged(stream)) << peer.DescribeStream(stream);
    }
    const auto fresh = peer.Open(address, "after-normal-fin");
    peer.WaitPayload(fresh, "after-normal-fin");
    EXPECT_FALSE(peer.Closed());
    peer.Reset(fresh);
    peer.WaitClosed(fresh);
    EXPECT_EQ(server.Stop(), 0);
    target.Join();
}

enum class OutputEnd { Resume, Reset, Shutdown };

void FinishBackpressuredWriter(OutputEnd ending) {
    TempDir root;
    constexpr size_t ReceiveWindow = 16 * 1024;
    std::string payload(2 * 1024 * 1024, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251);
    std::atomic<bool> exact_uplink = false;
    std::atomic<bool> target_closed = false;
    Targets target([&](Socket& socket) {
        const auto command = socket.ReadExact(1);
        if (command == "D") {
            // Downlink starts before the client supplies the large uplink, so
            // this specifically pressures Connection::WriteStream, not input.
            if (ending != OutputEnd::Resume) {
                try {
                    socket.Write(payload);
                    if (!socket.Read(1).empty())
                        throw std::runtime_error("aborted writer received unexpected uplink");
                } catch (const std::system_error& error) {
                    if (error.code().value() != ECONNRESET && error.code().value() != EPIPE)
                        throw;
                }
                target_closed = true;
                return;
            }
            socket.Write(payload);
            if (socket.ReadExact(payload.size()) != payload)
                throw std::runtime_error("backpressured uplink payload mismatch");
            exact_uplink = true;
            if (!socket.Read(1).empty())
                throw std::runtime_error("backpressured uplink missing normal EOF");
            socket.ShutdownWrite();
            return;
        }
        if (command != "C") throw std::runtime_error("unexpected target command");
        socket.Write(command);
        for (;;) {
            const auto bytes = socket.Read(65536, 30s);
            if (bytes.empty()) break;
            socket.Write(bytes);
        }
    });
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    Configure(root.Path(), HysteriaInbound(port),
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForLog("server started");
    Peer peer(port, "smoke-secret", 65535, ReceiveWindow);
    const std::string address = "127.0.0.1:" + std::to_string(target.Port());
    const auto control = peer.Open(address, "C");
    std::string expected = "C";
    peer.WaitPayload(control, expected);
    const auto stream = peer.Open(address);
    peer.HoldReceiveCredit(stream);
    peer.Send(stream, "D");
    peer.WaitStream(stream, [&] { return peer.Received(stream) == ReceiveWindow; });

    // These are real request/response barriers while Pump continues ACKing the
    // stalled stream. A connection-wide stall or a stopped packet pump cannot
    // make them pass. The producer supplies 2 MiB, above the 512 KiB queue cap.
    for (size_t round = 0; round < 64; ++round) {
        Exchange(peer, control, "|" + std::to_string(round), expected);
        peer.WaitStream(stream, [&] {
            return !peer.StreamClosed(stream) && peer.Received(stream) == ReceiveWindow;
        });
    }
    const auto received = peer.Payload(stream);
    EXPECT_EQ(received, std::string_view(payload).substr(0, received.size()));
    if (ending == OutputEnd::Shutdown) {
        EXPECT_EQ(server.Stop(), 0);
        Until([&] { return target_closed.load(); });
        target.Join();
        return;
    }
    if (ending == OutputEnd::Reset) {
        peer.Reset(stream);
        peer.WaitClosed(stream);
        peer.Wait([&] { return target_closed.load(); });
    } else {
        peer.HoldReceiveCredit(stream, false);
        peer.Send(stream, payload, true);
        peer.WaitPayload(stream, payload, true, 10s);
        EXPECT_TRUE(peer.AllAcknowledged(stream)) << peer.DescribeStream(stream);
        EXPECT_TRUE(exact_uplink.load());
    }
    Exchange(peer, control, "|after-writer-finished", expected);
    const auto fresh = peer.Open(address, "Cafter-response-fin");
    peer.WaitPayload(fresh, "Cafter-response-fin");
    EXPECT_FALSE(peer.Closed());
    peer.Reset(fresh);
    peer.Reset(control);
    peer.WaitClosed(fresh);
    peer.WaitClosed(control);
    EXPECT_EQ(server.Stop(), 0);
    target.Join();
}

TEST(QuicInputCredit, WithheldResponseCreditBackpressuresProductionWriter) {
    FinishBackpressuredWriter(OutputEnd::Resume);
}

TEST(QuicInputCredit, ResetBackpressuredWriterKeepsOtherStreamsUsable) {
    FinishBackpressuredWriter(OutputEnd::Reset);
}

TEST(QuicInputCredit, ShutdownJoinsBackpressuredWriterAndClosesTarget) {
    FinishBackpressuredWriter(OutputEnd::Shutdown);
}

} // namespace
} // namespace cnode::e2e::quic
