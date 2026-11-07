#include "http2_peer.hpp"
#include <openssl/base64.h>

namespace cnode::e2e::http2 {
namespace {
std::string FixtureKey(std::string_view hex) {
    std::string bytes;
    for (size_t offset = 0; offset < hex.size(); offset += 2)
        bytes += static_cast<char>(std::stoul(std::string(hex.substr(offset, 2)), nullptr, 16));
    std::string encoded(4 * ((bytes.size() + 2) / 3) + 1, '\0');
    const int count = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()),
                                     reinterpret_cast<const unsigned char*>(bytes.data()),
                                     static_cast<int>(bytes.size()));
    Require(count > 0, "encoding fixture key");
    encoded.resize(static_cast<size_t>(count));
    while (encoded.ends_with('=')) encoded.pop_back();
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    return encoded;
}
void Deadlines(Node& node, unsigned handshake) {
    PatchConfig(node.root.Path(), [&](Json& config) { config["timeouts"]["handshake"] = handshake; config["timeouts"]["write"] = 30; config["timeouts"]["connIdle"] = 30; config["log"]["loglevel"] = "debug"; });
}
class Http2H1Deadline : public testing::TestWithParam<std::string> {};
TEST_P(Http2H1Deadline, IncompleteProxyExpiresButActiveTransportOutlivesHandshake) {
    const auto mode = GetParam();
    Targets target([](Socket& socket) { for (;;) { auto data = socket.Read(); if (data.empty()) break; socket.Write(data); } });
    Node node; node.Setup("xhttp", false, mode); Deadlines(node, 1); node.Start();
    auto down = [&](std::string_view name) {
        auto wire = std::make_unique<Wire>(node.port, false, "", false);
        wire->Write("GET /fixture/" + std::string(name) + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
        auto header = wire->HttpResponse(); std::transform(header.begin(), header.end(), header.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        Require(header.find("transfer-encoding: chunked") != std::string::npos, "downlink was not chunked"); return wire;
    };
    auto slow = down("slow"); const auto before = Clock::now(); std::string ending;
    for (;;) { auto data = slow->Read(65536, 3s); if (data.empty()) break; ending += data; }
    EXPECT_TRUE(ending.empty() || ending == "0\r\n\r\n"); EXPECT_GE(Clock::now() - before, 500ms);
    auto active = down("active"); Chunked chunks(*active); std::unique_ptr<Wire> upload;
    if (mode == "stream-up") {
        upload = std::make_unique<Wire>(node.port, false, "", false);
        upload->Write("POST /fixture/active HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"); upload->HttpResponse();
    }
    auto send = [&](unsigned sequence, const std::string& data) {
        if (upload) { auto wire = Chunk(data); if (sequence == 1) wire.erase(0, 1); upload->Write(wire); }
        else H1Packet(node.port, false, "active", sequence, data);
    };
    auto start = Clock::now(); send(0, VlessRequest(target.Port(), Ready));
    if (upload) upload->Write(Hex(Echo.size()).substr(0, 1));
    EXPECT_EQ(chunks.Exact(Response.size()), Response);
    unsigned sequence = 1;
    while (Clock::now() - start < 2200ms) { std::this_thread::sleep_for(100ms); send(sequence++, Echo); EXPECT_EQ(chunks.Exact(Echo.size()), Echo); }
    EXPECT_GT(sequence, 1U); EXPECT_TRUE(node.child->Running()); target.Join();
}
INSTANTIATE_TEST_SUITE_P(SplitUploadModes, Http2H1Deadline, testing::Values(std::string("packet-up"), std::string("stream-up")));

std::string WebSocketFrame(uint8_t opcode, std::string_view payload) {
    std::string frame(1, static_cast<char>(0x80 | opcode));
    if (payload.size() < 126) frame += static_cast<char>(0x80 | payload.size());
    else if (payload.size() <= 65535) frame += std::string(1, '\xfe') + BigEndian(payload.size(), 2);
    else frame += std::string(1, '\xff') + BigEndian(payload.size(), 8);
    constexpr std::string_view mask = "loop"; frame += mask;
    for (size_t i = 0; i < payload.size(); ++i) frame += static_cast<char>(static_cast<unsigned char>(payload[i]) ^ mask[i % 4]);
    return frame;
}
std::pair<uint8_t, std::string> WebSocketRead(Wire& wire) {
    auto header = wire.Exact(2); Require(!(static_cast<uint8_t>(header[1]) & 128), "server masked a WebSocket frame");
    uint64_t length = static_cast<uint8_t>(header[1]) & 127;
    if (length >= 126) length = ReadBigEndian(wire.Exact(length == 126 ? 2 : 8));
    Require(length <= 65536, "oversize WebSocket frame"); return {static_cast<uint8_t>(header[0]) & 15, wire.Exact(length)};
}
class Http2WebSocketDeadline : public testing::TestWithParam<std::string> {};
TEST_P(Http2WebSocketDeadline, DecoderResumesAcrossSniffAndCloseCancelsTarget) {
    const auto mode = GetParam(); std::atomic<bool> target_closed{false};
    Targets target([&](Socket& socket) { for (;;) { auto data = socket.Read(); if (data.empty()) break; socket.Write(data); } target_closed = true; });
    Node node; node.Setup("ws", false); Deadlines(node, 1); node.Start();
    std::string upgrade = "GET /fixture HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    if (mode == "upgrade-rejection") {
        for (auto [from, to] : std::vector<std::pair<std::string, std::string>>{{"GET ", "POST "}, {"HTTP/1.1", "HTTP/1.0"}, {"Connection: Upgrade", "Connection: keep-alive"}, {"Version: 13", "Version: 12"}, {"dGhlIHNhbXBsZSBub25jZQ==", "not-a-key"}, {"dGhlIHNhbXBsZSBub25jZQ==", std::string(24, 'a')}}) {
            auto invalid = upgrade; invalid.replace(invalid.find(from), from.size(), to);
            Wire rejected(node.port, false); rejected.Write(invalid);
            try { EXPECT_TRUE(rejected.Read(65536, 3s).empty()); }
            catch (const std::system_error& error) { EXPECT_EQ(error.code().value(), ECONNRESET); }
        }
        const std::string from = "Connection: Upgrade";
        upgrade.replace(upgrade.find(from), from.size(), "Connection: keep-alive, uPgRaDe");
    }
    Wire wire(node.port, false); wire.Write(upgrade); wire.HttpResponse("HTTP/1.1 101 ");
    wire.Write(WebSocketFrame(2, VlessRequest(target.Port(), Ready)));
    const auto expected = mode == "extended-resume" ? Pattern(502) : mode == "large-extended-resume" ? std::string(65536, 'A') : Echo;
    const auto continuation = mode == "ping-resume" ? WebSocketFrame(9, "ping-owned") : WebSocketFrame(2, expected);
    const std::map<std::string, size_t> prefixes{{"prefix-resume", 1}, {"mask-resume", 4}, {"extended-resume", 3}, {"large-extended-resume", 6}, {"payload-resume", 11}, {"ping-resume", 8}};
    auto found = prefixes.find(mode); size_t prefix = found == prefixes.end() ? 0 : found->second;
    if (prefix) wire.Write(std::string_view(continuation).substr(0, prefix));
    std::string pending;
    auto exact = [&](size_t count) {
        while (pending.size() < count) { auto [opcode, bytes] = WebSocketRead(wire); Require(opcode == 0 || opcode == 2, "control frame leaked into proxy bytes"); pending += bytes; }
        auto out = pending.substr(0, count); pending.erase(0, count); return out;
    };
    EXPECT_EQ(exact(Response.size()), Response);
    std::string early;
    if (mode == "payload-resume") { early = exact(prefix - 6); EXPECT_EQ(early, expected.substr(0, early.size())); }
    if (prefix) {
        wire.Write(std::string_view(continuation).substr(prefix));
        if (mode == "ping-resume") { auto [opcode, bytes] = WebSocketRead(wire); EXPECT_EQ(opcode, 10); EXPECT_EQ(bytes, "ping-owned"); wire.Write(WebSocketFrame(2, expected)); }
        EXPECT_EQ(early + exact(expected.size() - early.size()), expected);
    }
    const auto start = Clock::now(); wire.Write(WebSocketFrame(8, std::string("\x03\xe8", 2)));
    auto [opcode, bytes] = WebSocketRead(wire); EXPECT_EQ(opcode, 8); EXPECT_EQ(bytes.substr(0, 2), std::string("\x03\xe8", 2));
    EXPECT_TRUE(wire.Read(65536, 2s).empty()); Until([&] { return target_closed.load(); }, 2s); EXPECT_LT(Clock::now() - start, 2s);
    EXPECT_TRUE(node.child->Running()); target.Join();
}
INSTANTIATE_TEST_SUITE_P(FramingAndClose, Http2WebSocketDeadline, testing::Values(
    std::string("full-close"), std::string("prefix-resume"), std::string("mask-resume"), std::string("extended-resume"), std::string("large-extended-resume"), std::string("payload-resume"), std::string("ping-resume"), std::string("upgrade-rejection")));

// Maps a real encrypted cnode client's bytes to XHTTP packets. Encryption remains
// entirely in the two production cnode processes; this bridge only owns framing.
class EncryptedBridge {
    Socket listener_ = Socket::Listen();
    std::mutex mutex_;
    std::vector<std::shared_ptr<Socket>> clients_;
    std::vector<std::unique_ptr<PeerThread>> uploaders_;
    std::unique_ptr<PeerThread> accept_;
    std::atomic<bool> stop_{false};
public:
    std::atomic<unsigned> uploads[2]{};
    explicit EncryptedBridge(uint16_t front) {
        accept_ = std::make_unique<PeerThread>([&, front] {
            for (unsigned index = 0; index < 2; ++index) {
                auto client = std::make_shared<Socket>(listener_.Accept(15s));
                { std::lock_guard lock(mutex_); clients_.push_back(client); }
                uploaders_.push_back(std::make_unique<PeerThread>([this, front, index, client] {
                    try {
                        for (unsigned sequence = 0; !stop_; ++sequence) {
                            auto bytes = client->Read(65536, 30s); if (bytes.empty()) break;
                            H1Packet(front, false, "s" + std::to_string(index * 2 + 1), sequence, bytes); ++uploads[index];
                        }
                    } catch (...) { if (!stop_) throw; }
                }));
            }
        });
    }
    ~EncryptedBridge() { try { Join(); } catch (...) { ADD_FAILURE() << "unobserved encrypted byte bridge failure"; } }
    uint16_t Port() const { return listener_.Port(); }
    void Forward(Peer& peer) {
        std::lock_guard lock(mutex_);
        for (size_t i = 0; i < clients_.size(); ++i) {
            auto sid = static_cast<uint32_t>(i * 2 + 1); auto& bytes = peer.messages[sid];
            if (!bytes.empty()) { clients_[i]->Write(bytes); bytes.clear(); }
            if (peer.Terminal(sid)) shutdown(clients_[i]->Fd(), SHUT_WR);
        }
    }
    void Join() {
        if (!accept_) return;
        stop_ = true;
        // Accept has a finite deadline even on an earlier assertion failure.
        std::exception_ptr error;
        try { accept_->Join(); } catch (...) { error = std::current_exception(); }
        accept_.reset();
        { std::lock_guard lock(mutex_); for (auto& client : clients_) shutdown(client->Fd(), SHUT_RDWR); }
        for (auto& thread : uploaders_) { try { thread->Join(); } catch (...) { if (!error) error = std::current_exception(); } }
        uploaders_.clear(); if (error) std::rethrow_exception(error);
    }
};
TEST(Http2EncryptedDeadline, ExpiredChildReturnsQuotaBeforeBlockedSiblingResumes) {
    constexpr size_t FloodSize = 256 * 65536;
    std::atomic<bool> go{false}, drained{false}, closed{false}; std::atomic<size_t> sent{0};
    std::mutex mutex; std::set<char> tags;
    Targets target([&](Socket& socket) {
        const auto tag = socket.ReadExact(1)[0]; { std::lock_guard lock(mutex); tags.insert(tag); }
        socket.Write(Ready);
        if (tag == 'A') {
            try {
                Until([&] { return go.load(); }, 10s); int size = 4096; setsockopt(socket.Fd(), SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
                const std::string flood(65536, 'A');
                for (size_t i = 0; i < 256; ++i) { socket.Write(flood, 30s); sent += flood.size(); }
                drained = true;
                for (;;) { auto bytes = socket.Read(65536, 30s); if (bytes.empty()) break; socket.Write(bytes); }
            } catch (...) { closed = true; throw; }
            closed = true;
        } else for (;;) { auto bytes = socket.Read(65536, 30s); if (bytes.empty()) break; socket.Write(bytes); }
    });
    Node server, client; server.Setup("xhttp", false, "packet-up");
    Socket probe_reservation = Socket::Listen(); const auto probe_port = probe_reservation.Port();
    auto inbounds = Json::parse(ReadFile(server.root.Path() / "inbounds.json"));
    // RFC 7748 section 6.1 public fixture vector, never deployment keys.
    inbounds.at(0)["settings"]["decryption"] = "mlkem768x25519plus.native.0s." +
        FixtureKey("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto probe = inbounds.at(0); probe["tag"] = "probe-in"; probe["port"] = probe_port; probe["settings"] = Protocol(); probe.erase("streamSettings"); inbounds.push_back(probe);
    WriteJson(server.root.Path(), "inbounds.json", inbounds); Deadlines(server, 8);
    auto routing = Json::parse(ReadFile(server.root.Path() / "routing.json"));
    routing["rules"].at(0)["inboundTag"].push_back("probe-in");
    WriteJson(server.root.Path(), "routing.json", routing);
    PatchConfig(server.root.Path(), [](Json& config) { config["limits"] = {{"maxConnections", 3}, {"maxConnectionsPerIP", 3}}; });
    probe_reservation.Close(); server.Start();
    Peer peer(server.port, false, "xhttp"); int receive_buffer = 65536; setsockopt(peer.wire.Fd(), SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer));
    EncryptedBridge bridge(server.port);
    auto outbound = Protocol("vless", bridge.Port());
    outbound["encryption"] = "mlkem768x25519plus.native.1rtt." +
        FixtureKey("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    Configure(client.root.Path(), {{"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", client.port}, {"settings", Protocol()}}, {{"protocol", "vless"}, {"settings", outbound}});
    Deadlines(client, 20); client.Start();
    auto pump_until = [&](const std::function<bool()>& predicate, Milliseconds timeout) {
        auto deadline = Clock::now() + timeout;
        while (!predicate()) { Require(Clock::now() < deadline && !peer.closed, "encrypted bridge observation deadline"); peer.Pump(10ms); bridge.Forward(peer); }
    };
    peer.Down(1, "s1"); auto survivor = Socket::Connect(client.port); survivor.Write(VlessRequest(target.Port(), "A"));
    std::atomic<bool> initial_done{false};
    PeerThread initial([&] { EXPECT_EQ(survivor.ReadExact(Response.size()), Response); initial_done = true; });
    pump_until([&] { return initial_done.load(); }, 5s); initial.Join();
    peer.Down(3, "s3"); const auto opened = Clock::now(); go = true;
    size_t previous = sent; auto stable = Clock::now();
    Until([&] {
        Require(!drained && !closed, "encrypted flood did not remain blocked"); auto current = sent.load();
        if (current != previous) { previous = current; stable = Clock::now(); }
        return current > 0 && Clock::now() - stable >= 300ms;
    }, 5s);
    auto victim = Socket::Connect(client.port); victim.Write(VlessRequest(target.Port(), "V"));
    Until([&] { return bridge.uploads[1].load() > 0; }, 3s); EXPECT_LT(Clock::now() - opened, 7s);
    auto admission_probe = [&](std::string_view tag, Milliseconds timeout) {
        std::unique_ptr<Socket> result;
        Until([&] {
            try { auto attempt = std::make_unique<Socket>(Socket::Connect(probe_port)); attempt->Write(VlessRequest(target.Port(), tag));
                auto response = attempt->ReadExact(Response.size(), 500ms); Require(response == Response, "wrong admission-probe response"); result = std::move(attempt); return true;
            } catch (const std::system_error&) { return false; }
            catch (const std::runtime_error&) { return false; }
        }, timeout);
        return result;
    };
    auto first = admission_probe("P", 1s), second = admission_probe("Q", 10s);
    EXPECT_FALSE(closed); EXPECT_FALSE(drained); EXPECT_FALSE(peer.closed);
    { std::lock_guard lock(mutex); EXPECT_FALSE(tags.contains('V')); }
    first->ShutdownWrite(); EXPECT_TRUE(ReadAll(*first, 2s).empty()); first->Close();
    second->ShutdownWrite(); EXPECT_TRUE(ReadAll(*second, 2s).empty()); second->Close();
    std::atomic<bool> flood_done{false};
    PeerThread consume([&] {
        size_t remaining = FloodSize;
        while (remaining) { auto bytes = survivor.Read(std::min<size_t>(65536, remaining), 8s); Require(!bytes.empty(), "encrypted survivor lost flood"); EXPECT_EQ(bytes, std::string(bytes.size(), 'A')); remaining -= bytes.size(); }
        survivor.Write(Echo); EXPECT_EQ(survivor.ReadExact(Echo.size()), Echo); flood_done = true;
    });
    pump_until([&] { return flood_done.load() && peer.Terminal(3); }, 20s); consume.Join(); peer.Ping("survived");
    EXPECT_FALSE(peer.closed); EXPECT_TRUE(server.child->Running()); EXPECT_TRUE(client.child->Running());
    bridge.Join(); target.Join();
}
} // namespace
} // namespace cnode::e2e::http2
