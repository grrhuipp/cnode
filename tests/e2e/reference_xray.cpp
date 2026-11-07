#include "reference_support.hpp"

namespace cnode::e2e::reference {
namespace {
// A memory BIO strips the outer VLESS response before the inner TLS engine sees it.
class InnerTls {
public:
    InnerTls(Socket& socket, int version, bool vless) : socket_(socket), header_(vless), context_(false) {
        SSL_CTX_set_min_proto_version(context_.Get(), version);
        SSL_CTX_set_max_proto_version(context_.Get(), version);
        ssl_.reset(SSL_new(context_.Get()));
        Require(bool(ssl_), "SSL_new failed");
        incoming_ = BIO_new(BIO_s_mem()); outgoing_ = BIO_new(BIO_s_mem());
        Require(incoming_ && outgoing_, "BIO allocation failed");
        SSL_set_bio(ssl_.get(), incoming_, outgoing_);
        SSL_set_connect_state(ssl_.get());
        SSL_set_tlsext_host_name(ssl_.get(), "localhost");
        for (;;) {
            const int result = SSL_do_handshake(ssl_.get());
            Flush();
            if (result == 1) break;
            WantRead(result);
        }
        EXPECT_EQ(SSL_version(ssl_.get()), version);
    }
    void Write(std::string_view data) {
        while (!data.empty()) {
            const int count = SSL_write(ssl_.get(), data.data(), static_cast<int>(std::min<size_t>(8191, data.size())));
            Flush();
            if (count > 0) data.remove_prefix(static_cast<size_t>(count));
            else WantRead(count);
        }
    }
    std::string ReadExact(size_t size) {
        std::string result;
        std::array<char, 16384> buffer{};
        while (result.size() < size) {
            const int count = SSL_read(ssl_.get(), buffer.data(), static_cast<int>(std::min(buffer.size(), size - result.size())));
            if (count > 0) result.append(buffer.data(), static_cast<size_t>(count));
            else WantRead(count);
        }
        return result;
    }
    void CloseNotify() {
        char byte;
        for (;;) {
            const int result = SSL_read(ssl_.get(), &byte, 1);
            if (result <= 0 && SSL_get_error(ssl_.get(), result) == SSL_ERROR_ZERO_RETURN) break;
            Require(result <= 0, "unexpected inner application data");
            WantRead(result);
        }
        EXPECT_EQ(BIO_ctrl_pending(incoming_), 0u);
        const int status = SSL_shutdown(ssl_.get());
        Require(status >= 0, "inner TLS shutdown failed");
        Flush();
    }
private:
    void Flush() {
        std::array<char, 16384> buffer{};
        while (BIO_ctrl_pending(outgoing_) > 0) {
            const int count = BIO_read(outgoing_, buffer.data(), static_cast<int>(buffer.size()));
            Require(count > 0, "TLS BIO read failed");
            socket_.Write(std::string_view(buffer.data(), static_cast<size_t>(count)));
        }
    }
    void WantRead(int result) {
        const int error = SSL_get_error(ssl_.get(), result);
        Require(error == SSL_ERROR_WANT_READ, "inner TLS protocol error " + std::to_string(error));
        Flush();
        if (header_) { Require(socket_.ReadExact(2) == std::string("\0\0", 2), "VLESS response missing"); header_ = false; }
        const auto data = socket_.Read();
        Require(!data.empty(), "EOF inside inner TLS");
        Require(BIO_write(incoming_, data.data(), static_cast<int>(data.size())) == static_cast<int>(data.size()), "TLS BIO write failed");
    }
    Socket& socket_;
    bool header_;
    TlsContext context_;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl_{nullptr, SSL_free};
    BIO* incoming_ = nullptr;
    BIO* outgoing_ = nullptr;
};

class VisionReference : public testing::TestWithParam<std::tuple<bool, int>> {};
TEST_P(VisionReference, BidirectionalPaddingDirectAndInnerTlsEof) {
    const auto [xray_client, mode] = GetParam();
    VerifyXray(CNODE_REFERENCE_XRAY);
    BinaryGuard binaries{Binary(), CNODE_REFERENCE_XRAY};
    TempDir root;
    const auto request = Pattern(251 * 1045);
    const std::string response(request.rbegin(), request.rend());
    TlsContext target_tls(true);
    const int version = mode == 1 ? TLS1_2_VERSION : TLS1_3_VERSION;
    SSL_CTX_set_min_proto_version(target_tls.Get(), version);
    SSL_CTX_set_max_proto_version(target_tls.Get(), version);
    TcpServer target([&](Socket socket, size_t) {
        auto exchange = [&](auto& stream) {
            EXPECT_EQ(stream.ReadExact(request.size()), request);
            size_t offset = 0;
            for (const size_t end : {size_t(1), size_t(899), size_t(900), size_t(8192), response.size()}) {
                stream.Write(std::string_view(response).substr(offset, end - offset)); offset = end;
                std::this_thread::sleep_for(5ms);
            }
            stream.ShutdownWrite();
        };
        if (mode) { TlsSocket tls(std::move(socket), target_tls, true); exchange(tls); }
        else exchange(socket);
    });
    const auto server_port = TcpPort(), front_port = TcpPort();
    Json xray;
    Json user{{"id", UserId}, {"encryption", "none"}, {"flow", "xtls-rprx-vision"}};
    if (xray_client) {
        auto inbound = VlessInbound(server_port);
        inbound["settings"]["clients"][0]["flow"] = "xtls-rprx-vision";
        inbound["streamSettings"] = TlsSettings(true);
        Configure(root.Path(), inbound, Freedom(), 4);
        auto outbound = XrayOutbound(server_port, user);
        outbound["streamSettings"] = {{"network", "tcp"}, {"security", "tls"}, {"tlsSettings", {
            {"serverName", "localhost"}, {"certificates", Json::array({{{"usage", "verify"},
            {"certificateFile", (SourceRoot() / "tests/fixtures/anytls-pool/cert.pem").string()}}})}}}};
        xray = {{"inbounds", Json::array({SocksInbound(front_port)})}, {"outbounds", Json::array({outbound})}};
    } else {
        Configure(root.Path(), VlessInbound(front_port), {{"protocol", "vless"}, {"settings", {
            {"address", "127.0.0.1"}, {"port", server_port}, {"id", UserId}, {"encryption", "none"},
            {"flow", "xtls-rprx-vision"}}}, {"streamSettings", TlsSettings(false)}}, 4);
        auto inbound = VlessInbound(server_port);
        inbound["settings"]["clients"][0]["flow"] = "xtls-rprx-vision";
        inbound["streamSettings"] = TlsSettings(true);
        xray = {{"inbounds", Json::array({inbound})}, {"outbounds", Json::array({Freedom(true)})}};
    }
    xray["log"]["loglevel"] = "debug";
    WriteJson(root.Path(), "xray.json", xray);
    Child reference({CNODE_REFERENCE_XRAY, "run", "-config", (root.Path() / "xray.json").string()}, root.Path() / "xray.log");
    reference.WaitForLog("started");
    Child cnode({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "cnode.log");
    for (int number = 0; number != 2; ++number) {
        auto socket = Connect(front_port);
        if (xray_client) Socks(socket, target.Port()); else socket.Write(VlessRequest(target.Port()));
        if (mode) {
            InnerTls tls(socket, version, !xray_client);
            tls.Write(request);
            EXPECT_EQ(tls.ReadExact(response.size()), response);
            tls.CloseNotify();
        } else {
            for (size_t offset = 0; offset < request.size(); offset += 8191) socket.Write(std::string_view(request).substr(offset, 8191));
            if (!xray_client) EXPECT_EQ(socket.ReadExact(2), std::string("\0\0", 2));
            EXPECT_EQ(socket.ReadExact(response.size()), response);
        }
        socket.ShutdownWrite();
        EXPECT_EQ(socket.Read(), "") << "outer TLS alert or trailing bytes leaked";
    }
    EXPECT_EQ(target.Count(), 2);
    EXPECT_TRUE(cnode.Running()); EXPECT_TRUE(reference.Running());
    target.Join(); binaries.Check();
}
INSTANTIATE_TEST_SUITE_P(BothDirections, VisionReference,
    testing::Combine(testing::Bool(), testing::Values(0, 1, 2)), ([](const auto& info) {
        return std::string(std::get<0>(info.param) ? "XrayClient" : "XrayServer") +
            std::array{"Plain", "Tls12", "Tls13"}[std::get<1>(info.param)];
    }));

std::pair<std::string, std::string> EncryptionKeys(std::string_view mode) {
    const auto keys = Command({CNODE_REFERENCE_XRAY, "vlessenc"});
    auto key = [&](std::string_view name) {
        std::smatch match;
        Require(std::regex_search(keys, match, std::regex("\"" + std::string(name) + R"key(": "([^"]+)")key")), "Xray key generator omitted key");
        auto value = match[1].str();
        const auto offset = value.find(".native.");
        Require(offset != std::string::npos, "unexpected VLESS encryption key mode");
        value.replace(offset, 8, "." + std::string(mode) + ".");
        return value;
    };
    return {key("decryption"), key("encryption")};
}

class EncryptionReference : public testing::TestWithParam<std::string> {};
TEST_P(EncryptionReference, CrossWorkerTicketsReplayAndHandshakeBoundaries) {
    VerifyXray(CNODE_REFERENCE_XRAY);
    BinaryGuard binaries{Binary(), CNODE_REFERENCE_XRAY};
    const auto started = std::chrono::steady_clock::now();
    TempDir root;
    const auto [decryption, encryption] = EncryptionKeys(GetParam());
    std::atomic<size_t> requests{0};
    TcpServer target([&](Socket socket, size_t) {
        EXPECT_EQ(socket.ReadExact(20), "vless-0rtt-real-xray");
        ++requests; socket.Write("accepted-once-per-nfs-key");
    });
    const auto server_port = TcpPort(), front_port = TcpPort();
    Bridge bridge(server_port);
    auto inbound = VlessInbound(server_port);
    inbound["proxyProtocol"] = "off";
    inbound["settings"]["decryption"] = decryption;
    Configure(root.Path(), inbound, Freedom(), 4); DebugConfig(root.Path());
    WriteJson(root.Path(), "xray.json", {{"log", {{"loglevel", "debug"}}},
        {"inbounds", Json::array({SocksInbound(front_port)})},
        {"outbounds", Json::array({XrayOutbound(bridge.Port(), {{"id", UserId}, {"encryption", encryption}})})}});
    Child cnode({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "cnode.log");
    Child reference({CNODE_REFERENCE_XRAY, "run", "-config", (root.Path() / "xray.json").string()}, root.Path() / "xray.log");
    for (size_t number = 0; number != 17; ++number) {
        auto socket = Connect(front_port); Socks(socket, target.Port()); socket.Write("vless-0rtt-real-xray");
        EXPECT_EQ(socket.ReadExact(25), "accepted-once-per-nfs-key");
        EXPECT_EQ(requests.load(), number + 1);
    }
    auto flights = bridge.Flights();
    ASSERT_EQ(flights.size(), 17);
    EXPECT_GE(flights[0].first_response, 1298u);
    for (size_t i = 1; i < flights.size(); ++i) {
        EXPECT_GE(flights[i].first_response, 98u); EXPECT_LT(flights[i].first_response, 1000u);
    }
    std::vector<std::pair<std::string, uint16_t>> boundary;
    for (const auto& kind : {"empty", "truncated", "rejected", "timeout"}) {
        auto socket = Connect(server_port);
        boundary.emplace_back(kind, socket.Port());
        if (std::string_view(kind) != "timeout") {
            if (std::string_view(kind) == "truncated") socket.Write(std::string(1, '\0'));
            if (std::string_view(kind) == "rejected") socket.Write(std::string(flights[0].sent.size(), '\0'));
            shutdown(socket.Fd(), SHUT_WR);
        }
        pollfd fd{socket.Fd(), POLLIN, 0};
        EXPECT_GT(poll(&fd, 1, 4000), 0) << kind;
        char buffer[4096];
        const auto count = recv(socket.Fd(), buffer, sizeof(buffer), MSG_DONTWAIT);
        EXPECT_LE(count, 0) << kind;
    }
    const auto replay = flights[1].sent;
    ASSERT_FALSE(replay.empty());
    for (int number = 0; number != 64; ++number) {
        auto socket = Connect(server_port); socket.Write(replay);
        pollfd fd{socket.Fd(), POLLIN, 0}; EXPECT_GT(poll(&fd, 1, 3000), 0);
        char buffer[4096]; EXPECT_LE(recv(socket.Fd(), buffer, sizeof(buffer), MSG_DONTWAIT), 0);
    }
    EXPECT_EQ(requests.load(), 17);
    EXPECT_TRUE(reference.Running()); EXPECT_TRUE(cnode.Running());
    reference.Stop(); cnode.Stop(); bridge.Join(); target.Join();
    const auto logs = Logs(root.Path());
    for (const auto& [kind, port] : boundary) {
        std::string peer_logs;
        const std::regex lines("[^\\n]*127\\.0\\.0\\.1:" + std::to_string(port) + "[^\\n]*");
        for (auto it = std::sregex_iterator(logs.begin(), logs.end(), lines); it != std::sregex_iterator(); ++it) peer_logs += it->str();
        if (kind == "empty") {
            EXPECT_EQ(peer_logs.find("encryption handshake"), std::string::npos);
            EXPECT_EQ(peer_logs.find("authentication failed"), std::string::npos);
        } else if (kind == "timeout") EXPECT_TRUE(peer_logs.find("timeout") != std::string::npos || peer_logs.find("timed out") != std::string::npos);
        else EXPECT_NE(peer_logs.find("encryption handshake " + kind), std::string::npos) << peer_logs;
    }
    const std::regex tickets("ticket lookup owner=(\\d+) receiver=(\\d+) accepted=(true|false)");
    size_t accepted = 0, rejected = 0, cross_accepts = 0, same_rejects = 0, cross_rejects = 0;
    std::set<std::string> receivers;
    for (auto it = std::sregex_iterator(logs.begin(), logs.end(), tickets); it != std::sregex_iterator(); ++it) {
        const bool same = (*it)[1].str() == (*it)[2].str();
        if ((*it)[3] == "true") { ++accepted; receivers.insert((*it)[2]); cross_accepts += !same; }
        else { ++rejected; same_rejects += same; cross_rejects += !same; }
    }
    EXPECT_EQ(accepted, 16); EXPECT_EQ(rejected, 64); EXPECT_GE(receivers.size(), 2u);
    EXPECT_GT(cross_accepts, 0); EXPECT_GT(same_rejects, 0); EXPECT_GT(cross_rejects, 0);
    EXPECT_LT(std::chrono::steady_clock::now() - started, 120s);
    binaries.Check();
}
TEST_P(EncryptionReference, CnodeOutboundResumesRealXrayTickets) {
    VerifyXray(CNODE_REFERENCE_XRAY);
    BinaryGuard binaries{Binary(), CNODE_REFERENCE_XRAY};
    TempDir root;
    const auto [decryption, encryption] = EncryptionKeys(GetParam());
    std::atomic<size_t> requests{0};
    TcpServer target([&](Socket socket, size_t) {
        EXPECT_EQ(socket.ReadExact(20), "vless-0rtt-real-xray");
        ++requests;
        socket.Write("accepted-once-per-nfs-key");
    });
    const auto server_port = TcpPort(), front_port = TcpPort();
    Bridge bridge(server_port);
    auto inbound = VlessInbound(server_port);
    inbound["settings"]["decryption"] = decryption;
    WriteJson(root.Path(), "xray.json", {{"log", {{"loglevel", "debug"}}},
        {"inbounds", Json::array({inbound})}, {"outbounds", Json::array({Freedom(true)})}});
    Configure(root.Path(), VlessInbound(front_port), {{"protocol", "vless"}, {"settings", {
        {"address", "127.0.0.1"}, {"port", bridge.Port()}, {"id", UserId}, {"encryption", encryption}}}});
    Child reference({CNODE_REFERENCE_XRAY, "run", "-config", (root.Path() / "xray.json").string()}, root.Path() / "xray.log");
    reference.WaitForLog("started");
    Child cnode({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "cnode.log");
    for (size_t number = 0; number != 17; ++number) {
        auto socket = Connect(front_port);
        socket.Write(VlessRequest(target.Port(), "vless-0rtt-real-xray"));
        EXPECT_EQ(socket.ReadExact(2), std::string("\0\0", 2));
        EXPECT_EQ(socket.ReadExact(25), "accepted-once-per-nfs-key");
        EXPECT_EQ(socket.Read(), "");
        EXPECT_EQ(requests.load(), number + 1);
    }
    const auto flights = bridge.Flights();
    ASSERT_EQ(flights.size(), 17);
    EXPECT_GE(flights[0].first_response, 1298u);
    for (size_t i = 1; i < flights.size(); ++i) {
        EXPECT_GE(flights[i].first_response, 98u);
        EXPECT_LT(flights[i].first_response, 1000u);
    }
    EXPECT_TRUE(cnode.Running()); EXPECT_TRUE(reference.Running());
    cnode.Stop(); reference.Stop(); bridge.Join(); target.Join(); binaries.Check();
}

INSTANTIATE_TEST_SUITE_P(AllModes, EncryptionReference, testing::Values("native", "xorpub", "random"));

TEST(XhttpReference, FourConcurrentStreamUpRequestsDrainUploadResponses) {
    VerifyXray(CNODE_REFERENCE_XRAY);
    BinaryGuard binaries{Binary(), CNODE_REFERENCE_XRAY};
    TempDir root;
    TcpServer target([](Socket socket, size_t) {
        socket.Write("ready");
        while (true) { const auto data = socket.Read(); if (data.empty()) break; socket.Write(data); }
    });
    const auto xray_port = TcpPort(), front_port = TcpPort();
    const Json stream{{"network", "xhttp"}, {"security", "none"},
        {"xhttpSettings", {{"path", "/interop"}, {"mode", "stream-up"}}}};
    auto inbound = VlessInbound(xray_port); inbound["streamSettings"] = stream;
    WriteJson(root.Path(), "xray.json", {{"log", {{"loglevel", "debug"}}},
        {"inbounds", Json::array({inbound})}, {"outbounds", Json::array({Freedom(true)})}});
    Child reference({CNODE_REFERENCE_XRAY, "run", "-config", (root.Path() / "xray.json").string()}, root.Path() / "xray.log");
    reference.WaitForLog("started");
    Bridge bridge(xray_port, true);
    auto outbound = XrayOutbound(bridge.Port(), {{"id", UserId}, {"encryption", "none"}});
    outbound["streamSettings"] = stream;
    Configure(root.Path(), VlessInbound(front_port), outbound);
    Child cnode({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "cnode.log");
    const auto started = std::chrono::steady_clock::now();
    std::vector<std::unique_ptr<PeerThread>> clients;
    for (int index = 0; index != 4; ++index) clients.push_back(std::make_unique<PeerThread>([&, index] {
        auto socket = Connect(front_port); const auto initial = "initial-" + std::to_string(index);
        socket.Write(VlessRequest(target.Port(), initial));
        EXPECT_EQ(socket.ReadExact(2), std::string("\0\0", 2));
        EXPECT_EQ(socket.ReadExact(5), "ready"); EXPECT_EQ(socket.ReadExact(initial.size()), initial);
        std::this_thread::sleep_for(200ms);
        for (int number = 0; number != 8; ++number) {
            const std::string payload(65536, static_cast<char>(index * 17 + number));
            socket.Write(payload); EXPECT_EQ(socket.ReadExact(payload.size()), payload);
        }
    }));
    for (auto& client : clients) client->Join();
    EXPECT_LT(std::chrono::steady_clock::now() - started, 25s);
    EXPECT_EQ(target.Count(), 4);
    const auto flights = bridge.Flights();
    size_t uploads = 0, downloads = 0;
    for (const auto& flight : flights) {
        if (flight.head.starts_with("POST ")) {
            ++uploads; auto lower = flight.head;
            std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            EXPECT_NE(lower.find("\r\nconnection: close\r\n"), std::string::npos);
            EXPECT_GT(flight.response_bytes, 0u);
        } else if (flight.head.starts_with("GET ")) ++downloads;
    }
    EXPECT_EQ(uploads, 4); EXPECT_EQ(downloads, 4);
    EXPECT_TRUE(reference.Running()); EXPECT_TRUE(cnode.Running());
    cnode.Stop(); reference.Stop(); bridge.Join(); target.Join(); binaries.Check();
}
} // namespace
} // namespace cnode::e2e::reference
