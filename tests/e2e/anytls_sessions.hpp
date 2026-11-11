#pragma once
#include "support.hpp"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <fcntl.h>
#include <system_error>
#include <tuple>
#include <unistd.h>
#include <mutex>
#include <map>
#include <poll.h>
#include <sys/socket.h>
#include <stdexcept>

namespace cnode::e2e::sessions {
// AnyTLS 帧命令字（协议 v2）。
enum FrameCommand : uint8_t {
    kWaste = 0,
    kSyn = 1,
    kPush = 2,
    kFin = 3,
    kSettings = 4,
    kAlert = 5,
    kUpdatePaddingScheme = 6,
    kSynAck = 7,
    kHeartRequest = 8,
    kHeartResponse = 9,
    kServerSettings = 10,
};
inline bool Ready(int fd, Milliseconds timeout) {
    pollfd p{fd, POLLIN, 0};
    int result;
    do {
        result = ::poll(&p, 1, static_cast<int>(timeout.count()));
    } while (result < 0 && errno == EINTR);
    Require(result >= 0, "poll failed");
    return result != 0;
}
inline std::string Drain(Socket& socket, Milliseconds timeout = 5s, bool allowReset = false) {
    std::string out;
    const auto end = std::chrono::steady_clock::now() + timeout;
    try {
        for (;;) {
            const auto left = std::chrono::duration_cast<Milliseconds>(end - std::chrono::steady_clock::now());
            Require(left > 0ms, "EOF deadline expired");
            auto bytes = socket.Read(65536, left);
            if (bytes.empty()) return out;
            out += bytes;
        }
    } catch (const std::system_error& error) {
        if (allowReset && error.code().value() == ECONNRESET) return out;
        throw;
    }
}
inline bool Next(TlsSocket& socket, AnyTlsRecord& frame, Milliseconds timeout = 5s) {
    std::string header;
    try {
        header = socket.Read(7, timeout);
    } catch (const std::runtime_error& error) {
        if (errno == ECONNRESET && std::string_view(error.what()).starts_with("SSL_read (SSL error 5)")) return false;
        throw;
    }
    if (header.empty()) return false;
    if (header.size() < 7) header += socket.ReadExact(7 - header.size(), timeout);
    frame = {static_cast<uint8_t>(header[0]),
             static_cast<uint32_t>(ReadBigEndian(std::string_view(header).substr(1, 4))),
             socket.ReadExact(ReadBigEndian(std::string_view(header).substr(5, 2)), timeout)};
    return true;
}
struct Frames {
    explicit Frames(TlsSocket& value) : socket(value) {}
    TlsSocket& socket;
    std::vector<AnyTlsRecord> records;
    bool closed = false;
    size_t Count(uint8_t command, uint32_t sid = UINT32_MAX) const {
        return std::count_if(records.begin(), records.end(), [&](const auto& f) {
            return f.command == command && (sid == UINT32_MAX || sid == f.stream);
        });
    }
    std::string Payload(uint32_t sid) const {
        std::string out;
        for (const auto& f : records)
            if (f.command == 2 && f.stream == sid) out += f.payload;
        return out;
    }
    void One(Milliseconds timeout = 5s) {
        AnyTlsRecord frame;
        if (Next(socket, frame, timeout)) records.push_back(std::move(frame));
        else closed = true;
    }
    void Await(const std::function<bool()>& condition, Milliseconds timeout = 5s) {
        const auto end = std::chrono::steady_clock::now() + timeout;
        while (!condition()) {
            Require(!closed, "session closed before observation");
            const auto left = std::chrono::duration_cast<Milliseconds>(end - std::chrono::steady_clock::now());
            Require(left > 0ms, "frame observation expired");
            One(left);
        }
    }
    void Barrier() {
        auto count = Count(9);
        socket.Write(AnyTlsFrame(8, 0));
        Await([&] { return Count(9) > count; });
    }
};
// Listener and handlers own every socket and are stopped before their shared state.
class Server {
public:
    using Handler = std::function<void(Socket)>;
    explicit Server(Handler handler, std::string_view address = "127.0.0.1")
        : listener_(Socket::Listen(0, address))
        , handler_(std::move(handler))
        , accept_([this] {
            while (!stop_) {
                if (!Ready(listener_.Fd(), 50ms)) continue;
                auto socket = listener_.Accept();
                const int fd = ::fcntl(socket.Fd(), F_DUPFD_CLOEXEC, 0);
                Require(fd >= 0, "duplicate peer shutdown handle");
                {
                    std::lock_guard lock(mutex_);
                    fds_.push_back(fd);
                }
                threads_.push_back(
                    std::make_unique<PeerThread>([this, fd, socket = std::make_shared<Socket>(std::move(socket))] {
                        try {
                            handler_(std::move(*socket));
                        } catch (...) {
                            if (!stop_) {
                                std::lock_guard lock(mutex_);
                                if (!error_) error_ = std::current_exception();
                            }
                        }
                        std::lock_guard lock(mutex_);
                        std::erase(fds_, fd);
                        ::close(fd);
                    }));
            }
        }) {}
    ~Server() {
        try {
            Stop();
        } catch (const std::exception& error) {
            ADD_FAILURE() << "Peer cleanup: " << error.what();
        }
    }
    uint16_t Port() const { return listener_.Port(); }
    bool Stopping() const { return stop_; }
    void Stop() {
        if (joined_) return;
        stop_ = true;
        accept_.Join();
        {
            std::lock_guard lock(mutex_);
            for (int fd : fds_) ::shutdown(fd, SHUT_RDWR);
        }
        for (auto& thread : threads_) thread->Join();
        joined_ = true;
        if (error_) std::rethrow_exception(error_);
    }
private:
    Socket listener_;
    Handler handler_;
    std::atomic<bool> stop_ = false;
    std::mutex mutex_;
    std::vector<int> fds_;
    std::vector<std::unique_ptr<PeerThread>> threads_;
    std::exception_ptr error_;
    bool joined_ = false;
    PeerThread accept_;
};
struct Echo {
    struct Record {
        std::string bytes;
        bool closed = false;
    };
    std::mutex mutex;
    std::vector<Record> records;
    Server server;
    explicit Echo(std::string_view address = "127.0.0.1", bool echo = true)
        : server(
              [this, echo](Socket socket) {
                  size_t index;
                  {
                      std::lock_guard lock(mutex);
                      index = records.size();
                      records.emplace_back();
                  }
                  try {
                      for (;;) {
                          auto bytes = socket.Read();
                          if (bytes.empty()) break;
                          {
                              std::lock_guard lock(mutex);
                              records[index].bytes += bytes;
                          }
                          if (echo) socket.Write(bytes);
                      }
                  } catch (const std::system_error& error) {
                      if (error.code().value() != ECONNRESET) throw;
                  }
                  std::lock_guard lock(mutex);
                  records[index].closed = true;
              },
              address) {}
    size_t Count() {
        std::lock_guard lock(mutex);
        return records.size();
    }
    Record Get(size_t index) {
        std::lock_guard lock(mutex);
        return records.at(index);
    }
};
inline Json Inbound(uint16_t port, bool anytls = true) {
    Json in = {{"protocol", anytls ? "anytls" : "vless"}, {"listen", "127.0.0.1"}, {"port", port}};
    in["settings"]["clients"] = Json::array({anytls ? Json{{"password", "secret"}} : Json{{"id", UserId}}});
    if (anytls) in["streamSettings"] = TlsSettings(true);
    return in;
}
inline Json Outbound(uint16_t port, unsigned minimum = 1, unsigned idle = 30) {
    return {{"protocol", "anytls"},
            {"settings",
             {{"address", "127.0.0.1"},
              {"port", port},
              {"password", "secret"},
              {"minIdleSession", minimum},
              {"idleSessionTimeout", idle},
              {"idleSessionCheckInterval", 1}}},
            {"streamSettings", TlsSettings(false)}};
}
// The node port stays reserved for the cnode child's lifetime; a reference peer,
// which binds without SO_REUSEADDR, gets it released at startup.
struct Node {
    TempDir directory;
    Socket port_reservation = Socket::ReserveTcp();
    uint16_t port = port_reservation.Port();
    std::unique_ptr<Child> child;
    Node(bool inbound, uint16_t peer = 0, Json timeouts = Json::object(), unsigned minimum = 1, unsigned idle = 30) {
        Configure(directory.Path(), Inbound(port, inbound),
                  inbound ? Json{{"protocol", "freedom"}, {"settings", Json::object()}}
                          : Outbound(peer, minimum, idle));
        if (!timeouts.empty()) {
            auto config = Json::parse(ReadFile(directory.Path() / "config.json"));
            config["timeouts"].update(timeouts);
            WriteJson(directory.Path(), "config.json", config);
        }
        Start();
    }
    Node() = default;
    void Start(std::vector<std::string> command = {}) {
        const bool native = command.empty();
        if (native) command = {Binary().string(), "--config-dir", directory.Path().string()};
        if (!native) port_reservation.Close();
        child =
            std::make_unique<Child>(std::move(command), directory.Path() / (native ? "child.log" : "reference.log"));
        if (native) child->WaitForLog("server started");
    }
    void Stop() {
        if (child) EXPECT_EQ(child->Stop(), 0);
    }
    Socket Application(std::string_view payload = "request!", uint8_t command = 1) {
        auto socket = Socket::Connect(port);
        socket.Write(VlessRequest(443, payload, command));
        return socket;
    }
};
inline void Authenticate(TlsSocket& socket, std::string_view settings = "v=2", std::string_view password = "secret") {
    AnyTlsAuthenticate(socket, password);
    socket.Write(AnyTlsFrame(4, 0, settings));
}
inline void Open(TlsSocket& socket, uint32_t sid, uint16_t port, std::string_view payload,
                 std::string_view host = "127.0.0.1") {
    socket.Write(AnyTlsFrame(1, sid) + AnyTlsFrame(2, sid, SocksAddress(port, host) + std::string(payload)));
}
inline std::string Magic(bool v1) {
    return SocksAddress(0, v1 ? "sp.udp-over-tcp.arpa" : "sp.v2.udp-over-tcp.arpa");
}
// Panel provisioning remains real: the rate-limited user travels through the HTTP panel adapter and user store.
struct PanelNode {
    TempDir directory;
    Socket port_reservation = Socket::ReserveTcp();
    uint16_t port = port_reservation.Port();
    std::atomic<unsigned> userRequests = 0;
    Server panel;
    std::unique_ptr<Child> child;
    explicit PanelNode(bool anytls = true, Json timeouts = Json::object())
        : panel([this](Socket socket) { ServePanel(socket); }) {
        auto cert = SourceRoot() / "tests/fixtures/anytls-pool";
        Json config = {{"workers", 1},
                       {"log", {{"logDir", (directory.Path() / "logs").string()}}},
                       {"timeouts", {{"connIdle", 10}, {"uplinkOnly", 3}, {"downlinkOnly", 3}}},
                       {"panels",
                        Json::array({{{"name", "session-test"},
                                      {"type", "V2board"},
                                      {"apiHost", "http://127.0.0.1:" + std::to_string(panel.Port())},
                                      {"key", "local-test-key"},
                                      {"nodeIDs", Json::array({1})},
                                      {"nodeType", anytls ? "anytls" : "vless"},
                                      {"listenIP", "127.0.0.1"},
                                      {"tlsEnable", anytls},
                                      {"tlsCert", (cert / "cert.pem").string()},
                                      {"tlsKey", (cert / "key.pem").string()}}})}};
        config["timeouts"].update(timeouts);
        WriteJson(directory.Path(), "config.json", config);
        child = std::make_unique<Child>(
            std::vector<std::string>{Binary().string(), "--config-dir", directory.Path().string()},
            directory.Path() / "child.log");
        Until(
            [&] {
                Require(child->Running(), "panel node exited");
                return userRequests.load() != 0;
            },
            8s);
    }
    Socket Connect() {
        Socket socket;
        Until(
            [&] {
                try {
                    socket = Socket::Connect(port, "127.0.0.1", 100ms);
                    return true;
                } catch (...) {
                    Require(child->Running(), "panel node exited");
                    return false;
                }
            },
            5s);
        return socket;
    }
    void Stop() {
        EXPECT_EQ(child->Stop(), 0);
        panel.Stop();
    }
private:
    // 最小 V2board 面板：/config 返回节点端口，/user 返回一个限速用户；其余请求回空对象。
    void ServePanel(Socket& socket) {
        for (;;) {
            std::string header;
            while (!header.ends_with("\r\n\r\n")) {
                auto byte = socket.Read(1);
                if (byte.empty()) return;
                header += byte;
                Require(header.size() < 65536, "panel header too large");
            }
            auto lower = header;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            auto at = lower.find("content-length:");
            if (at != std::string::npos) socket.ReadExact(std::stoul(lower.substr(at + 15)));
            Json value = Json::object();
            if (header.starts_with("GET ") && header.find("/config?") != std::string::npos)
                value = {{"server_port", port},
                         {"network", "tcp"},
                         {"tls", 0},
                         {"base_config", {{"pull_interval", 60}, {"push_interval", 60}}}};
            else if (header.starts_with("GET ") && header.find("/user?") != std::string::npos) {
                ++userRequests;
                value = {{"users", Json::array({{{"id", 1}, {"uuid", UserId}, {"speed_limit", 1}}})}};
            }
            auto body = value.dump();
            socket.Write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                         std::to_string(body.size()) + "\r\nConnection: keep-alive\r\n\r\n" + body);
        }
    }
};
inline Socket ConnectChild(Child& child, uint16_t port) {
    Socket socket;
    Until(
        [&] {
            try {
                socket = Socket::Connect(port, "127.0.0.1", 100ms);
                return true;
            } catch (...) {
                Require(child.Running(), "child exited before accepting");
                return false;
            }
        },
        8s);
    return socket;
}
inline void ServerFin(bool remote, std::string reference = {}) {
    std::atomic<unsigned> requests = 0;
    std::atomic<bool> release = false, targetEof = false;
    std::string late;
    Server target([&](Socket socket) {
        EXPECT_EQ(socket.ReadExact(8), "request!");
        auto count = ++requests;
        if (count > 1) {
            socket.Write("recovery");
            return;
        }
        socket.Write("accepted");
        Until([&] { return release.load(); });
        if (!remote) {
            socket.Write("forbidden-after-fin");
            socket.ShutdownWrite();
        }
        late = Drain(socket);
        targetEof = true;
    });
    Node node;
    if (reference.empty()) {
        Configure(node.directory.Path(), Inbound(node.port), {{"protocol", "freedom"}, {"settings", Json::object()}});
        node.Start();
    } else node.Start({reference, "-l", "127.0.0.1:" + std::to_string(node.port), "-p", "secret"});
    TlsContext context(false);
    TlsSocket client(ConnectChild(*node.child, node.port), context, false);
    Frames frames(client);
    Authenticate(client);
    Open(client, 1, target.Port(), "request!");
    frames.Await([&] { return frames.Payload(1) == "accepted"; });
    if (remote) {
        client.Write(AnyTlsFrame(3, 1));
        frames.Barrier();
        client.Write(AnyTlsFrame(2, 1, "forbidden-after-fin"));
        frames.Barrier();
        release = true;
    } else {
        release = true;
        frames.Await([&] { return frames.Count(3, 1) > 0; });
        client.Write(AnyTlsFrame(2, 1, "forbidden-after-fin"));
        frames.Barrier();
    }
    Until([&] { return targetEof.load(); });
    EXPECT_EQ(late, "");
    EXPECT_EQ(frames.Payload(1), remote ? "accepted" : "acceptedforbidden-after-fin");
    EXPECT_EQ(frames.Count(3, 1), remote ? 0u : 1u);
    Open(client, 3, target.Port(), "request!");
    frames.Await([&] { return frames.Count(3, 3) == 1; });
    EXPECT_EQ(frames.Payload(3), "recovery");
    EXPECT_FALSE(frames.closed);
    EXPECT_EQ(requests.load(), 2u);
    client.Close();
    EXPECT_TRUE(node.child->Running());
    if (reference.empty()) node.Stop();
    else node.child->Stop();
    target.Stop();
}
// ClientFin 的上游 AnyTLS 对端：首个流回 accepted 后，remote 时由对端发完整载荷再 FIN，
// 否则等 cnode 先 FIN 再回违规数据；之后的流回 recovery 并立即 FIN。
class ClientFinPeer {
public:
    ClientFinPeer(bool remote, std::string_view expected) : remote_(remote), expected_(expected) {}
    void Serve(Socket socket) {
        ++connections;
        TlsSocket tls(std::move(socket), context_, true);
        ReadAnyTlsAuthentication(tls, "secret");
        tls.Write(AnyTlsFrame(kServerSettings, 0, "v=2"));
        Session session{tls};
        AnyTlsRecord frame;
        while (Next(tls, frame)) OnFrame(session, frame);
    }
    std::atomic<unsigned> connections = 0, requests = 0, fins = 0, hearts = 0;
    std::atomic<size_t> late = 0;

private:
    struct Session {
        TlsSocket& tls;
        std::map<uint32_t, std::string> bytes;
        uint32_t first = 0;
    };
    void OnFrame(Session& session, const AnyTlsRecord& frame) {
        switch (frame.command) {
        case kSyn:
            if (!session.first) session.first = frame.stream;
            session.tls.Write(AnyTlsFrame(kSynAck, frame.stream));
            break;
        case kPush: OnPush(session, frame); break;
        case kFin:
            if (frame.stream == session.first) OnFirstFin(session, frame.stream);
            break;
        case kHeartRequest: session.tls.Write(AnyTlsFrame(kHeartResponse, 0)); break;
        case kHeartResponse: ++hearts; break;
        default: break;
        }
    }
    void OnPush(Session& session, const AnyTlsRecord& frame) {
        auto& data = session.bytes[frame.stream];
        const auto before = data.size();
        data += frame.payload;
        if (before < 15 && data.size() >= 15) {
            EXPECT_EQ(data.substr(0, 15), SocksAddress(443) + "request!");
            Answer(session.tls, frame.stream, ++requests);
        }
        if (frame.stream == session.first && data.size() > 15) late = data.size() - 15;
    }
    void Answer(TlsSocket& tls, uint32_t stream, unsigned request) {
        tls.Write(AnyTlsFrame(kPush, stream, request == 1 ? "accepted" : "recovery"));
        if (request > 1) tls.Write(AnyTlsFrame(kFin, stream));
        else if (remote_) {
            for (size_t i = 0; i < expected_.size(); i += 16384)
                tls.Write(AnyTlsFrame(kPush, stream, expected_.substr(i, 16384)));
            tls.Write(AnyTlsFrame(kFin, stream) + AnyTlsFrame(kHeartRequest, 0));
        }
    }
    void OnFirstFin(Session& session, uint32_t stream) {
        ++fins;
        if (!remote_)
            session.tls.Write(AnyTlsFrame(kPush, stream, "forbidden-after-fin") + AnyTlsFrame(kHeartRequest, 0));
    }
    const bool remote_;
    const std::string_view expected_;
    TlsContext context_{true};
};
inline void ClientFin(bool remote, std::string reference = {}) {
    const auto expected = remote ? Pattern(256 * 1024) : std::string{};
    ClientFinPeer fin_peer(remote, expected);
    Server peer([&](Socket socket) { fin_peer.Serve(std::move(socket)); });
    Node node;
    if (reference.empty()) {
        Configure(node.directory.Path(), Inbound(node.port, false), Outbound(peer.Port()));
        node.Start();
    } else
        node.Start({reference, "-l", "127.0.0.1:" + std::to_string(node.port), "-s",
                    "127.0.0.1:" + std::to_string(peer.Port()), "-p", "secret", "-m", "1"});
    auto application = [&] {
        auto app = ConnectChild(*node.child, node.port);
        if (reference.empty()) {
            app.Write(VlessRequest(443, "request!"));
            EXPECT_EQ(app.ReadExact(2), std::string("\0\0", 2));
        } else {
            app.Write(std::string("\5\1\0", 3));
            EXPECT_EQ(app.ReadExact(2), std::string("\5\0", 2));
            app.Write(std::string("\5\1\0", 3) + SocksAddress(443));
            auto reply = app.ReadExact(4);
            EXPECT_EQ(reply.substr(0, 2), std::string("\5\0", 2));
            Require(reply[3] == 1 || reply[3] == 4, "SOCKS address type");
            app.ReadExact(reply[3] == 1 ? 6 : 18);
            app.Write("request!");
        }
        return app;
    };
    auto app = application();
    EXPECT_EQ(app.ReadExact(8), "accepted");
    if (!remote) app.ShutdownWrite();
    EXPECT_EQ(Drain(app, 2s), expected);
    Until([&] { return fin_peer.hearts.load() > 0; });
    if (remote) {
        try {
            app.Write("forbidden-after-fin");
        } catch (const std::exception&) {}
    }
    app.Close();
    auto recovery = application();
    EXPECT_EQ(Drain(recovery), "recovery");
    EXPECT_EQ(fin_peer.connections.load(), 1u);
    EXPECT_EQ(fin_peer.late.load(), 0u);
    EXPECT_EQ(fin_peer.fins.load(), remote ? 0u : 1u);
    EXPECT_TRUE(node.child->Running());
    if (reference.empty()) node.Stop();
    else node.child->Stop();
    peer.Stop();
}
} // namespace cnode::e2e::sessions
