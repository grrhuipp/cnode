#pragma once
#include "support.hpp"

#include <openssl/sha.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <mutex>
#include <regex>
#include <set>
#include <fstream>
#include <stdexcept>

namespace cnode::e2e::reference {
inline void Require(bool ok, std::string_view why) {
    if (!ok) throw std::runtime_error(std::string(why));
}
inline uint16_t TcpPort() {
    static std::mutex mutex;
    static std::set<uint16_t> allocated;
    std::lock_guard lock(mutex);
    for (int attempt = 0; attempt != 100; ++attempt) {
        const auto port = Socket::Listen().Port();
        if (allocated.insert(port).second) return port;
    }
    throw std::runtime_error("unable to allocate a distinct ephemeral TCP port");
}
inline uint16_t UdpPort() { return Socket::BindUdp().Port(); }
inline std::string Address(uint16_t port) { return "127.0.0.1:" + std::to_string(port); }
inline std::string Digest(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    Require(bool(input), "cannot open reference binary");
    SHA256_CTX context{};
    SHA256_Init(&context);
    std::array<char, 65536> buffer{};
    while (input) {
        input.read(buffer.data(), buffer.size());
        SHA256_Update(&context, buffer.data(), static_cast<size_t>(input.gcount()));
    }
    Require(input.eof(), "reference binary read failed");
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256_Final(digest.data(), &context);
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
class BinaryGuard {
public:
    explicit BinaryGuard(std::initializer_list<std::filesystem::path> paths) {
        for (const auto& path : paths) hashes_.emplace_back(path, Digest(path));
    }
    void Check() const { for (const auto& [path, hash] : hashes_) EXPECT_EQ(Digest(path), hash) << path; }
private:
    std::vector<std::pair<std::filesystem::path, std::string>> hashes_;
};
inline std::string Command(std::vector<std::string> args) {
    TempDir dir;
    Child child(std::move(args), dir.Path() / "command.log");
    const int status = child.Wait(15s);
    const auto output = ReadFile(child.LogPath());
    Require(status == 0, "reference command failed: " + output);
    return output;
}
inline void VerifyAnyTls(std::string path, std::string_view kind) {
    const auto metadata = Command({CNODE_REFERENCE_GO, "version", "-m", path});
    Require(metadata.find("vcs.revision=fd6167acd6d73b9fa3e607659951847fbc9e6c50") != std::string::npos,
            "AnyTLS reference must be https://github.com/anytls/anytls-go commit fd6167acd6d73b9fa3e607659951847fbc9e6c50");
    Require(metadata.find("vcs.modified=false") != std::string::npos, "modified AnyTLS reference");
    Require(metadata.find("path\tanytls/cmd/" + std::string(kind)) != std::string::npos, "wrong AnyTLS reference executable");
}
inline void VerifyXray(const std::string& path) {
    const auto metadata = Command({CNODE_REFERENCE_GO, "version", "-m", path});
    const auto version = Command({path, "version"});
    Require(Digest(path) == "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1" ||
        (metadata.find("vcs.revision=a4a3dff5b20c2faae567b742c172c7b95e75c083") != std::string::npos &&
         metadata.find("vcs.modified=false") != std::string::npos), "Xray must be unmodified XTLS/Xray-core a4a3dff5b20c2faae567b742c172c7b95e75c083");
    Require(version.find("26.10.31") != std::string::npos && version.find("a4a3dff") != std::string::npos,
            "wrong Xray reference release (expected v26.10.31)");
}
inline Socket Connect(uint16_t port) {
    Socket socket;
    Until([&] { try { socket = Socket::Connect(port, "127.0.0.1", 200ms); return true; } catch (...) { return false; } }, 15s);
    return socket;
}
inline uint16_t Socks(Socket& socket, uint16_t port, uint8_t command = 1) {
    socket.Write(std::string("\5\1\0", 3));
    Require(socket.ReadExact(2) == std::string("\5\0", 2), "SOCKS authentication failed");
    socket.Write(std::string("\5", 1) + char(command) + char(0) + SocksAddress(port));
    const auto head = socket.ReadExact(4);
    Require(head.substr(0, 2) == std::string("\5\0", 2), "SOCKS request failed");
    switch (static_cast<unsigned char>(head[3])) {
        case 1: socket.ReadExact(4); break;
        case 4: socket.ReadExact(16); break;
        case 3: socket.ReadExact(static_cast<unsigned char>(socket.ReadExact(1)[0])); break;
        default: throw std::runtime_error("invalid SOCKS address type");
    }
    return static_cast<uint16_t>(ReadBigEndian(socket.ReadExact(2)));
}
inline Json VlessInbound(uint16_t port) {
    return {{"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", port},
        {"settings", {{"decryption", "none"}, {"clients", Json::array({{{"id", UserId}}})}}}};
}
inline Json Freedom(bool xray = false) {
    Json result = {{"protocol", "freedom"}, {"settings", Json::object()}};
    if (xray) result["settings"]["finalRules"] = Json::array({{{"action", "allow"}}});
    return result;
}
inline Json SocksInbound(uint16_t port) {
    return {{"listen", "127.0.0.1"}, {"port", port}, {"protocol", "socks"},
        {"settings", {{"auth", "noauth"}, {"udp", false}}}};
}
inline Json XrayOutbound(uint16_t port, const Json& user) {
    return {{"protocol", "vless"}, {"settings", {{"vnext", Json::array({
        {{"address", "127.0.0.1"}, {"port", port}, {"users", Json::array({user})}}})}}}};
}
inline void DebugConfig(const std::filesystem::path& root) {
    auto config = Json::parse(ReadFile(root / "config.json"));
    config["timeouts"]["handshake"] = 2;
    config["log"]["enable"] = true;
    config["log"]["loglevel"] = "debug";
    WriteJson(root, "config.json", config);
}
inline std::string Logs(const std::filesystem::path& root) {
    std::string logs;
    for (const auto& file : std::filesystem::recursive_directory_iterator(root))
        if (file.is_regular_file() && file.path().extension() == ".log") logs += ReadFile(file.path());
    return logs;
}

// Only the target endpoint is a fixture. All proxy protocols pass through real executables.
class TcpServer {
public:
    using Handler = std::function<void(Socket, size_t)>;
    explicit TcpServer(Handler handler) : listener_(Socket::Listen()), thread_([this, handler = std::move(handler)] {
        std::vector<std::unique_ptr<PeerThread>> peers;
        try {
            while (!stop_) {
                pollfd fd{listener_.Fd(), POLLIN, 0};
                const int ready = poll(&fd, 1, 50);
                if (ready < 0 && errno == EINTR) continue;
                Require(ready >= 0, "listener poll failed");
                if (!ready) continue;
                auto socket = std::make_shared<Socket>(listener_.Accept());
                const size_t number = accepted_++;
                peers.push_back(std::make_unique<PeerThread>([socket, handler, number] { handler(std::move(*socket), number); }));
            }
        } catch (...) { error_ = std::current_exception(); }
        for (auto& peer : peers) {
            try { peer->Join(); } catch (...) { if (!error_) error_ = std::current_exception(); }
        }
    }) {}
    ~TcpServer() { stop_ = true; if (thread_.joinable()) thread_.join(); }
    uint16_t Port() const { return listener_.Port(); }
    size_t Count() const { return accepted_; }
    void Join() { stop_ = true; if (thread_.joinable()) thread_.join(); if (error_) std::rethrow_exception(error_); }
private:
    Socket listener_;
    std::atomic<bool> stop_{false};
    std::atomic<size_t> accepted_{0};
    std::exception_ptr error_;
    std::thread thread_;
};
struct Flight { std::string sent; size_t first_response = 0; bool responded = false; std::string head; size_t response_bytes = 0; };
class Bridge {
public:
    explicit Bridge(uint16_t target, bool http = false) : server_([this, target, http](Socket client, size_t) {
        auto remote = Connect(target);
        auto record = std::make_shared<Flight>();
        if (http) {
            while (!record->head.ends_with("\r\n\r\n")) {
                record->head += client.ReadExact(1);
                Require(record->head.size() < 65536, "oversized HTTP header");
            }
            remote.Write(record->head);
        }
        { std::lock_guard lock(mutex_); flights_.push_back(record); }
        bool upload = true, download = true;
        const auto deadline = std::chrono::steady_clock::now() + 600s;
        while ((upload || download) && !stop_) {
            Require(std::chrono::steady_clock::now() < deadline, "bridge deadline exceeded");
            pollfd fds[] = {{upload ? client.Fd() : -1, POLLIN, 0}, {download ? remote.Fd() : -1, POLLIN, 0}};
            const int ready = poll(fds, 2, 50);
            if (ready < 0 && errno == EINTR) continue;
            Require(ready >= 0, "bridge poll failed");
            for (int i = 0; i != 2; ++i) {
                if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                auto& source = i == 0 ? client : remote;
                auto& destination = i == 0 ? remote : client;
                std::array<char, 65536> buffer{};
                const auto count = recv(source.Fd(), buffer.data(), buffer.size(), 0);
                if (count <= 0) {
                    if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
                    if (i == 0) upload = false; else download = false;
                    shutdown(destination.Fd(), SHUT_WR);
                    continue;
                }
                {
                    std::lock_guard lock(mutex_);
                    if (i == 0) record->sent.append(buffer.data(), static_cast<size_t>(count));
                    else { if (!record->responded) { record->first_response = record->sent.size(); record->responded = true; }
                        record->response_bytes += static_cast<size_t>(count); }
                }
                auto bytes = std::string_view(buffer.data(), static_cast<size_t>(count));
                const auto write_deadline = std::chrono::steady_clock::now() + 5s;
                while (!bytes.empty() && !stop_) {
                    Require(std::chrono::steady_clock::now() < write_deadline, "bridge write deadline exceeded");
                    const auto written = send(destination.Fd(), bytes.data(), bytes.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
                    if (written > 0) { bytes.remove_prefix(static_cast<size_t>(written)); continue; }
                    if (written < 0 && (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN)) {
                        upload = download = false;
                        break;
                    }
                    Require(written < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK), "bridge write failed");
                    pollfd writable{destination.Fd(), POLLOUT, 0};
                    poll(&writable, 1, 50);
                }
            }
        }
    }) {}
    ~Bridge() { stop_ = true; }
    uint16_t Port() const { return server_.Port(); }
    size_t Count() const { return server_.Count(); }
    std::vector<Flight> Flights() const {
        std::lock_guard lock(mutex_); std::vector<Flight> result;
        for (const auto& flight : flights_) result.push_back(*flight);
        return result;
    }
    void Join() { stop_ = true; server_.Join(); }
private:
    std::atomic<bool> stop_{false};
    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<Flight>> flights_;
    TcpServer server_;
};
inline std::string Pattern(size_t size) {
    std::string bytes(size, '\0');
    for (size_t i = 0; i < size; ++i) bytes[i] = static_cast<char>(i % 251);
    return bytes;
}
} // namespace cnode::e2e::reference
