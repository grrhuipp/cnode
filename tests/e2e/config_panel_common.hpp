#pragma once

#include "support.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <sys/file.h>
#include <sys/socket.h>
#include <system_error>
#include <unistd.h>

namespace cnode::e2e::config_panel {
inline constexpr std::string_view UserA = "11111111-1111-4111-8111-111111111111";
inline constexpr std::string_view UserB = "22222222-2222-4222-8222-222222222222";
inline constexpr std::string_view Payload = "panel-user-sync-regression";
inline Json Inbound(uint16_t port, std::string_view protocol = "vless", std::string_view user = UserId) {
    return {{"protocol", protocol}, {"listen", "127.0.0.1"}, {"port", port},
            {"settings", {{"clients", Json::array({{{"id", user}, {"email", "handshake@example.test"}}})}}}};
}
inline Json Direct() { return {{"protocol", "freedom"}, {"settings", Json::object()}}; }
struct RuntimePortReservation {
    std::string address;
    Socket tcp_guard;
    Socket udp_guard;
    Socket tcp;
    Socket udp;
};

inline RuntimePortReservation ReserveRuntimePort() {
    // 默认地址守卫阻止通配绑定及默认地址抢占；独占端口同时确定隔离的回环别名。
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        auto tcp_guard = Socket::Listen();
        const auto port = tcp_guard.Port();
        auto address = "127.1." + std::to_string(port >> 8) + "." +
            std::to_string(port & 0xff);
        try {
            auto udp_guard = Socket::BindUdp(port);
            auto tcp = Socket::Listen(port, address);
            auto udp = Socket::BindUdp(port, address);
            return {std::move(address), std::move(tcp_guard), std::move(udp_guard),
                std::move(tcp), std::move(udp)};
        } catch (const std::system_error& error) {
            if (error.code() != std::errc::address_in_use) throw;
        }
    }
    throw std::runtime_error("no available TCP/UDP runtime fixture port");
}
inline Json MixedKeys(const Json& value) {
    if (value.is_array()) {
        Json result = Json::array();
        for (const auto& item : value) result.push_back(MixedKeys(item));
        return result;
    }
    if (!value.is_object()) return value;
    Json result = Json::object();
    for (auto it = value.begin(); it != value.end(); ++it) {
        std::string key = it.key();
        for (size_t i = 0; i < key.size(); ++i)
            key[i] = static_cast<char>(i % 2 ? std::tolower(static_cast<unsigned char>(key[i])) :
                                             std::toupper(static_cast<unsigned char>(key[i])));
        result[key] = MixedKeys(it.value());
    }
    return result;
}
inline std::unique_ptr<Child> Start(const std::filesystem::path& root, std::string_view log = "child.log") {
    return std::make_unique<Child>(std::vector<std::string>{Binary().string(), "--config-dir", root.string()}, root / log, root);
}
inline bool Listening(uint16_t port, std::string_view address = "127.0.0.1") {
    try { auto socket = Socket::Connect(port, address, 200ms); return true; }
    catch (const std::system_error& error) {
        if (error.code() == std::errc::connection_refused) return false;
        throw;
    }
}
inline bool Echo(uint16_t port, uint16_t target, std::string_view user = UserA,
                 std::string_view host = "127.0.0.1",
                 std::string_view inbound_address = "127.0.0.1") {
    auto socket = Socket::Connect(port, inbound_address, 500ms);
    socket.Write(VlessRequest(target, Payload, 1, host, user), 1s);
    const auto expected = std::string("\0\0", 2) + std::string(Payload);
    std::string received(expected.size(), '\0');
    size_t offset = 0;
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (offset < received.size()) {
        const auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::steady_clock::duration::zero()) return false;
        pollfd descriptor{socket.Fd(), POLLIN, 0};
        const int ready = ::poll(&descriptor, 1,
            static_cast<int>(std::chrono::ceil<Milliseconds>(remaining).count()));
        if (ready == 0) return false;
        if (ready < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "echo response poll");
        }
        const auto count = ::recv(socket.Fd(), received.data() + offset, received.size() - offset, MSG_DONTWAIT);
        if (count == 0) return false;
        if (count < 0) {
            if (errno == ECONNRESET) return false;
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            throw std::system_error(errno, std::generic_category(), "echo response recv");
        }
        offset += static_cast<size_t>(count);
    }
    if (received != expected) throw std::runtime_error("corrupt VLESS echo response");
    return true;
}
inline bool ReadClosed(Socket& socket, Milliseconds timeout = 3s) {
    pollfd descriptor{socket.Fd(), POLLIN, 0};
    const auto result = ::poll(&descriptor, 1, static_cast<int>(timeout.count()));
    if (result <= 0) return false;
    char byte;
    const auto count = ::recv(socket.Fd(), &byte, 1, 0);
    return count == 0 || (count < 0 && errno == ECONNRESET);
}
inline std::string Logs(const std::filesystem::path& root) {
    std::string result;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root))
        if (entry.is_regular_file() && entry.path().extension() == ".log") result += ReadFile(entry.path());
    return result;
}

// The product's explicit/implicit --test listener is intentionally fixed at
// 10086. Serialize only scenarios exercising that public CLI contract.
class TestPortLock {
public:
    TestPortLock() {
        fd_ = ::open("/tmp/cnode-e2e-test-port.lock", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (fd_ < 0) throw std::runtime_error("opening test listener lock");
        try { Until([&] { return ::flock(fd_, LOCK_EX | LOCK_NB) == 0; }, 180s); }
        catch (...) { ::close(fd_); throw; }
    }
    ~TestPortLock() { ::flock(fd_, LOCK_UN); ::close(fd_); }
private:
    int fd_;
};

// Accept and handler lifetimes are bounded and every exception is rethrown on
// explicit Join. The listener remains owned until all handlers have completed.
class LoopServer {
public:
    using Handler = std::function<void(Socket)>;
    explicit LoopServer(Handler handler, std::string_view address = "127.0.0.1")
        : listener_(Socket::Listen(0, address)), accept_([this, handler = std::move(handler)] {
            while (!stop_.load()) {
                pollfd descriptor{listener_.Fd(), POLLIN, 0};
                const int ready = ::poll(&descriptor, 1, 50);
                if (ready < 0 && errno != EINTR) throw std::runtime_error("fixture accept poll failed");
                if (ready <= 0) continue;
                auto connection = std::make_shared<Socket>(listener_.Accept(1s));
                handlers_.push_back(std::make_unique<PeerThread>([handler, connection] { handler(std::move(*connection)); }));
            }
        }) {}
    ~LoopServer() {
        try { Join(); }
        catch (const std::exception& error) { ADD_FAILURE() << "fixture cleanup: " << error.what(); }
    }
    uint16_t Port() const { return listener_.Port(); }
    void Join() {
        if (joined_) return;
        stop_ = true;
        std::exception_ptr first;
        try { accept_.Join(); } catch (...) { first = std::current_exception(); }
        for (auto& thread : handlers_) {
            try { thread->Join(); } catch (...) { if (!first) first = std::current_exception(); }
        }
        joined_ = true;
        if (first) std::rethrow_exception(first);
    }
private:
    Socket listener_;
    std::atomic<bool> stop_{false};
    std::vector<std::unique_ptr<PeerThread>> handlers_;
    PeerThread accept_;
    bool joined_ = false;
};
inline void EchoPeer(Socket socket) {
    const auto payload = socket.ReadExact(Payload.size(), 3s);
    EXPECT_EQ(payload, Payload);
    socket.Write(payload);
}
struct HttpRequest {
    std::string method, path, body;
    std::map<std::string, std::string> headers;
};
inline HttpRequest ReadHttp(Socket& socket) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    const auto remaining = [&] {
        const auto duration = deadline - std::chrono::steady_clock::now();
        if (duration <= std::chrono::steady_clock::duration::zero())
            throw std::runtime_error("fixture HTTP request deadline exceeded");
        return std::chrono::ceil<Milliseconds>(duration);
    };
    std::string wire;
    while (!wire.ends_with("\r\n\r\n")) {
        if (wire.size() >= 65536) throw std::runtime_error("oversized fixture HTTP header");
        wire += socket.ReadExact(1, remaining());
    }
    HttpRequest request;
    std::istringstream stream(wire);
    std::string version, line;
    stream >> request.method >> request.path >> version;
    std::getline(stream, line);
    while (std::getline(stream, line) && line != "\r") {
        const auto split = line.find(':');
        if (split == std::string::npos) throw std::runtime_error("malformed fixture HTTP header");
        auto key = line.substr(0, split);
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return std::tolower(c); });
        auto value = line.substr(split + 1);
        while (!value.empty() && value.front() == ' ') value.erase(value.begin());
        if (!value.empty() && value.back() == '\r') value.pop_back();
        request.headers[key] = value;
    }
    if (request.headers.contains("content-length")) {
        const auto size = std::stoul(request.headers.at("content-length"));
        if (size > 1024 * 1024) throw std::runtime_error("oversized fixture HTTP body");
        request.body = socket.ReadExact(size, remaining());
    }
    return request;
}
inline void Reply(Socket& socket, int status, std::string_view body, std::string_view etag = {}) {
    std::string response = "HTTP/1.1 " + std::to_string(status) + " Fixture\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nConnection: close\r\n";
    if (!etag.empty()) response += "ETag: \"" + std::string(etag) + "\"\r\n";
    response += "\r\n";
    response += body;
    socket.Write(response, 3s);
}
inline void PanelConfig(const std::filesystem::path& root, uint16_t port, std::string_view name,
                        bool mixed = false) {
    Json config = {{"workers", 2}, {"log", {{"enable", false}, {"loglevel", "WARNING"}, {"logDir", (root / "logs").string()}}},
        {"panels", Json::array({{{"name", name}, {"type", "V2Board"},
            {"apiHost", "http://127.0.0.1:" + std::to_string(port)}, {"key", "fixture-secret-must-not-persist"},
            {"nodeIDs", {1}}, {"nodeType", "VLESS"}, {"listenIP", "127.0.0.1"},
            {"sendIP", "AUTO"}, {"dnsType", "useipv4"}, {"requestTimeout", 1}}})}};
    WriteJson(root, "config.json", mixed ? MixedKeys(config) : config);
}
} // namespace cnode::e2e::config_panel
