#pragma once
#include "support.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <csignal>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <system_error>
#include <tuple>
#include <utility>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>

namespace cnode::e2e::http2 {
inline constexpr std::string_view Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
inline const std::string Ready = "ready", Echo = "other-stream-alive", Request = "request!";
inline const std::string Response = std::string(2, '\0') + Ready;
using Clock = std::chrono::steady_clock;
inline void Require(bool value, std::string_view message) {
    if (!value) throw std::runtime_error(std::string(message));
}
inline std::string Varint(uint64_t value) {
    std::string out;
    while (value >= 128) { out += static_cast<char>((value & 127) | 128); value >>= 7; }
    out += static_cast<char>(value);
    return out;
}
inline std::string Grpc(std::string_view payload) {
    auto body = std::string(1, '\x0a') + Varint(payload.size()) + std::string(payload);
    return std::string(1, '\0') + BigEndian(body.size(), 4) + body;
}
inline std::string Frame(uint8_t type, uint8_t flags = 0, uint32_t stream = 0, std::string_view body = {}) {
    return BigEndian(body.size(), 3) + static_cast<char>(type) + static_cast<char>(flags) + BigEndian(stream, 4) + std::string(body);
}
inline std::string Field(std::string_view key, std::string_view value) {
    Require(key.size() < 127 && value.size() < 127, "fixture HPACK literal too long");
    return std::string(1, '\0') + static_cast<char>(key.size()) + std::string(key) + static_cast<char>(value.size()) + std::string(value);
}
inline std::string Headers(std::string_view network, bool tls, std::string path = {}, std::string_view method = "POST") {
    if (path.empty()) path = network == "grpc" ? "/fixture/Tun" : network == "xhttp" ? "/fixture/" : "/fixture";
    auto out = Field(":method", method) + Field(":scheme", tls ? "https" : "http") + Field(":authority", "localhost") + Field(":path", path);
    if (network == "grpc") out += Field("content-type", "application/grpc") + Field("te", "trailers");
    return out;
}
inline Json Protocol(std::string_view name = "vless", uint16_t port = 0) {
    Json settings;
    if (name == "vless" || name == "vmess") {
        if (port) settings = {{"address", "127.0.0.1"}, {"port", port}, {"id", UserId}};
        else settings = {{"clients", Json::array({{{"id", UserId}}})}};
    } else {
        settings = {{"password", "fixture-secret"}};
        if (port) { settings["address"] = "127.0.0.1"; settings["port"] = port; }
        if (name == "shadowsocks") settings["method"] = "aes-128-gcm";
    }
    return settings;
}
inline Json Transport(std::string_view network, bool tls, bool server, std::string_view mode = "stream-one") {
    Json value = tls ? TlsSettings(server) : Json{{"security", "none"}};
    value["network"] = network;
    if (network == "grpc") value["grpcSettings"] = {{"serviceName", "fixture"}};
    else if (network == "h2") value["httpSettings"] = {{"path", "/fixture"}, {"method", "POST"}};
    else if (network == "ws") value["wsSettings"] = {{"path", "/fixture"}};
    else value["xhttpSettings"] = {{"path", "/fixture"}, {"mode", mode}};
    return value;
}
inline Json Inbound(uint16_t port, std::string_view network, bool tls, std::string_view mode = "stream-one", std::string_view protocol = "vless") {
    return {{"protocol", protocol}, {"listen", "127.0.0.1"}, {"port", port}, {"settings", Protocol(protocol)}, {"streamSettings", Transport(network, tls, true, mode)}};
}
inline Json Freedom() { return {{"protocol", "freedom"}, {"settings", Json::object()}}; }
inline void PatchConfig(const std::filesystem::path& root, const std::function<void(Json&)>& patch) {
    auto value = Json::parse(ReadFile(root / "config.json"));
    patch(value);
    WriteJson(root, "config.json", value);
}
class Node {
    Socket reservation_ = Socket::Listen();
public:
    TempDir root;
    uint16_t port = reservation_.Port();
    std::unique_ptr<Child> child;
    void Setup(std::string_view network, bool tls, std::string_view mode = "stream-one", unsigned workers = 1) {
        Configure(root.Path(), Inbound(port, network, tls, mode), Freedom(), workers);
    }
    void Start() {
        PatchConfig(root.Path(), [](Json& config) {
            config["log"]["enable"] = true;
            if (!config["log"].contains("loglevel")) config["log"]["loglevel"] = "debug";
        });
        reservation_.Close();
        child = std::make_unique<Child>(std::vector<std::string>{Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
        child->WaitForLog("server started");
    }
};
inline Socket ConnectFrom(uint16_t port, std::string_view source) {
    if (source.empty()) return Socket::Connect(port);
    Socket socket(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    Require(socket.Fd() >= 0, "creating source-bound socket");
    sockaddr_in local{}; local.sin_family = AF_INET;
    Require(inet_pton(AF_INET, std::string(source).c_str(), &local.sin_addr) == 1, "invalid fixture source address");
    Require(bind(socket.Fd(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0, "binding fixture source address");
    sockaddr_in remote{}; remote.sin_family = AF_INET; remote.sin_port = htons(port); remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const int result = connect(socket.Fd(), reinterpret_cast<sockaddr*>(&remote), sizeof(remote));
    Require(result == 0 || errno == EINPROGRESS, "connecting source-bound socket");
    pollfd item{socket.Fd(), POLLOUT, 0};
    Require(poll(&item, 1, 5000) > 0, "source-bound connect timeout");
    int error = 0; socklen_t size = sizeof(error);
    Require(getsockopt(socket.Fd(), SOL_SOCKET, SO_ERROR, &error, &size) == 0 && !error, "source-bound connect failed");
    return socket;
}
class Wire {
    Socket plain_;
    std::unique_ptr<TlsContext> context_;
    std::unique_ptr<TlsSocket> tls_;
public:
    Wire(Socket socket, bool tls, bool server = false, bool h2 = true) {
        if (!tls) { plain_ = std::move(socket); return; }
        context_ = std::make_unique<TlsContext>(server);
        if (!server) {
            const std::string alpn = h2 ? std::string("\x02h2", 3) : std::string("\x08http/1.1", 9);
            Require(SSL_CTX_set_alpn_protos(context_->Get(), reinterpret_cast<const unsigned char*>(alpn.data()), static_cast<unsigned>(alpn.size())) == 0, "setting fixture ALPN");
        }
        tls_ = std::make_unique<TlsSocket>(std::move(socket), *context_, server);
    }
    Wire(uint16_t port, bool tls, std::string_view source = {}, bool h2 = true) : Wire(ConnectFrom(port, source), tls, false, h2) {}
    int Fd() const { return tls_ ? tls_->Fd() : plain_.Fd(); }
    bool Readable(Milliseconds timeout = 50ms) const {
        if (tls_ && SSL_pending(tls_->Get())) return true;
        pollfd item{Fd(), POLLIN, 0};
        int result;
        do { result = poll(&item, 1, static_cast<int>(timeout.count())); } while (result < 0 && errno == EINTR);
        Require(result >= 0, "polling fixture wire");
        return result > 0;
    }
    void Write(std::string_view bytes) { if (tls_) tls_->Write(bytes); else plain_.Write(bytes); }
    std::string Read(size_t count = 65536, Milliseconds timeout = 5s) { return tls_ ? tls_->Read(count, timeout) : plain_.Read(count, timeout); }
    std::string Exact(size_t count) { return tls_ ? tls_->ReadExact(count) : plain_.ReadExact(count); }
    void Close() { if (tls_) tls_->Close(); else plain_.Close(); }
    void Abort() { linger value{1, 0}; setsockopt(Fd(), SOL_SOCKET, SO_LINGER, &value, sizeof(value)); Close(); }
    std::string Line() {
        std::string value;
        while (!value.ends_with("\r\n")) { Require(value.size() < 65536, "oversize HTTP line"); value += Exact(1); }
        return value;
    }
    std::string HttpResponse(std::string_view status = "HTTP/1.1 200 ") {
        auto value = Line(); Require(value.starts_with(status), "unexpected HTTP response: " + value);
        for (;;) { auto line = Line(); value += line; if (line == "\r\n") return value; }
    }
};
struct ObservedFrame { uint8_t type, flags; uint32_t stream; std::string body; };
class Peer {
    std::map<uint32_t, std::string> pending_;
    int64_t initial_window_ = 65535;
public:
    Wire wire;
    bool raw, tls, closed = false, goaway = false;
    std::string network;
    std::vector<ObservedFrame> frames;
    std::map<uint32_t, std::string> messages;
    std::map<uint32_t, int64_t> stream_windows;
    int64_t connection_window = 65535;
    Peer(uint16_t port, bool secure, std::string transport = "grpc", std::string_view source = {})
        : wire(port, secure, source), raw(transport != "grpc"), tls(secure), network(std::move(transport)) { wire.Write(std::string(Preface) + Frame(4)); }
    Peer(Socket socket, bool secure, bool is_raw) : wire(std::move(socket), secure, true), raw(is_raw), tls(secure), network(is_raw ? "h2" : "grpc") {
        Require(wire.Exact(Preface.size()) == Preface, "bad HTTP2 client preface"); wire.Write(Frame(4));
    }
    bool Has(uint8_t type, uint32_t stream) const { return std::any_of(frames.begin(), frames.end(), [&](const auto& f) { return f.type == type && f.stream == stream; }); }
    bool Ended(uint32_t stream) const { return std::any_of(frames.begin(), frames.end(), [&](const auto& f) { return f.stream == stream && ((f.type == 0 || f.type == 1) && (f.flags & 1)); }); }
    bool Terminal(uint32_t stream) const { return Ended(stream) || Has(3, stream); }
    std::vector<std::string> Bodies(uint8_t type, uint32_t stream) const {
        std::vector<std::string> result;
        for (auto& f : frames) if (f.type == type && f.stream == stream) result.push_back(f.body);
        return result;
    }
    bool Pump(Milliseconds timeout = 50ms) {
        if (closed || !wire.Readable(timeout)) return false;
        auto header = wire.Read(9);
        if (header.empty()) { closed = true; return true; }
        if (header.size() < 9) header += wire.Exact(9 - header.size());
        const auto length = ReadBigEndian(std::string_view(header).substr(0, 3));
        const auto type = static_cast<uint8_t>(header[3]), flags = static_cast<uint8_t>(header[4]);
        const auto sid = static_cast<uint32_t>(ReadBigEndian(std::string_view(header).substr(5))) & 0x7fffffff;
        Require(length <= 16384 && type <= 9, "malformed HTTP2 frame");
        auto body = wire.Exact(length);
        frames.push_back({type, flags, sid, type == 0 ? std::string{} : body});
        if (type == 7) goaway = true;
        if (type == 8) {
            Require(body.size() == 4, "invalid WINDOW_UPDATE length");
            auto credit = ReadBigEndian(body) & 0x7fffffff; Require(credit > 0, "zero HTTP2 credit");
            if (!sid) connection_window += credit;
            else { stream_windows.try_emplace(sid, initial_window_); stream_windows[sid] += credit; }
        }
        if (type == 4 && !(flags & 1)) {
            Require(body.size() % 6 == 0, "invalid SETTINGS length");
            for (size_t i = 0; i < body.size(); i += 6) {
                if (ReadBigEndian(std::string_view(body).substr(i, 2)) == 4) {
                    auto value = static_cast<int64_t>(ReadBigEndian(std::string_view(body).substr(i + 2, 4)));
                    Require(value <= 0x7fffffff, "invalid initial stream window");
                    for (auto& [id, credit] : stream_windows) { (void)id; credit += value - initial_window_; }
                    initial_window_ = value;
                }
            }
            wire.Write(Frame(4, 1));
        }
        if (type == 0) {
            if (!body.empty()) wire.Write(Frame(8, 0, 0, BigEndian(body.size(), 4)) + Frame(8, 0, sid, BigEndian(body.size(), 4)));
            if (raw) messages[sid] += body;
            else {
                auto& bytes = pending_[sid]; bytes += body;
                while (bytes.size() >= 5) {
                    const auto count = ReadBigEndian(std::string_view(bytes).substr(1, 4));
                    Require(bytes[0] == 0 && count <= 4 * 1024 * 1024, "invalid gRPC response prefix");
                    if (bytes.size() < count + 5) break;
                    Require(count > 0 && bytes[5] == 10, "invalid Hunk response tag");
                    uint64_t size = 0; size_t pos = 6; unsigned shift = 0;
                    for (;;) { Require(pos < count + 5 && shift < 35, "invalid Hunk varint"); auto part = static_cast<uint8_t>(bytes[pos++]); size |= uint64_t(part & 127) << shift; if (!(part & 128)) break; shift += 7; }
                    Require(pos + size == count + 5, "invalid Hunk response size");
                    messages[sid].append(bytes, pos, size); bytes.erase(0, count + 5);
                }
            }
        }
        return true;
    }
    void Wait(const std::function<bool()>& predicate, Milliseconds timeout = 5s) {
        auto deadline = Clock::now() + timeout;
        while (!predicate()) { Require(!closed && Clock::now() < deadline, "HTTP2 observation deadline/physical EOF"); Pump(); }
    }
    void Message(uint32_t sid, const std::string& expected) { Wait([&] { return messages[sid].size() >= expected.size(); }); Require(messages[sid] == expected, "HTTP2 stream payload mismatch"); }
    int64_t Capacity(uint32_t sid) { auto [it, inserted] = stream_windows.try_emplace(sid, initial_window_); (void)inserted; return std::min(connection_window, it->second); }
    size_t TryData(uint32_t sid, std::string_view data, bool end = false) {
        Require(!closed && !goaway && !Has(3, sid), "DATA on terminated stream");
        const auto capacity = Capacity(sid);
        if (capacity <= 0 && !data.empty()) return 0;
        auto count = std::min({data.size(), size_t(16384), static_cast<size_t>(std::max<int64_t>(0, capacity))});
        wire.Write(Frame(0, end && count == data.size() ? 1 : 0, sid, data.substr(0, count)));
        connection_window -= count; stream_windows[sid] -= count;
        return count;
    }
    void Data(uint32_t sid, std::string_view data, bool end = false) {
        if (data.empty()) { TryData(sid, data, end); return; }
        auto deadline = Clock::now() + 15s;
        while (!data.empty()) { Require(Clock::now() < deadline, "HTTP2 send credit deadline"); auto sent = TryData(sid, data, end); data.remove_prefix(sent); if (!sent) Pump(); }
    }
    void Send(uint32_t sid, std::string_view data, bool end = false) { Data(sid, raw ? std::string(data) : Grpc(data), end); }
    void Open(uint32_t sid, uint16_t target, std::string_view tag, bool end = false) { wire.Write(Frame(1, 4, sid, Headers(network, tls))); Send(sid, VlessRequest(target, tag), end); }
    void Ping(std::string_view token) {
        Require(token.size() == 8, "PING token must have eight bytes"); wire.Write(Frame(6, 0, 0, token));
        Wait([&] { return std::any_of(frames.begin(), frames.end(), [&](auto& f) { return f.type == 6 && f.flags == 1 && f.body == token; }); });
    }
    void Reset(uint32_t sid) { wire.Write(Frame(3, 0, sid, BigEndian(8, 4))); }
    void Down(uint32_t sid, std::string_view session) {
        wire.Write(Frame(1, 5, sid, Headers("xhttp", tls, "/fixture/" + std::string(session), "GET")));
        Wait([&] { return Has(1, sid); });
    }
    void Packet(uint32_t sid, std::string_view session, unsigned sequence, std::string_view payload, bool end = true) {
        wire.Write(Frame(1, 4, sid, Headers("xhttp", tls, "/fixture/" + std::string(session) + "/" + std::to_string(sequence))));
        Data(sid, payload, end);
    }
    void Committed(uint32_t sid) { Wait([&] { return Terminal(sid); }); Require(Ended(sid) && !Has(3, sid), "XHTTP upload did not commit"); }
};

inline std::string ReadAll(Socket& socket, Milliseconds timeout = 5s) {
    auto deadline = Clock::now() + timeout; std::string result;
    for (;;) { Require(Clock::now() < deadline, "EOF deadline"); auto data = socket.Read(65536, std::chrono::duration_cast<Milliseconds>(deadline - Clock::now())); if (data.empty()) return result; result += data; }
}
inline std::string Pattern(size_t length) { std::string out(length, '\0'); for (size_t i = 0; i < length; ++i) out[i] = static_cast<char>(i % 251); return out; }
inline void H1Packet(uint16_t port, bool tls, std::string_view session, unsigned sequence, std::string_view payload, std::string_view source = {}) {
    Wire wire(port, tls, source, false);
    wire.Write("POST /fixture/" + std::string(session) + "/" + std::to_string(sequence) + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(payload.size()) + "\r\nConnection: close\r\n\r\n" + std::string(payload));
    wire.HttpResponse();
}
class Chunked {
    Wire& wire_;
    std::string pending_;
public:
    explicit Chunked(Wire& wire) : wire_(wire) {}
    std::string Exact(size_t count) {
        while (pending_.size() < count) { auto size = std::stoull(wire_.Line(), nullptr, 16); Require(size > 0 && size <= 16 * 1024 * 1024, "invalid/terminal XHTTP chunk"); pending_ += wire_.Exact(size); Require(wire_.Exact(2) == "\r\n", "bad chunk delimiter"); }
        auto out = pending_.substr(0, count); pending_.erase(0, count); return out;
    }
};
inline std::string Hex(size_t value) { constexpr char digits[] = "0123456789abcdef"; std::string out; do { out += digits[value & 15]; value >>= 4; } while (value); std::reverse(out.begin(), out.end()); return out; }
inline std::string Chunk(std::string_view bytes) { return Hex(bytes.size()) + "\r\n" + std::string(bytes) + "\r\n"; }
} // namespace cnode::e2e::http2
