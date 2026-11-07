#pragma once
#include "support.hpp"

#include <openssl/err.h>
#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <system_error>

namespace cnode::e2e::tls {
inline void Require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
inline Json Inbound(uint16_t port, Json stream = Json::object()) {
    return {{"tag", "in"}, {"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", port},
            {"outboundTag", "direct"}, {"settings", {{"clients", {{{"id", UserId}}}}}},
            {"sniffing", {{"enabled", false}}}, {"streamSettings", std::move(stream)}};
}
inline Json AnyInbound(uint16_t port) {
    auto in = Inbound(port, TlsSettings(true));
    in["protocol"] = "anytls";
    in["settings"] = {{"clients", {{{"password", "secret"}}}}};
    return in;
}
inline void Config(const std::filesystem::path& root, Json inbounds, Json outbounds,
                   Json config = Json::object()) {
    config["workers"] = 1;
    if (!config.contains("timeouts"))
        config["timeouts"] = {{"handshake", 5}, {"connIdle", 40}, {"write", 30},
                              {"uplinkOnly", 2}, {"downlinkOnly", 2}};
    if (!config.contains("log")) config["log"] = {{"level", "debug"}};
    config["log"]["logDir"] = root.string();
    WriteJson(root, "config.json", config);
    WriteJson(root, "inbounds.json", inbounds);
    WriteJson(root, "outbounds.json", outbounds);
    WriteJson(root, "routing.json", {{"rules", Json::array()}});
}
inline Json Direct() { return {{"tag", "direct"}, {"protocol", "freedom"}}; }
inline std::unique_ptr<Child> Start(const std::filesystem::path& root) {
    auto child = std::make_unique<Child>(std::vector<std::string>{Binary().string(), "--config-dir", root.string()}, root / "child.log");
    child->WaitForLog("server started");
    Require(child->Running(), "cnode exited at startup");
    return child;
}
inline std::string Auth() {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash{};
    SHA256(reinterpret_cast<const unsigned char*>("secret"), 6, hash.data());
    return std::string(reinterpret_cast<const char*>(hash.data()), hash.size()) + std::string(2, '\0') + AnyTlsFrame(4, 0, "v=2");
}
inline std::string TrojanRequest(std::string_view payload) {
    std::array<unsigned char, SHA224_DIGEST_LENGTH> hash{};
    SHA224(reinterpret_cast<const unsigned char*>("secret"), 6, hash.data());
    std::string hex;
    for (auto c : hash) { hex += "0123456789abcdef"[c >> 4]; hex += "0123456789abcdef"[c & 15]; }
    return hex + "\r\n\1" + SocksAddress(443) + "\r\n" + std::string(payload);
}

// Memory BIOs keep TLS record boundaries under test control while all plaintext
// still traverses cnode's real TLS/dispatcher/relay path.
class WireTls {
public:
    WireTls(Socket socket, TlsContext& context, bool server = false,
            std::string_view name = "localhost") : socket_(std::move(socket)), ssl_(SSL_new(context.Get()), SSL_free) {
        Require(ssl_ != nullptr, "SSL_new");
        std::unique_ptr<BIO, decltype(&BIO_free)> incoming(BIO_new(BIO_s_mem()), BIO_free);
        std::unique_ptr<BIO, decltype(&BIO_free)> outgoing(BIO_new(BIO_s_mem()), BIO_free);
        Require(incoming && outgoing, "BIO_new");
        incoming_ = incoming.get();
        outgoing_ = outgoing.get();
        SSL_set_bio(ssl_.get(), incoming.release(), outgoing.release());
        if (server) SSL_set_accept_state(ssl_.get());
        else {
            SSL_set_connect_state(ssl_.get());
            Require(SSL_set_tlsext_host_name(ssl_.get(), std::string(name).c_str()) == 1, "TLS SNI");
            if (SSL_CTX_get_verify_mode(context.Get()) != SSL_VERIFY_NONE)
                Require(X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl_.get()), name.data(), name.size()) == 1, "TLS hostname");
        }
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        for (;;) {
            ERR_clear_error();
            int result = SSL_do_handshake(ssl_.get());
            if (result == 1) break;
            Require(SSL_get_error(ssl_.get(), result) == SSL_ERROR_WANT_READ, "TLS handshake failed");
            Require(Feed(Remaining(deadline)), "truncated TLS handshake");
        }
        Flush();
    }
    SSL* Get() const { return ssl_.get(); }
    Socket& Raw() { return socket_; }
    std::string Encrypt(std::string_view plain) {
        size_t offset = 0;
        while (offset < plain.size()) {
            ERR_clear_error();
            int n = SSL_write(ssl_.get(), plain.data() + offset, static_cast<int>(plain.size() - offset));
            Require(n > 0, "SSL_write");
            offset += static_cast<size_t>(n);
        }
        return Drain();
    }
    void Write(std::string_view plain) { socket_.Write(Encrypt(plain)); }
    std::string Read(size_t maximum = 65536, Milliseconds timeout = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        std::string data(maximum, '\0');
        for (;;) {
            ERR_clear_error();
            int n = SSL_read(ssl_.get(), data.data(), static_cast<int>(data.size()));
            if (n > 0) { data.resize(n); return data; }
            int error = SSL_get_error(ssl_.get(), n);
            if (error == SSL_ERROR_ZERO_RETURN) { close_notify = true; return {}; }
            if (error == SSL_ERROR_SYSCALL && n == 0) return {};
            Require(error == SSL_ERROR_WANT_READ, "TLS read failed");
            if (!Feed(Remaining(deadline))) return {};
        }
    }
    std::string ReadExact(size_t count, Milliseconds timeout = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        std::string result;
        while (result.size() < count) {
            auto bytes = Read(count - result.size(), Remaining(deadline));
            Require(!bytes.empty(), "truncated TLS plaintext");
            result += bytes;
        }
        return result;
    }
    void ShutdownWrite() {
        ERR_clear_error();
        const int result = SSL_shutdown(ssl_.get());
        if (result < 0)
            Require(SSL_get_error(ssl_.get(), result) == SSL_ERROR_WANT_READ, "TLS shutdown failed");
        Flush();
    }
    bool close_notify = false;
private:
    static Milliseconds Remaining(std::chrono::steady_clock::time_point deadline) {
        auto left = std::chrono::duration_cast<Milliseconds>(deadline - std::chrono::steady_clock::now());
        Require(left.count() > 0, "TLS operation deadline");
        return left;
    }
    std::string Drain() {
        std::string result(BIO_ctrl_pending(outgoing_), '\0');
        if (!result.empty()) Require(BIO_read(outgoing_, result.data(), static_cast<int>(result.size())) == static_cast<int>(result.size()), "BIO drain");
        return result;
    }
    void Flush() { auto wire = Drain(); if (!wire.empty()) socket_.Write(wire); }
    bool Feed(Milliseconds timeout) {
        Flush();
        auto data = socket_.Read(65536, timeout);
        if (data.empty()) { BIO_set_mem_eof_return(incoming_, 0); return false; }
        Require(BIO_write(incoming_, data.data(), static_cast<int>(data.size())) == static_cast<int>(data.size()), "BIO feed");
        return true;
    }
    Socket socket_;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl_;
    BIO* incoming_ = nullptr;
    BIO* outgoing_ = nullptr;
};

template<class Stream> std::string ReadUntil(Stream& stream, std::string_view delimiter, size_t limit = 16384) {
    std::string result;
    while (!result.ends_with(delimiter)) {
        Require(result.size() < limit, "header limit");
        result += stream.ReadExact(1);
    }
    return result;
}
template<class Stream> AnyTlsRecord Frame(Stream& stream, Milliseconds timeout = 5s) {
    auto h = stream.ReadExact(7, timeout);
    return {static_cast<uint8_t>(h[0]), static_cast<uint32_t>(ReadBigEndian(std::string_view(h).substr(1, 4))),
            stream.ReadExact(ReadBigEndian(std::string_view(h).substr(5, 2)), timeout)};
}
template<class Stream> std::vector<AnyTlsRecord> Barrier(Stream& stream) {
    stream.Write(AnyTlsFrame(8, 0));
    std::vector<AnyTlsRecord> records;
    do { records.push_back(Frame(stream)); } while (records.back().command != 9);
    return records;
}

// One connection per instance: preserve the ClientHello transcript, split it
// across TLS records, and split every record header across TCP writes.
class FragmentingProxy {
public:
    explicit FragmentingProxy(uint16_t target) : listener_(Socket::Listen()), thread_([this, target] {
        auto client = listener_.Accept();
        auto remote = Socket::Connect(target);
        auto header = client.ReadExact(5);
        Require(static_cast<uint8_t>(header[0]) == 22, "not a handshake record");
        auto body = client.ReadExact(ReadBigEndian(std::string_view(header).substr(3)));
        Require(!body.empty() && body[0] == 1, "not ClientHello");
        size_t offset = 0;
        for (size_t limit : std::array<size_t, 7>{1, 2, 3, 17, 127, 511, body.size()}) {
            auto part = body.substr(offset, limit);
            if (part.empty()) break;
            auto wire = header.substr(0, 3) + BigEndian(part.size(), 2) + part;
            for (size_t i = 0; i < 5; ++i) { remote.Write(std::string_view(wire).substr(i, 1)); std::this_thread::sleep_for(2ms); }
            remote.Write(std::string_view(wire).substr(5));
            offset += part.size();
        }
        Require(offset == body.size(), "incomplete fragmented ClientHello");
        fragmented = true;
        const auto deadline = std::chrono::steady_clock::now() + 15s;
        while (!stop_.load() && std::chrono::steady_clock::now() < deadline) {
            pollfd fds[2]{{client.Fd(), POLLIN, 0}, {remote.Fd(), POLLIN, 0}};
            int ready = poll(fds, 2, 50);
            if (ready < 0 && errno == EINTR) continue;
            Require(ready >= 0, "proxy poll");
            for (unsigned i = 0; i < 2; ++i) if (fds[i].revents & (POLLIN | POLLHUP)) {
                try {
                    auto bytes = (i == 0 ? client : remote).Read();
                    if (bytes.empty()) return;
                    (i == 0 ? remote : client).Write(bytes);
                } catch (const std::system_error& error) {
                    if (error.code().value() == ECONNRESET || error.code().value() == EPIPE) return;
                    throw;
                }
            }
        }
    }) {}
    ~FragmentingProxy() { stop_ = true; }
    uint16_t Port() const { return listener_.Port(); }
    void Join() { stop_ = true; thread_.Join(); }
    std::atomic<bool> fragmented{false};
private:
    Socket listener_;
    std::atomic<bool> stop_{false};
    PeerThread thread_;
};
} // namespace cnode::e2e::tls
