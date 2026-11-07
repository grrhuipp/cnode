#pragma once

#include "support.hpp"

#include <openssl/evp.h>

#include <atomic>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>

namespace cnode::e2e::padding {
inline constexpr std::string_view Request = "request!";
inline constexpr std::string_view Banner = "accepted";
inline constexpr std::string_view Default =
    "stop=8\n0=30-30\n1=100-400\n"
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
    "3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
inline constexpr std::string_view Learned = "stop=8\n0=45-45\n1=256-256\n2=64-64\n";

inline std::string Digest(std::string_view bytes, const EVP_MD* algorithm, bool hex) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest, &size, algorithm, nullptr) != 1)
        throw std::runtime_error("fixture digest failed");
    if (!hex) return {reinterpret_cast<const char*>(digest), size};
    constexpr char digits[] = "0123456789abcdef";
    std::string result(size * 2, '\0');
    for (unsigned i = 0; i < size; ++i) {
        result[2 * i] = digits[digest[i] >> 4];
        result[2 * i + 1] = digits[digest[i] & 15];
    }
    return result;
}
inline std::string Settings(std::string_view policy, bool reference = false) {
    return "v=2\nclient=" + std::string(reference ? "anytls/0.0.13" : "cnode") +
           "\npadding-md5=" + Digest(policy, EVP_md5(), true);
}
inline std::map<std::string, std::string> Fields(std::string_view text) {
    std::map<std::string, std::string> result;
    while (!text.empty()) {
        const auto end = text.find('\n');
        const auto line = text.substr(0, end);
        const auto equal = line.find('=');
        if (equal == std::string_view::npos) throw std::runtime_error("invalid settings field");
        result.emplace(line.substr(0, equal), line.substr(equal + 1));
        if (end == std::string_view::npos) break;
        text.remove_prefix(end + 1);
    }
    return result;
}
inline uint16_t ReadAuth(TlsSocket& socket, std::string_view password) {
    const auto header = socket.ReadExact(34);
    EXPECT_EQ(header.substr(0, 32), Digest(password, EVP_sha256(), false));
    const auto size = static_cast<uint16_t>(ReadBigEndian(std::string_view(header).substr(32)));
    EXPECT_EQ(socket.ReadExact(size), std::string(size, '\0'));
    return size;
}
inline Json VlessInbound(uint16_t port) {
    return {{"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", port},
            {"settings", {{"clients", Json::array({{{"id", UserId}}})}}}};
}
inline Json AnyOutbound(uint16_t port, std::string_view password) {
    return {{"protocol", "anytls"},
            {"settings", {{"address", "127.0.0.1"}, {"port", port},
                          {"password", password}, {"minIdleSession", 1}}},
            {"streamSettings", TlsSettings(false)}};
}
inline Json AnyInbound(uint16_t port, const Json& policy) {
    return {{"protocol", "anytls"}, {"listen", "127.0.0.1"}, {"port", port},
            {"settings", {{"clients", Json::array({{{"password", "secret"}}})},
                          {"paddingScheme", policy}}},
            {"streamSettings", TlsSettings(true)}};
}
inline Json PolicySetting(std::string_view text, bool array) {
    if (!array) return std::string(text);
    Json lines = Json::array();
    for (;;) {
        const auto end = text.find('\n');
        lines.push_back(std::string(text.substr(0, end)));
        if (end == std::string_view::npos) break;
        text.remove_prefix(end + 1);
    }
    return lines;
}
inline Socket ConnectEventually(uint16_t port) {
    Socket result;
    Until([&] {
        try { result = Socket::Connect(port, "127.0.0.1", 100ms); return true; }
        catch (const std::exception&) { return false; }
    }, 8s);
    return result;
}
inline void Roundtrip(uint16_t port, bool reference = false) {
    auto application = ConnectEventually(port);
    if (reference) {
        application.Write(std::string("\5\1\0", 3));
        EXPECT_EQ(application.ReadExact(2), std::string("\5\0", 2));
        application.Write(std::string("\5\1\0", 3) + SocksAddress(443));
        const auto reply = application.ReadExact(4);
        EXPECT_EQ(reply.substr(0, 2), std::string("\5\0", 2));
        if (reply[3] != 1 && reply[3] != 4) throw std::runtime_error("unexpected SOCKS address");
        application.ReadExact(reply[3] == 1 ? 6 : 18);
        application.Write(Request);
    } else {
        application.Write(VlessRequest(443, Request));
        EXPECT_EQ(application.ReadExact(2), std::string(2, '\0'));
    }
    EXPECT_EQ(application.ReadExact(Banner.size()), Banner);
    EXPECT_TRUE(application.Read(1).empty()) << "application stream did not close after FIN";
}

struct Observation {
    uint16_t authentication = 0;
    std::string settings;
    std::vector<uint32_t> streams;
    std::vector<size_t> waste;
};
// This is a wire-observing AnyTLS peer, not a replacement for cnode: every
// application request crosses a real cnode VLESS -> AnyTLS outbound pipeline.
inline Observation Exchange(TlsSocket& socket, std::string_view password,
                            const std::vector<std::string>& updates) {
    Observation observed;
    observed.authentication = ReadAuth(socket, password);
    std::string request;
    bool replied = false;
    for (size_t frames = 0; frames < 256; ++frames) {
        const auto record = ReadAnyTls(socket);
        switch (record.command) {
        case 4:
            EXPECT_TRUE(observed.settings.empty());
            observed.settings = record.payload;
            socket.Write(AnyTlsFrame(10, 0, "v=2"));
            break;
        case 1:
            observed.streams.push_back(record.stream);
            socket.Write(AnyTlsFrame(7, record.stream));
            break;
        case 2:
            request += record.payload;
            if (request == SocksAddress(443) + std::string(Request)) {
                EXPECT_FALSE(replied);
                replied = true;
                std::string response;
                for (const auto& update : updates) response += AnyTlsFrame(6, 0, update);
                response += AnyTlsFrame(2, record.stream, Banner) + AnyTlsFrame(3, record.stream) + AnyTlsFrame(8, 0);
                socket.Write(response);
            }
            break;
        case 0:
            EXPECT_EQ(record.payload, std::string(record.payload.size(), '\0'));
            observed.waste.push_back(record.payload.size());
            break;
        case 9:
            EXPECT_TRUE(replied);
            EXPECT_EQ(request, SocksAddress(443) + std::string(Request));
            return observed;
        default:
            break;
        }
    }
    throw std::runtime_error("AnyTLS frame observation limit exceeded");
}
inline void ForceReconnect(TlsSocket& socket) {
    socket.Write(AnyTlsFrame(5, 0, "fixture requires a fresh physical session"));
    // Drain any in-flight stream-close/control frames, but require transport EOF.
    for (size_t reads = 0; reads < 64; ++reads) {
        if (socket.Read().empty()) return;
    }
    throw std::runtime_error("AnyTLS connection did not close after alert");
}
struct PhysicalCase {
    std::string policy;
    unsigned low = 0;
    unsigned high = 0; // Equal bounds represent a constant; otherwise high is exclusive.
    std::vector<std::string> updates;
    std::optional<std::vector<size_t>> waste;
};
inline std::vector<Observation> PhysicalSessions(const std::vector<PhysicalCase>& cases,
                                                std::string_view password, bool reference = false) {
    TempDir root;
    auto listener = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto front = reservation.Port();
    Configure(root.Path(), VlessInbound(front), AnyOutbound(listener.Port(), password));
    TlsContext tls(true);
    std::atomic<size_t> completed{0};
    std::vector<Observation> observations;
    PeerThread peer([&] {
        for (size_t i = 0; i < cases.size(); ++i) {
            SCOPED_TRACE("physical session " + std::to_string(i + 1));
            TlsSocket socket(listener.Accept(10s), tls, true);
            auto observed = Exchange(socket, password, cases[i].updates);
            EXPECT_EQ(observed.streams, std::vector<uint32_t>{1});
            if (reference) EXPECT_EQ(Fields(observed.settings), Fields(Settings(cases[i].policy, true)));
            else EXPECT_EQ(observed.settings, Settings(cases[i].policy));
            EXPECT_GE(observed.authentication, cases[i].low);
            if (cases[i].low == cases[i].high) EXPECT_EQ(observed.authentication, cases[i].high);
            else EXPECT_LT(observed.authentication, cases[i].high);
            if (cases[i].waste) EXPECT_EQ(observed.waste, *cases[i].waste);
            observations.push_back(std::move(observed));
            ForceReconnect(socket);
            completed.store(i + 1);
        }
    });
    reservation.Close();
    std::vector<std::string> command{Binary().string(), "--config-dir", root.Path().string()};
#ifdef CNODE_REFERENCE_ANYTLS_CLIENT
    if (reference) command = {CNODE_REFERENCE_ANYTLS_CLIENT, "-l", "127.0.0.1:" + std::to_string(front),
                             "-s", "127.0.0.1:" + std::to_string(listener.Port()),
                             "-p", std::string(password), "-m", "1"};
#else
    if (reference) throw std::runtime_error("reference client path was not configured");
#endif
    Child child(command, root.Path() / "child.log");
    if (!reference) child.WaitForLog("server started");
    for (size_t i = 0; i < cases.size(); ++i) {
        Roundtrip(front, reference);
        Until([&] { return completed.load() == i + 1; }, 10s);
    }
    peer.Join();
    EXPECT_TRUE(child.Running());
    return observations;
}

inline std::vector<std::string> ReceiveInbound(TlsSocket& socket, uint32_t sid) {
    std::string payload;
    std::vector<std::string> updates;
    bool fin = false;
    for (size_t frames = 0; frames < 128 && !fin; ++frames) {
        const auto record = ReadAnyTls(socket);
        if (record.command == 6) updates.push_back(record.payload);
        if (record.command == 2 && record.stream == sid) payload += record.payload;
        if (record.command == 3 && record.stream == sid) fin = true;
    }
    EXPECT_TRUE(fin);
    EXPECT_EQ(payload, Banner);
    return updates;
}
inline void DrainBarrier(TlsSocket& socket, std::vector<std::string>& updates) {
    socket.Write(AnyTlsFrame(8, 0));
    for (size_t frames = 0; frames < 128; ++frames) {
        const auto record = ReadAnyTls(socket);
        if (record.command == 6) updates.push_back(record.payload);
        if (record.command == 9) return;
    }
    throw std::runtime_error("AnyTLS barrier response missing");
}
} // namespace cnode::e2e::padding
