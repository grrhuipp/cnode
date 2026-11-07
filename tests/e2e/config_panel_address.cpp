#include "config_panel_common.hpp"

#include <array>
#include <tuple>

namespace cnode::e2e::config_panel {
namespace {
constexpr std::string_view Request = "request!";
constexpr std::string_view Banner = "accepted";
std::string DomainRequest(uint16_t port, std::string_view host) {
    return std::string(1, '\0') + UuidBytes() + std::string("\0\1", 2) + BigEndian(port, 2) +
        std::string(1, '\2') + std::string(1, static_cast<char>(host.size())) + std::string(host) + std::string(Request);
}
class Resolver {
public:
    Resolver(bool reject, std::string_view address)
        : socket_(Socket::BindUdp(0, address)), thread_([this, reject] {
            while (!stop_.load()) {
                pollfd descriptor{socket_.Fd(), POLLIN, 0};
                const int ready = ::poll(&descriptor, 1, 50);
                if (ready < 0 && errno != EINTR) throw std::runtime_error("DNS fixture poll failed");
                if (ready <= 0) continue;
                std::array<char, 4096> buffer{};
                sockaddr_storage sender{};
                socklen_t sender_size = sizeof(sender);
                const auto count = ::recvfrom(socket_.Fd(), buffer.data(), buffer.size(), 0,
                    reinterpret_cast<sockaddr*>(&sender), &sender_size);
                if (count < 17) throw std::runtime_error("short DNS request");
                std::string_view wire(buffer.data(), static_cast<size_t>(count));
                size_t offset = 12;
                std::string name;
                while (offset < wire.size() && wire[offset]) {
                    const auto size = static_cast<unsigned char>(wire[offset++]);
                    if (offset + size >= wire.size()) throw std::runtime_error("bad DNS labels");
                    if (!name.empty()) name += '.';
                    name += wire.substr(offset, size);
                    offset += size;
                }
                if (offset + 5 > wire.size()) throw std::runtime_error("short DNS question");
                ++offset;
                const auto kind = ReadBigEndian(wire.substr(offset, 2));
                EXPECT_EQ(ReadBigEndian(wire.substr(offset + 2, 2)), 1u);
                EXPECT_TRUE(kind == 1 || kind == 28);
                { std::lock_guard lock(mutex_); names_.push_back(name); }
                std::string answer;
                if (!reject && kind == 1)
                    answer = std::string("\xc0\x0c", 2) + BigEndian(1, 2) + BigEndian(1, 2) +
                        BigEndian(30, 4) + BigEndian(4, 2) + std::string("\x7f\0\0\1", 4);
                const auto response = std::string(wire.substr(0, 2)) + BigEndian(reject ? 0x8182 : 0x8180, 2) +
                    BigEndian(1, 2) + BigEndian(answer.empty() ? 0 : 1, 2) + std::string(4, '\0') +
                    std::string(wire.substr(12, offset + 4 - 12)) + answer;
                if (::sendto(socket_.Fd(), response.data(), response.size(), 0,
                    reinterpret_cast<sockaddr*>(&sender), sender_size) != static_cast<ssize_t>(response.size()))
                    throw std::runtime_error("DNS fixture reply failed");
            }
        }) {}
    ~Resolver() {
        try { Join(); }
        catch (const std::exception& error) { ADD_FAILURE() << "DNS fixture cleanup: " << error.what(); }
    }
    uint16_t Port() const { return socket_.Port(); }
    std::vector<std::string> Names() { std::lock_guard lock(mutex_); return names_; }
    void Join() { if (!joined_) { stop_ = true; thread_.Join(); joined_ = true; } }
private:
    Socket socket_;
    std::atomic<bool> stop_{false};
    std::mutex mutex_;
    std::vector<std::string> names_;
    PeerThread thread_;
    bool joined_ = false;
};
class DnsEndpoints : public testing::TestWithParam<std::string> {};
TEST_P(DnsEndpoints, NormalizesEndpointFallsBackAndSharesCacheAcrossWorkers) {
    const auto mode = GetParam();
    TempDir directory;
    std::vector<std::unique_ptr<Resolver>> resolvers;
    const std::string host = mode == "ipv6" ? "::1" : "127.0.0.1";
    if (mode == "fallback-same-address") resolvers.push_back(std::make_unique<Resolver>(true, host));
    resolvers.push_back(std::make_unique<Resolver>(false, host));
    Json servers = Json::array();
    for (const auto& resolver : resolvers)
        servers.push_back((host == "::1" ? "[::1]" : host) + ":" + std::to_string(resolver->Port()));
    auto backend = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto port = reservation.Port();
    Configure(directory.Path(), Inbound(port), Direct(), 2);
    auto config = Json::parse(ReadFile(directory.Path() / "config.json"));
    config["dns"] = {{"servers", servers}, {"timeout", 1}, {"minTTL", 1}, {"maxTTL", 30}};
    WriteJson(directory.Path(), "config.json", config);
    PeerThread peer([&] {
        for (int i = 0; i < 2; ++i) {
            auto socket = backend.Accept();
            EXPECT_EQ(socket.ReadExact(Request.size()), Request);
            socket.Write(Banner);
        }
    });
    reservation.Close();
    auto child = Start(directory.Path());
    child->WaitForLog("server started");
    const auto domain = mode + ".endpoint.test";
    std::array<size_t, 2> query_counts{};
    for (size_t i = 0; i < query_counts.size(); ++i) {
        auto socket = Socket::Connect(port);
        socket.Write(DomainRequest(backend.Port(), domain));
        EXPECT_EQ(socket.ReadExact(Banner.size() + 2), std::string("\0\0", 2) + std::string(Banner));
        for (auto& resolver : resolvers) query_counts[i] += resolver->Names().size();
    }
    peer.Join();
    EXPECT_EQ(query_counts[0], query_counts[1]);
    EXPECT_TRUE(child->Running());
    EXPECT_EQ(child->Stop(), 0);
    for (auto& resolver : resolvers) {
        resolver->Join();
        const auto names = resolver->Names();
        EXPECT_FALSE(names.empty());
        for (const auto& name : names) EXPECT_EQ(name, domain);
    }
}
INSTANTIATE_TEST_SUITE_P(AddressFamilies, DnsEndpoints, testing::Values("ipv4", "ipv6", "fallback-same-address"));

using LiteralCase = std::tuple<std::string, std::string, bool>;
class IpLiterals : public testing::TestWithParam<LiteralCase> {};
TEST_P(IpLiterals, ConsumesWholeAddressWithoutEndpointOrCStringCoercion) {
    const auto& [name, host, accepted] = GetParam();
    SCOPED_TRACE(name);
    TempDir directory;
    auto backend = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto port = reservation.Port();
    Configure(directory.Path(), Inbound(port), Direct());
    std::unique_ptr<PeerThread> peer;
    if (accepted) peer = std::make_unique<PeerThread>([&] {
        auto socket = backend.Accept();
        EXPECT_EQ(socket.ReadExact(Request.size()), Request);
        socket.Write(Banner);
    });
    reservation.Close();
    auto child = Start(directory.Path());
    child->WaitForLog("server started");
    auto socket = Socket::Connect(port);
    socket.Write(DomainRequest(backend.Port(), host));
    if (accepted) {
        EXPECT_EQ(socket.ReadExact(Banner.size() + 2, 2s), std::string("\0\0", 2) + std::string(Banner));
        peer->Join();
    } else {
        EXPECT_TRUE(ReadClosed(socket, 2s)) << "malformed literal returned bytes or stayed open";
        pollfd descriptor{backend.Fd(), POLLIN, 0};
        EXPECT_EQ(::poll(&descriptor, 1, 100), 0) << "malformed literal reached destination";
    }
    EXPECT_TRUE(child->Running());
    EXPECT_EQ(child->Stop(), 0);
}
INSTANTIATE_TEST_SUITE_P(CompleteConsumption, IpLiterals, testing::Values(
    LiteralCase{"ipv4", "127.0.0.1", true}, LiteralCase{"mapped_v6", "::ffff:127.0.0.1", true},
    LiteralCase{"mapped_hex", "0:0:0:0:0:ffff:7f00:1", true}, LiteralCase{"embedded_port", "127.0.0.1:9", false},
    LiteralCase{"embedded_nul", std::string("127.0.0.1\0ignored", 17), false},
    LiteralCase{"mapped_nul", std::string("::ffff:127.0.0.1\0ignored", 24), false},
    LiteralCase{"bracketed_v4", "[127.0.0.1]", false}, LiteralCase{"bracketed_v6", "[::ffff:127.0.0.1]", false},
    LiteralCase{"trailing_space", "127.0.0.1 ", false}, LiteralCase{"invalid_scope", "::ffff:127.0.0.1%invalid", false}));
} // namespace
} // namespace cnode::e2e::config_panel
