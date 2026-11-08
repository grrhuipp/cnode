#include "udp_wire.hpp"

namespace cnode::e2e::udp {
namespace {
// Independent wire peer: the existing client emits a single-user AES packet.
// SIP022 identity mode changes its separate header and inserts one EIH; the
// authenticated body and server replies still use the selected user's key.
std::string WithIdentity(std::string_view packet, std::string_view user_key,
                         std::string_view identity_key) {
    Require(packet.size() >= 32, "short identity request");
    const auto separate = AesBlock(user_key, packet.substr(0, 16), false);
    std::string identity(16, '\0');
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, user_key.data(), user_key.size());
    blake3_hasher_finalize(&hasher, Bytes(identity), identity.size());
    OPENSSL_cleanse(&hasher, sizeof(hasher));
    for (size_t i = 0; i < identity.size(); ++i)
        identity[i] = static_cast<char>(static_cast<unsigned char>(identity[i]) ^
                                        static_cast<unsigned char>(separate[i]));
    return AesBlock(identity_key, separate, true) +
           AesBlock(identity_key, identity, true) + std::string(packet.substr(16));
}

class Ss2022UdpIdentity : public testing::TestWithParam<bool> {};

TEST_P(Ss2022UdpIdentity, AuthenticatesUsersAndPreservesReplayNamespaces) {
    const bool aes256 = GetParam();
    const size_t key_size = aes256 ? 32 : 16;
    const std::string cipher = aes256 ? "aes256" : "aes";
    const std::string method = aes256 ? "2022-blake3-aes-256-gcm" : "2022-blake3-aes-128-gcm";
    const auto identity_key = Sequence(key_size, 193);
    const auto first_key = Sequence(key_size);
    const auto second_key = Sequence(key_size, key_size);
    TempDir root;
    auto peer = Socket::BindUdp();
    PortReservation reservation(true);
    Json clients = Json::array({{{"password", Base64(first_key)}}, {{"password", Base64(second_key)}}});
    for (size_t i = 0; i < 255; ++i) {
        auto key = BigEndian(i, 8) + std::string(key_size - 8, '\x7b');
        clients.push_back({{"password", Base64(key)}});
    }
    WriteJson(root.Path(), "config.json", {{"workers", 1},
        {"log", {{"enable", false}, {"logDir", (root.Path() / "logs").string()}}}});
    WriteJson(root.Path(), "inbounds.json", Json::array({{
        {"tag", "identity-udp"}, {"protocol", "shadowsocks"}, {"listen", "127.0.0.1"},
        {"port", reservation.port}, {"outboundTag", "direct"},
        {"settings", {{"method", method}, {"password", Base64(identity_key)}, {"clients", clients}}}}}));
    WriteJson(root.Path(), "outbounds.json", Json::array({{
        {"tag", "direct"}, {"protocol", "freedom"}, {"settings", Json::object()}}}));
    const auto port = reservation.port;
    reservation.Release();
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started");
    Client first(port, peer.Port(), true, false, "127.0.0.1", cipher);
    Client second(port, peer.Port(), true, true, "127.0.0.1", cipher);
    second.socket = first.socket;

    const auto first_packet = WithIdentity(first.Encode(""), first_key, identity_key);
    first.SendRaw(first_packet);
    auto first_path = Receive(peer);
    EXPECT_EQ(first_path.payload, "");
    Reply(peer, first_path, "first-user-response");
    first.Expect("first-user-response");

    const std::string payload(1200, 'z');
    second.SendRaw(WithIdentity(second.Encode(payload), second_key, identity_key));
    auto second_path = Receive(peer);
    EXPECT_EQ(second_path.payload, payload);
    EXPECT_FALSE(first_path.SameEndpoint(second_path));
    Reply(peer, second_path, "second-user-response");
    second.Expect("second-user-response");

    first.SendRaw(first_packet);
    EXPECT_FALSE(Readable(peer.Fd(), 150ms));
    const auto next = WithIdentity(first.Encode("next-valid-packet"), first_key, identity_key);
    auto damaged = next;
    damaged.back() ^= 1;
    first.SendRaw(damaged);
    EXPECT_FALSE(Readable(peer.Fd(), 150ms));
    first.SendRaw(next);
    auto resumed = Receive(peer);
    EXPECT_EQ(resumed.payload, "next-valid-packet");
    EXPECT_TRUE(resumed.SameEndpoint(first_path));
    Reply(peer, resumed, "after-rejected-packet");
    first.Expect("after-rejected-packet");
    EXPECT_EQ(child.Stop(), 0);
}

INSTANTIATE_TEST_SUITE_P(AesMethods, Ss2022UdpIdentity, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) { return info.param ? "Aes256" : "Aes128"; });
} // namespace
} // namespace cnode::e2e::udp
