#include <gtest/gtest.h>

#include "app/user_store.hpp"
#include "common/address_codec.hpp"
#include "common/multi_buffer.hpp"
#include "proxy/trojan/trojan_codec.hpp"
#include "proxy/vless/vless_codec.hpp"
#include "proxy/vmess/body.hpp"
#include "proxy/vmess/vmess_crypto.hpp"
#include "transport/link.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr uint16_t kPort = 8443;
constexpr std::array<uint8_t, 5> kPayload{0x00, 0x71, 0xff, '\r', '\n'};

struct DomainCase {
    const char* name;
    std::string wire_host;
    size_t wire_size;
    std::string normalized_host;
    bool accepted;
};

std::vector<DomainCase> DomainCases() {
    const std::string maximum = std::string(63, 'a') + "." + std::string(63, 'b') +
        "." + std::string(63, 'c') + "." + std::string(61, 'd');
    std::string absolute = maximum;
    std::transform(absolute.begin(), absolute.end(), absolute.begin(), [](unsigned char c) {
        return c >= 'a' && c <= 'z' ? static_cast<char>(c - 'a' + 'A') : static_cast<char>(c);
    });
    absolute += '.';
    return {
        {"Absolute254", absolute, 254, maximum, true},
        {"Relative253", maximum, 253, maximum, true},
        {"Overlong255", std::string(63, 'a') + "." + std::string(63, 'b') +
            "." + std::string(63, 'c') + "." + std::string(63, 'd'), 255, {}, false},
        {"Label64", std::string(64, 'a') + ".example", 72, {}, false},
    };
}

std::vector<uint8_t> EncodeRawAddress(const DomainCase& domain, common::AddressWireFormat format) {
    // 构造器会规范化根点；初始化后写入公开 host，确保测试发送原始域名而非253字节替身。
    common::TargetAddress target("fixture.example", kPort);
    target.host.assign(domain.wire_host.data(), domain.wire_host.size());
    std::array<uint8_t, common::kMaxEncodedAddressSize> encoded{};
    const size_t size = common::EncodeAddressTo(target, encoded.data(), encoded.size(), format);
    EXPECT_EQ(domain.wire_host.size(), domain.wire_size);
    EXPECT_EQ(size, domain.wire_size + 4);
    const size_t length_offset = format == common::AddressWireFormat::PortFirst ? 3 : 1;
    EXPECT_EQ(encoded[length_offset], domain.wire_size);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(encoded.data() + length_offset + 1),
                               domain.wire_size), domain.wire_host);
    return {encoded.begin(), encoded.begin() + size};
}

void ExpectTarget(const common::TargetAddress& target, const DomainCase& domain) {
    EXPECT_TRUE(target.IsValid());
    EXPECT_TRUE(target.IsDomain());
    EXPECT_EQ(std::string_view(target.host), domain.normalized_host);
    EXPECT_EQ(target.port, kPort);
}

void ExpectPayload(std::span<const uint8_t> wire, size_t consumed) {
    ASSERT_LE(consumed, wire.size());
    const auto remaining = wire.subspan(consumed);
    EXPECT_EQ(std::vector<uint8_t>(remaining.begin(), remaining.end()),
              std::vector<uint8_t>(kPayload.begin(), kPayload.end()));
}

std::vector<uint8_t> Flatten(const common::MultiBuffer& payload) {
    const auto part = payload.FrontSpan();
    return std::vector<uint8_t>(part.begin(), part.end());
}

class ProtocolDomainTest : public testing::TestWithParam<DomainCase> {};

TEST_P(ProtocolDomainTest, VlessRequestHeader) {
    const auto& domain = GetParam();
    const auto address = EncodeRawAddress(domain, common::AddressWireFormat::PortFirst);
    std::vector<uint8_t> wire(18, 0); // version、UUID、空addons。
    wire.push_back(static_cast<uint8_t>(proxy::VlessCommand::TCP));
    wire.insert(wire.end(), address.begin(), address.end());
    const size_t header_size = wire.size();
    wire.insert(wire.end(), kPayload.begin(), kPayload.end());

    const auto decoded = proxy::DecodeVlessRequestHeader(wire);
    if (!domain.accepted) {
        EXPECT_EQ(decoded.status, proxy::VlessRequestDecodeStatus::InvalidAddress);
        return;
    }
    ASSERT_EQ(decoded.status, proxy::VlessRequestDecodeStatus::Complete);
    ExpectTarget(decoded.header.target, domain);
    EXPECT_EQ(decoded.header.command, proxy::VlessCommand::TCP);
    EXPECT_EQ(decoded.consumed, header_size);
    ExpectPayload(wire, decoded.consumed);
}

TEST_P(ProtocolDomainTest, TrojanTcpAndUdpRequestHeaders) {
    const auto& domain = GetParam();
    const auto address = EncodeRawAddress(domain, common::AddressWireFormat::Socks5);
    for (const auto command : {proxy::TrojanCommand::CONNECT, proxy::TrojanCommand::UDP_ASSOCIATE}) {
        SCOPED_TRACE(static_cast<int>(command));
        std::vector<uint8_t> wire(proxy::kPasswordHashSize, 'a');
        wire.insert(wire.end(), {'\r', '\n', static_cast<uint8_t>(command)});
        wire.insert(wire.end(), address.begin(), address.end());
        wire.insert(wire.end(), {'\r', '\n'});
        const size_t header_size = wire.size();
        wire.insert(wire.end(), kPayload.begin(), kPayload.end());

        const auto decoded = proxy::DecodeTrojanRequest(wire);
        if (!domain.accepted) {
            EXPECT_EQ(decoded.status, proxy::TrojanRequestDecodeStatus::InvalidAddress);
            continue;
        }
        ASSERT_EQ(decoded.status, proxy::TrojanRequestDecodeStatus::Complete);
        ExpectTarget(decoded.request.target, domain);
        EXPECT_EQ(decoded.request.command, command);
        EXPECT_EQ(decoded.consumed, header_size);
        ExpectPayload(wire, decoded.consumed);
    }
}

TEST_P(ProtocolDomainTest, TrojanUdpFrame) {
    const auto& domain = GetParam();
    auto wire = EncodeRawAddress(domain, common::AddressWireFormat::Socks5);
    const size_t split = wire.size() - 1;
    wire.insert(wire.end(), {0, static_cast<uint8_t>(kPayload.size()), '\r', '\n'});
    wire.insert(wire.end(), kPayload.begin(), kPayload.end());
    // 尾随另一帧，检查首帧解析不会多消费后续流字节。
    constexpr std::array<uint8_t, 12> next_frame{
        1, 127, 0, 0, 1, 0, 53, 0, 1, '\r', '\n', 0x42};
    wire.insert(wire.end(), next_frame.begin(), next_frame.end());
    proxy::TrojanUdpFramer framer;
    proxy::TrojanFramedUdpPacket packet;
    if (!domain.accepted) {
        common::MultiBuffer input;
        ASSERT_TRUE(input.AppendSpan(wire));
        framer.Feed(std::move(input));
        try {
            (void)framer.Next(packet);
            ADD_FAILURE() << "invalid domain was accepted";
        } catch (const transport::LinkError& error) {
            EXPECT_EQ(error.code(), common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        return;
    }

    common::MultiBuffer prefix;
    ASSERT_TRUE(prefix.AppendSpan(std::span(wire).first(split)));
    framer.Feed(std::move(prefix));
    EXPECT_FALSE(framer.Next(packet));
    common::MultiBuffer remainder;
    ASSERT_TRUE(remainder.AppendSpan(std::span(wire).subspan(split)));
    framer.Feed(std::move(remainder));
    ASSERT_TRUE(framer.Next(packet));
    ExpectTarget(packet.target, domain);
    const auto datagram = common::InspectUdpDatagram(packet.payload);
    ASSERT_TRUE(datagram.Valid());
    ASSERT_NE(datagram.target, nullptr);
    ExpectTarget(*datagram.target, domain);
    EXPECT_EQ(Flatten(packet.payload), std::vector<uint8_t>(kPayload.begin(), kPayload.end()));
    ASSERT_TRUE(framer.Next(packet));
    EXPECT_TRUE(packet.target.SameEndpoint(common::TargetAddress("127.0.0.1", 53)));
    EXPECT_EQ(Flatten(packet.payload), std::vector<uint8_t>({0x42}));
    EXPECT_FALSE(framer.Next(packet));
    framer.Finish();
}

// 与 vmess_udp_datagram_test 的认证失败fixture相同：公开AuthID/AEAD codec
// 生成真实认证请求，经过 ServerSession 解密。客户端header builder的253字节
// 出站限制不能用于生成本测试所需的254字节入站wire。
class VmessUsers {
public:
    static constexpr std::string_view kTag = "protocol-domain-boundary";
    app::PreparedVmessUser user;

    VmessUsers() {
        using namespace app;
        user.auth_key.fill(0x19);
        user.cmd_key.fill(0x27);
        user.profile.user_id = 73;
        auto snapshot = UserStore::PrepareUsers(kTag, UserSet{PreparedVmessUsers{user}});
        auto view = UserStore::PrepareWorkerView(snapshot);
        UserStore::CommitSnapshot(std::move(snapshot));
        UserStore::InstallWorkerView(std::move(view));
    }

    ~VmessUsers() { app::UserStore::ClearWorkerView(); }
};

TEST_P(ProtocolDomainTest, VmessAuthenticatedRequestHeader) {
    const auto& domain = GetParam();
    const auto address = EncodeRawAddress(domain, common::AddressWireFormat::PortFirst);
    VmessUsers users;
    std::vector<uint8_t> plain(38, 0);
    plain[0] = 1;
    std::fill(plain.begin() + 1, plain.begin() + 33, 0x35); // body IV/key。
    plain[35] = static_cast<uint8_t>(proxy::VmessSecurity::NONE);
    plain[37] = static_cast<uint8_t>(proxy::VmessCommand::UDP);
    plain.insert(plain.end(), address.begin(), address.end());
    ASSERT_EQ(plain[41], domain.wire_size); // 加密前的实际PortFirst域名长度。
    const uint32_t checksum = common::Fnv1a32(std::span<const uint8_t>(plain.data(), plain.size()));
    for (size_t i = 0; i != 4; ++i) {
        plain.push_back(static_cast<uint8_t>(checksum >> (24 - i * 8)));
    }

    std::vector<uint8_t> wire(42 + plain.size() + 16, 0);
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    proxy::GenerateAuthID(proxy::ExpandAuthIDEncryptKey(users.user.auth_key), now, wire.data());
    const std::span<const uint8_t, 16> auth_id(wire.data(), 16);
    const std::span<const uint8_t, 8> nonce(wire.data() + 34, 8);
    const auto length_key = proxy::RequestHeaderLengthKey(users.user.cmd_key, auth_id, nonce);
    const auto payload_key = proxy::RequestHeaderPayloadKey(users.user.cmd_key, auth_id, nonce);
    const std::array<uint8_t, 2> length{
        static_cast<uint8_t>(plain.size() >> 8), static_cast<uint8_t>(plain.size())};
    ASSERT_TRUE(proxy::SealScatterOneShotAead(EVP_aead_aes_128_gcm(), {length_key.key.data(), 16}, {length_key.nonce.data(), 12}, {length.data(), length.size()}, {auth_id.data(), auth_id.size()}, wire.data() + 16, {wire.data() + 18, 16}));
    ASSERT_TRUE(proxy::SealScatterOneShotAead(EVP_aead_aes_128_gcm(), {payload_key.key.data(), 16}, {payload_key.nonce.data(), 12}, {plain.data(), plain.size()}, {auth_id.data(), auth_id.size()}, wire.data() + 42, {wire.data() + 42 + plain.size(), 16}));
    const size_t header_size = wire.size();
    wire.insert(wire.end(), kPayload.begin(), kPayload.end());

    proxy::ServerSession session(VmessUsers::kTag);
    const auto prefix = session.DecodeRequestHeader(wire.data(), 42);
    EXPECT_FALSE(prefix.first);
    EXPECT_EQ(session.RequiredHeaderBytes(), header_size);
    const auto [request, consumed] = session.DecodeRequestHeader(wire.data(), wire.size());
    if (!domain.accepted) {
        EXPECT_FALSE(request);
        EXPECT_EQ(session.RequiredHeaderBytes(), 0u);
        const auto* rejected = session.AuthenticatedRejectedHeader();
        ASSERT_NE(rejected, nullptr); // 是域名语义拒绝，不是fixture认证失败。
        ASSERT_TRUE(rejected->user);
        EXPECT_EQ(rejected->user->profile.user_id, 73);
        return;
    }
    ASSERT_TRUE(request) << session.HeaderFailureReason();
    ASSERT_TRUE(request->user);
    EXPECT_EQ(request->user->profile.user_id, 73);
    EXPECT_EQ(request->command, proxy::VmessCommand::UDP);
    ExpectTarget(request->target, domain);
    EXPECT_EQ(consumed, header_size);
    ExpectPayload(wire, consumed);
}

INSTANTIATE_TEST_SUITE_P(Boundaries, ProtocolDomainTest, testing::ValuesIn(DomainCases()),
    [](const testing::TestParamInfo<DomainCase>& info) { return info.param.name; });

} // namespace
