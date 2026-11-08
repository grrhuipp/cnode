#include <gtest/gtest.h>

#include "app/proxyman/inbound/prepared_config.hpp"
#include "common/address_codec.hpp"
#include "common/buf/multi_buffer.hpp"
#include "proxy/trojan/trojan_codec.hpp"
#include "proxy/trojan/udp_framing.hpp"
#include "proxy/vless/vless_codec.hpp"
#include "proxy/vmess/encoding/server.hpp"
#include "proxy/vmess/vmess_crypto.hpp"

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

std::vector<uint8_t> EncodeRawAddress(const DomainCase& domain, AddressWireFormat format) {
    // 构造器会规范化根点；初始化后写入公开 host，确保测试发送原始域名而非253字节替身。
    TargetAddress target("fixture.example", kPort);
    target.host.assign(domain.wire_host.data(), domain.wire_host.size());
    std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
    const size_t size = EncodeAddressTo(target, encoded.data(), encoded.size(), format);
    EXPECT_EQ(domain.wire_host.size(), domain.wire_size);
    EXPECT_EQ(size, domain.wire_size + 4);
    const size_t length_offset = format == AddressWireFormat::PortFirst ? 3 : 1;
    EXPECT_EQ(encoded[length_offset], domain.wire_size);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(encoded.data() + length_offset + 1),
                               domain.wire_size), domain.wire_host);
    return {encoded.begin(), encoded.begin() + size};
}

void ExpectTarget(const TargetAddress& target, const DomainCase& domain) {
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

std::vector<uint8_t> Flatten(const buf::MultiBuffer& payload) {
    std::vector<uint8_t> bytes;
    for (const buf::Buffer* buffer : payload) {
        if (buffer && !buffer->IsEmpty()) {
            const auto part = buffer->Bytes();
            bytes.insert(bytes.end(), part.begin(), part.end());
        }
    }
    return bytes;
}

class ProtocolDomainTest : public testing::TestWithParam<DomainCase> {};

TEST_P(ProtocolDomainTest, VlessRequestHeader) {
    const auto& domain = GetParam();
    const auto address = EncodeRawAddress(domain, AddressWireFormat::PortFirst);
    std::vector<uint8_t> wire(18, 0); // version、UUID、空addons。
    wire.push_back(static_cast<uint8_t>(vless::Command::TCP));
    wire.insert(wire.end(), address.begin(), address.end());
    const size_t header_size = wire.size();
    wire.insert(wire.end(), kPayload.begin(), kPayload.end());

    const auto decoded = vless::DecodeRequestHeader(wire);
    if (!domain.accepted) {
        EXPECT_EQ(decoded.status, vless::RequestHeaderDecodeStatus::InvalidAddress);
        return;
    }
    ASSERT_EQ(decoded.status, vless::RequestHeaderDecodeStatus::Complete);
    ExpectTarget(decoded.header.target, domain);
    EXPECT_EQ(decoded.header.command, vless::Command::TCP);
    EXPECT_EQ(decoded.consumed, header_size);
    ExpectPayload(wire, decoded.consumed);
}

TEST_P(ProtocolDomainTest, TrojanTcpAndUdpRequestHeaders) {
    const auto& domain = GetParam();
    const auto address = EncodeRawAddress(domain, AddressWireFormat::Socks5);
    for (const auto command : {trojan::TrojanCommand::CONNECT, trojan::TrojanCommand::UDP_ASSOCIATE}) {
        SCOPED_TRACE(static_cast<int>(command));
        std::vector<uint8_t> wire(trojan::kPasswordHashSize, 'a');
        wire.insert(wire.end(), {'\r', '\n', static_cast<uint8_t>(command)});
        wire.insert(wire.end(), address.begin(), address.end());
        wire.insert(wire.end(), {'\r', '\n'});
        const size_t header_size = wire.size();
        wire.insert(wire.end(), kPayload.begin(), kPayload.end());

        const auto decoded = trojan::DecodeRequest(wire);
        if (!domain.accepted) {
            EXPECT_EQ(decoded.status, trojan::RequestDecodeStatus::InvalidAddress);
            continue;
        }
        ASSERT_EQ(decoded.status, trojan::RequestDecodeStatus::Complete);
        ExpectTarget(decoded.request.target, domain);
        EXPECT_EQ(decoded.request.command, command);
        EXPECT_EQ(decoded.consumed, header_size);
        ExpectPayload(wire, decoded.consumed);
    }
}

TEST_P(ProtocolDomainTest, TrojanUdpFrame) {
    const auto& domain = GetParam();
    auto wire = EncodeRawAddress(domain, AddressWireFormat::Socks5);
    const size_t split = wire.size() - 1;
    wire.insert(wire.end(), {0, static_cast<uint8_t>(kPayload.size()), '\r', '\n'});
    wire.insert(wire.end(), kPayload.begin(), kPayload.end());
    // 尾随另一帧，检查首帧解析不会多消费后续流字节。
    constexpr std::array<uint8_t, 12> next_frame{
        1, 127, 0, 0, 1, 0, 53, 0, 1, '\r', '\n', 0x42};
    wire.insert(wire.end(), next_frame.begin(), next_frame.end());
    trojan::UdpFramer framer;
    trojan::FramedUdpPacket packet;
    if (!domain.accepted) {
        buf::MultiBuffer input;
        ASSERT_TRUE(buf::AppendSpanToMultiBuffer(wire, input));
        framer.Feed(std::move(input));
        EXPECT_THROW((void)framer.Next(packet), IoSystemError);
        return;
    }

    buf::MultiBuffer prefix;
    ASSERT_TRUE(buf::AppendSpanToMultiBuffer(std::span(wire).first(split), prefix));
    framer.Feed(std::move(prefix));
    EXPECT_FALSE(framer.Next(packet));
    buf::MultiBuffer remainder;
    ASSERT_TRUE(buf::AppendSpanToMultiBuffer(std::span(wire).subspan(split), remainder));
    framer.Feed(std::move(remainder));
    ASSERT_TRUE(framer.Next(packet));
    ExpectTarget(packet.target, domain);
    const auto datagram = buf::InspectUdpDatagram(packet.payload);
    ASSERT_TRUE(datagram.Valid());
    ASSERT_NE(datagram.target, nullptr);
    ExpectTarget(*datagram.target, domain);
    EXPECT_EQ(Flatten(packet.payload), std::vector<uint8_t>(kPayload.begin(), kPayload.end()));
    ASSERT_TRUE(framer.Next(packet));
    EXPECT_TRUE(packet.target.SameEndpoint(TargetAddress("127.0.0.1", 53)));
    EXPECT_EQ(Flatten(packet.payload), std::vector<uint8_t>({0x42}));
    EXPECT_FALSE(framer.Next(packet));
    EXPECT_NO_THROW(framer.Finish());
}

// 与 vmess_udp_datagram_test 的认证失败fixture相同：公开AuthID/AEAD codec
// 生成真实认证请求，经过 ServerSession 解密。客户端header builder的253字节
// 出站限制不能用于生成本测试所需的254字节入站wire。
class VmessUsers {
public:
    static constexpr std::string_view kTag = "protocol-domain-boundary";
    proxyman::inbound::PreparedVmessUser user;

    VmessUsers() {
        using namespace proxyman::inbound;
        user.uuid = "11111111-1111-4111-8111-111111111111";
        user.auth_key.fill(0x19);
        user.cmd_key.fill(0x27);
        user.profile.user_id = 73;
        auto snapshot = UserStore::PrepareUsers(kTag, UserSet{PreparedVmessUsers{user}});
        auto view = UserStore::PrepareWorkerView(snapshot);
        UserStore::CommitSnapshot(std::move(snapshot));
        UserStore::InstallWorkerView(std::move(view));
    }

    ~VmessUsers() { proxyman::inbound::UserStore::ClearWorkerView(); }
};

TEST_P(ProtocolDomainTest, VmessAuthenticatedRequestHeader) {
    const auto& domain = GetParam();
    const auto address = EncodeRawAddress(domain, AddressWireFormat::PortFirst);
    VmessUsers users;
    std::vector<uint8_t> plain(38, 0);
    plain[0] = 1;
    std::fill(plain.begin() + 1, plain.begin() + 33, 0x35); // body IV/key。
    plain[35] = static_cast<uint8_t>(vmess::Security::NONE);
    plain[37] = static_cast<uint8_t>(vmess::Command::UDP);
    plain.insert(plain.end(), address.begin(), address.end());
    ASSERT_EQ(plain[41], domain.wire_size); // 加密前的实际PortFirst域名长度。
    const uint32_t checksum = vmess::FNV1a32(plain.data(), plain.size());
    for (size_t i = 0; i != 4; ++i) {
        plain.push_back(static_cast<uint8_t>(checksum >> (24 - i * 8)));
    }

    std::vector<uint8_t> wire(42 + plain.size() + 16, 0);
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    vmess::GenerateAuthID(vmess::ExpandAuthIDEncryptKey(users.user.auth_key), now, wire.data());
    const std::span<const uint8_t, 16> auth_id(wire.data(), 16);
    const std::span<const uint8_t, 8> nonce(wire.data() + 34, 8);
    const auto length_key = vmess::RequestHeaderLengthKey(users.user.cmd_key, auth_id, nonce);
    const auto payload_key = vmess::RequestHeaderPayloadKey(users.user.cmd_key, auth_id, nonce);
    const std::array<uint8_t, 2> length{
        static_cast<uint8_t>(plain.size() >> 8), static_cast<uint8_t>(plain.size())};
    ASSERT_TRUE(vmess::AES128GCMEncrypt(length_key.key.data(), length_key.nonce.data(),
        auth_id.data(), auth_id.size(), length.data(), length.size(),
        wire.data() + 16, wire.data() + 18));
    ASSERT_TRUE(vmess::AES128GCMEncrypt(payload_key.key.data(), payload_key.nonce.data(),
        auth_id.data(), auth_id.size(), plain.data(), plain.size(),
        wire.data() + 42, wire.data() + 42 + plain.size()));
    const size_t header_size = wire.size();
    wire.insert(wire.end(), kPayload.begin(), kPayload.end());

    vmess::TimedUserValidator validator;
    vmess::encoding::ServerSession session(validator, VmessUsers::kTag);
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
    EXPECT_EQ(request->command, vmess::Command::UDP);
    ExpectTarget(request->target, domain);
    EXPECT_EQ(consumed, header_size);
    ExpectPayload(wire, consumed);
}

INSTANTIATE_TEST_SUITE_P(Boundaries, ProtocolDomainTest, testing::ValuesIn(DomainCases()),
    [](const testing::TestParamInfo<DomainCase>& info) { return info.param.name; });

} // namespace
