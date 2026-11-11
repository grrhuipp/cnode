#include <gtest/gtest.h>

#include "sniff/sniffer.hpp"

#include <string_view>
#include <vector>

namespace {

void AppendU16(std::vector<uint8_t>& output, std::size_t value) {
    output.push_back(static_cast<uint8_t>(value >> 8));
    output.push_back(static_cast<uint8_t>(value));
}

void AppendU24(std::vector<uint8_t>& output, std::size_t value) {
    output.push_back(static_cast<uint8_t>(value >> 16));
    output.push_back(static_cast<uint8_t>(value >> 8));
    output.push_back(static_cast<uint8_t>(value));
}

void SetU16(std::vector<uint8_t>& output, std::size_t offset, std::size_t value) {
    output[offset] = static_cast<uint8_t>(value >> 8);
    output[offset + 1] = static_cast<uint8_t>(value);
}

void SetU24(std::vector<uint8_t>& output, std::size_t offset, std::size_t value) {
    output[offset] = static_cast<uint8_t>(value >> 16);
    output[offset + 1] = static_cast<uint8_t>(value >> 8);
    output[offset + 2] = static_cast<uint8_t>(value);
}

struct ClientHelloFixture {
    std::vector<uint8_t> bytes;
    std::size_t extensions_length_offset = 0;
};

ClientHelloFixture BuildClientHello(
    bool malformed_sni_tail = false,
    std::string_view host = "example.com") {
    std::vector<uint8_t> server_name_list;
    server_name_list.push_back(0);
    AppendU16(server_name_list, host.size());
    server_name_list.insert(server_name_list.end(), host.begin(), host.end());
    if (malformed_sni_tail) server_name_list.push_back(0xff);

    std::vector<uint8_t> sni_extension;
    AppendU16(sni_extension, server_name_list.size());
    sni_extension.insert(
        sni_extension.end(), server_name_list.begin(), server_name_list.end());

    std::vector<uint8_t> extensions;
    AppendU16(extensions, 0);
    AppendU16(extensions, sni_extension.size());
    extensions.insert(
        extensions.end(), sni_extension.begin(), sni_extension.end());

    std::vector<uint8_t> body;
    AppendU16(body, 0x0303);
    body.insert(body.end(), 32, 0x11);
    body.push_back(0);
    AppendU16(body, 2);
    AppendU16(body, 0x1301);
    body.push_back(1);
    body.push_back(0);
    const std::size_t extensions_length_in_body = body.size();
    AppendU16(body, extensions.size());
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake;
    handshake.push_back(1);
    AppendU24(handshake, body.size());
    handshake.insert(handshake.end(), body.begin(), body.end());

    ClientHelloFixture fixture;
    fixture.bytes.push_back(0x16);
    AppendU16(fixture.bytes, 0x0301);
    AppendU16(fixture.bytes, handshake.size());
    fixture.bytes.insert(
        fixture.bytes.end(), handshake.begin(), handshake.end());
    fixture.extensions_length_offset =
        5 + 4 + extensions_length_in_body;
    return fixture;
}

}  // namespace

TEST(TlsSniffer, ExtractsCanonicalClientHelloServerName) {
    const auto result = ::sniff::SniffTls(BuildClientHello().bytes);
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.domain, "example.com");
}

TEST(TlsSniffer, RejectsTrailingMalformedSniBytes) {
    EXPECT_FALSE(::sniff::SniffTls(BuildClientHello(true).bytes).success);
}

TEST(TlsSniffer, DoesNotReadBeyondDeclaredRecord) {
    auto hello = BuildClientHello();
    SetU16(hello.bytes, 3, hello.bytes.size() - 6);
    EXPECT_FALSE(::sniff::SniffTls(hello.bytes).success);
}

TEST(TlsSniffer, IncompleteRecordRequestsMoreBytes) {
    auto hello = BuildClientHello();
    SetU16(hello.bytes, 3, hello.bytes.size() - 4);
    const auto result = ::sniff::SniffTls(hello.bytes);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "tls");
}

TEST(TlsSniffer, DoesNotReadBeyondDeclaredHandshake) {
    auto hello = BuildClientHello();
    SetU24(hello.bytes, 6, hello.bytes.size() - 10);
    EXPECT_FALSE(::sniff::SniffTls(hello.bytes).success);
}

TEST(TlsSniffer, RejectsTruncatedExtensionList) {
    auto hello = BuildClientHello();
    SetU16(hello.bytes, hello.extensions_length_offset, hello.bytes.size());
    EXPECT_FALSE(::sniff::SniffTls(hello.bytes).success);
}

namespace {
class TlsInvalidHostName : public testing::TestWithParam<const char*> {};
TEST_P(TlsInvalidHostName, RejectsNonDnsSniIdentity) {
    EXPECT_FALSE(::sniff::SniffTls(BuildClientHello(false, GetParam()).bytes).success);
}
INSTANTIATE_TEST_SUITE_P(Identities, TlsInvalidHostName, testing::Values(
    "192.0.2.1", "example.com.", "bad..example", "bad_name.example"));
}

TEST(TlsSniffer, ReassemblesClientHelloAcrossTlsRecords) {
    const auto valid = BuildClientHello();
    const std::vector<uint8_t> handshake(valid.bytes.begin() + 5, valid.bytes.end());
    const std::size_t split = 20;
    std::vector<uint8_t> wire{0x16};
    AppendU16(wire, 0x0301);
    AppendU16(wire, split);
    wire.insert(wire.end(), handshake.begin(), handshake.begin() + split);
    wire.push_back(0x16);
    AppendU16(wire, 0x0303);
    AppendU16(wire, handshake.size() - split);
    wire.insert(wire.end(), handshake.begin() + split, handshake.end());
    const auto result = ::sniff::SniffTls(wire);
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.domain, "example.com");
}
