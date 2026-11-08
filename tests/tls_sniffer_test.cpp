#include <gtest/gtest.h>

#include "sniff/sniffer.hpp"

#include <cstdio>
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

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

TEST(TlsSniffer, Contract) {
    auto valid = BuildClientHello();
    const auto valid_result = ::SniffTls(valid.bytes);
    ASSERT_FALSE((!Require(valid_result.success && valid_result.domain == "example.com",
                 "a canonical ClientHello must be sniffed")));

    auto malformed_sni = BuildClientHello(true);
    ASSERT_FALSE((!Require(!::SniffTls(malformed_sni.bytes).success,
                 "malformed bytes after SNI must be rejected")));

    auto short_record = BuildClientHello();
    SetU16(short_record.bytes, 3, short_record.bytes.size() - 6);
    ASSERT_FALSE((!Require(!::SniffTls(short_record.bytes).success,
                 "bytes outside the declared TLS record must be ignored")));

    auto long_record = BuildClientHello();
    SetU16(long_record.bytes, 3, long_record.bytes.size() - 4);
    const auto partial_record_res = ::SniffTls(long_record.bytes);
    ASSERT_FALSE((!Require(!partial_record_res.success && partial_record_res.need_more &&
                     partial_record_res.protocol == "tls",
                 "an incomplete TLS ClientHello record must request more bytes")));

    auto short_handshake = BuildClientHello();
    SetU24(short_handshake.bytes, 6, short_handshake.bytes.size() - 10);
    ASSERT_FALSE((!Require(!::SniffTls(short_handshake.bytes).success,
                 "bytes outside the declared ClientHello must be ignored")));

    auto long_extensions = BuildClientHello();
    SetU16(long_extensions.bytes, long_extensions.extensions_length_offset,
           long_extensions.bytes.size());
    ASSERT_FALSE((!Require(!::SniffTls(long_extensions.bytes).success,
                 "truncated ClientHello extensions must be rejected")));

    const auto ipv4_sni = BuildClientHello(false, "192.0.2.1");
    ASSERT_FALSE((!Require(!::SniffTls(ipv4_sni.bytes).success,
                 "an IPv4 literal must not be accepted as TLS host_name")));

    const auto trailing_dot_sni = BuildClientHello(false, "example.com.");
    ASSERT_FALSE((!Require(!::SniffTls(trailing_dot_sni.bytes).success,
                 "TLS host_name must not contain a trailing dot")));

    const auto empty_label_sni = BuildClientHello(false, "bad..example");
    ASSERT_FALSE((!Require(!::SniffTls(empty_label_sni.bytes).success,
                 "TLS host_name must not contain an empty DNS label")));

    const auto invalid_label_sni = BuildClientHello(false, "bad_name.example");
    ASSERT_FALSE((!Require(!::SniffTls(invalid_label_sni.bytes).success,
                 "TLS host_name must use DNS hostname labels")));

    // A ClientHello split across two TLS Handshake records must be reassembled and sniffed.
    const std::vector<uint8_t> handshake(valid.bytes.begin() + 5, valid.bytes.end());
    const std::size_t split = 20;
    std::vector<uint8_t> two_records;
    two_records.push_back(0x16);
    AppendU16(two_records, 0x0301);
    AppendU16(two_records, split);
    two_records.insert(two_records.end(), handshake.begin(), handshake.begin() + split);
    two_records.push_back(0x16);
    AppendU16(two_records, 0x0303);
    AppendU16(two_records, handshake.size() - split);
    two_records.insert(two_records.end(), handshake.begin() + split, handshake.end());
    const auto multi_record_res = ::SniffTls(two_records);
    ASSERT_FALSE((!Require(multi_record_res.success && multi_record_res.domain == "example.com",
                 "a ClientHello spanning two TLS records must be sniffed")));
}
