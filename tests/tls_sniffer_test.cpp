#include "acppnode/sniff/sniffer.hpp"

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

ClientHelloFixture BuildClientHello(bool malformed_sni_tail = false) {
    const std::string_view host = "example.com";
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

int main() {
    acpp::TlsSniffer sniffer;
    auto valid = BuildClientHello();
    const auto valid_result = sniffer.Sniff(valid.bytes);
    if (!Require(valid_result.success && valid_result.domain == "example.com",
                 "a canonical ClientHello must be sniffed")) return 1;

    auto malformed_sni = BuildClientHello(true);
    if (!Require(!sniffer.Sniff(malformed_sni.bytes).success,
                 "malformed bytes after SNI must be rejected")) return 2;

    auto short_record = BuildClientHello();
    SetU16(short_record.bytes, 3, short_record.bytes.size() - 6);
    if (!Require(!sniffer.Sniff(short_record.bytes).success,
                 "bytes outside the declared TLS record must be ignored")) return 3;

    auto long_record = BuildClientHello();
    SetU16(long_record.bytes, 3, long_record.bytes.size() - 4);
    if (!Require(!sniffer.Sniff(long_record.bytes).success,
                 "a truncated TLS record must be rejected")) return 4;

    auto short_handshake = BuildClientHello();
    SetU24(short_handshake.bytes, 6, short_handshake.bytes.size() - 10);
    if (!Require(!sniffer.Sniff(short_handshake.bytes).success,
                 "bytes outside the declared ClientHello must be ignored")) return 5;

    auto long_extensions = BuildClientHello();
    SetU16(long_extensions.bytes, long_extensions.extensions_length_offset,
           long_extensions.bytes.size());
    if (!Require(!sniffer.Sniff(long_extensions.bytes).success,
                 "truncated ClientHello extensions must be rejected")) return 6;
    return 0;
}
