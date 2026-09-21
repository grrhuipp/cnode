#include "acppnode/sniff/sniffer.hpp"

#include <array>
#include <cstdio>
#include <span>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    acpp::QuicSniffer sniffer;
    const std::array<uint8_t, 8> empty_udp{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    const auto random = sniffer.Sniff(empty_udp);
    if (!Require(!random.success && !random.need_more,
                 "random UDP payload must not sniff as QUIC or wait for more")) {
        return 1;
    }

    // Long header with unknown version is not QUIC Initial we handle.
    const std::array<uint8_t, 12> unknown_version{
        0xc0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (!Require(!sniffer.Sniff(unknown_version).success,
                 "unknown QUIC version must not sniff a domain")) {
        return 2;
    }

    const auto tcp_hello = std::array<uint8_t, 5>{0x16, 0x03, 0x01, 0x00, 0x01};
    if (!Require(!acpp::Sniff(tcp_hello, acpp::Network::UDP).success,
                 "UDP sniff must not use TLS/HTTP sniffers")) {
        return 3;
    }
    return 0;
}
