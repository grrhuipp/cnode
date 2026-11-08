#include <gtest/gtest.h>

#include "reality_client_hello.hpp"
#include <cstdio>
#include <vector>

namespace {
using Reader = ::RealityClientHelloReader;
bool Require(bool ok, const char* message) {
    if (!ok) std::fprintf(stderr, "%s\n", message);
    return ok;
}
std::vector<uint8_t> Records(const std::vector<uint8_t>& hello, size_t fragment) {
    std::vector<uint8_t> wire;
    for (size_t offset = 0; offset < hello.size();) {
        const auto count = std::min(fragment, hello.size() - offset);
        wire.insert(wire.end(), {22, 3, 1, static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count)});
        wire.insert(wire.end(), hello.begin() + offset, hello.begin() + offset + count);
        offset += count;
    }
    return wire;
}
void Feed(Reader& reader, std::span<const uint8_t> wire, size_t fragment) {
    while (!wire.empty() && reader.State() == Reader::Status::Reading) {
        const size_t count = std::min({wire.size(), fragment, reader.ReadSize()});
        reader.Append(wire.first(count));
        wire = wire.subspan(count);
    }
}
}
TEST(RealityClientHello, Contract) {
    std::vector<uint8_t> hello(20000, 0x55);
    hello[0] = 1;
    hello[1] = 0;
    hello[2] = static_cast<uint8_t>((hello.size() - 4) >> 8);
    hello[3] = static_cast<uint8_t>(hello.size() - 4);
    for (const size_t record : {size_t{1}, size_t{2}, size_t{3}, size_t{17}, size_t{16384}}) {
        for (const size_t tcp : {size_t{1}, size_t{4}, size_t{4096}}) {
            Reader reader;
            const auto wire = Records(hello, record);
            Feed(reader, wire, tcp);
            ASSERT_FALSE((!Require(reader.State() == Reader::Status::Complete,
                         "ClientHello spanning TLS/TCP fragments must complete")));
            ASSERT_FALSE((!Require(std::ranges::equal(reader.Hello(), hello),
                         "authentication transcript must exclude all record headers")));
            ASSERT_FALSE((!Require(std::ranges::equal(reader.TakeWire(), wire),
                         "fallback and SSL replay must preserve exact record bytes")));
        }
    }
    const std::array<uint8_t, 9> oversized{22, 3, 3, 0, 4, 1, 0xff, 0xff, 0xff};
    Reader bad;
    Feed(bad, oversized, 1);
    ASSERT_FALSE((!Require(bad.State() == Reader::Status::Invalid && bad.Hello().size() == 4,
                 "untrusted 24-bit length must reject before allocating its body")));
    Reader partial;
    const auto wire = Records(hello, 13);
    Feed(partial, std::span(wire).first(wire.size() - 1), 1);
    ASSERT_FALSE((!Require(partial.State() == Reader::Status::Reading,
                 "incomplete record stays pending until caller observes EOF/deadline")));
    for (const auto header : {std::array<uint8_t, 5>{22, 3, 3, 0, 0},
                              std::array<uint8_t, 5>{22, 3, 3, 0x40, 1},
                              std::array<uint8_t, 5>{23, 3, 3, 0, 1}}) {
        Reader invalid;
        Feed(invalid, header, 1);
        ASSERT_FALSE((!Require(invalid.State() == Reader::Status::Invalid && invalid.Hello().empty(),
                     "invalid record header rejects without reading/allocating payload")));
    }
    Reader probe;
    const std::array<uint8_t, 1> http_get{'G'};
    probe.Append(http_get);
    ASSERT_FALSE((!Require(probe.State() == Reader::Status::Invalid,
                 "1-byte non-TLS probe must fail immediately without waiting for 5 bytes")));
}
