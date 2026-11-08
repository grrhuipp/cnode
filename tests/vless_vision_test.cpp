#include <stdexcept>
#include <gtest/gtest.h>

// Wire timing reference: XTLS/Xray-core a4a3dff5b20c2faae567b742c172c7b95e75c083
// proxy/proxy.go: VisionWriter.WriteMultiBuffer, IsCompleteRecord, XtlsPadding.
#include "vless_vision.hpp"
#include "common/byte_reader.hpp"
#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace {
void Check(bool ok, const char* message) {
    if (!ok) { std::cerr << message << '\n'; ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed"); }
}
class Capture final : public transport::MultiBufferWriter {
public:
    std::vector<uint8_t> bytes;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        for (auto* b : mb) bytes.insert(bytes.end(), b->Bytes().begin(), b->Bytes().end());
        co_return;
    }
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        for (auto b : buffers) {
            const auto* p = static_cast<const uint8_t*>(b.data());
            bytes.insert(bytes.end(), p, p + b.size());
        }
        co_return;
    }
};
struct Frame { uint8_t command; size_t content; size_t padding; size_t end; };
Frame Parse(const Capture& sink, size_t offset, bool first) {
    offset += first ? 16 : 0;
    Check(offset + 5 <= sink.bytes.size(), "missing Vision frame header");
    const auto* p = sink.bytes.data() + offset;
    Frame f{p[0], LoadU16BE(p + 1), LoadU16BE(p + 3), 0};
    f.end = offset + 5 + f.content + f.padding;
    Check(f.end <= sink.bytes.size(), "truncated Vision frame");
    Check(f.content + f.padding <= 8192 - 21, "Vision frame exceeded Xray capacity");
    return f;
}
class FragmentReader final : public transport::MultiBufferReader {
public:
    explicit FragmentReader(const std::vector<uint8_t>& bytes, size_t chunk = 1)
        : bytes_(bytes), chunk_(chunk) {}
    bool EnableRawRead() noexcept override { switched_at = offset_; return true; }
    size_t switched_at = 0;
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        buf::MultiBuffer mb;
        if (offset_ < bytes_.size()) {
            const auto n = std::min(chunk_, bytes_.size() - offset_);
            Check(buf::AppendSpanToMultiBuffer(std::span(bytes_).subspan(offset_, n), mb), "allocation");
            offset_ += n;
        }
        co_return mb;
    }
private:
    const std::vector<uint8_t>& bytes_;
    size_t offset_ = 0;
    size_t chunk_;
    transport::CancellationSource cancellation_;
};
static_assert(vless::detail::VisionPaddingSize(899, true, 0) == 1);
static_assert(vless::detail::VisionPaddingSize(899, true, 499) == 500);
static_assert(vless::detail::VisionPaddingSize(900, true, 255) == 255);
static_assert(vless::detail::VisionPaddingSize(900, false, 255) == 255);
static_assert(vless::detail::VisionPaddingSize(8170, true, 255) == 1);
static_assert(vless::detail::VisionPaddingSize(8171, true, 255) == 0);
net::awaitable<void> Exercise() {
    const std::array<uint8_t, 16> uuid{};
    const std::array<uint8_t, 6> hello{0x16, 0x03, 0x01, 0, 1, 1};
    const std::array<uint8_t, 9> record{0x17, 0x03, 0x03, 0, 4, 1, 2, 3, 4};
    {
        vless::VisionTrafficState state;
        Capture sink;
        vless::VisionWriter writer(sink, uuid, state);
        std::array<net::const_buffer, 1> buffers{net::buffer(hello)};
        co_await writer.WriteBuffers(buffers);
        auto f = Parse(sink, 0, true);
        Check(f.command == 0 && f.content == 6 && f.padding >= 894 && f.padding <= 1393,
              "ClientHello long padding range");
        sink.bytes.clear();
        // A record prefix is not enough: no padding-end before complete records.
        buffers[0] = net::buffer(record.data(), 6);
        co_await writer.WriteBuffers(buffers);
        f = Parse(sink, 0, false);
        Check(f.command == 0, "partial TLS record prematurely ended padding");
        sink.bytes.clear();
        std::array<net::const_buffer, 2> split{
            net::buffer(record.data(), 6), net::buffer(record.data() + 6, 3)};
        co_await writer.WriteBuffers(split);
        f = Parse(sink, 0, false);
        Check(f.command == 0 && f.content == 6, "batch ended before last fragment");
        auto last = Parse(sink, f.end, false);
        Check(last.command == 1 && last.content == 3 && last.padding <= 255,
              "last fragment did not end padding with short padding");
        sink.bytes.clear();
        buffers[0] = net::buffer(record);
        co_await writer.WriteBuffers(buffers);
        Check(sink.bytes == std::vector<uint8_t>(record.begin(), record.end()), "post-end bytes not raw");
    }
    {
        vless::VisionTrafficState state;
        Capture sink;
        vless::VisionWriter writer(sink, uuid, state);
        const std::array<uint8_t, 1> plain{0x41};
        std::array<net::const_buffer, 7> batch;
        batch.fill(net::buffer(plain));
        co_await writer.WriteBuffers(batch);
        auto first = Parse(sink, 0, true);
        Check(first.command == 1 && sink.bytes.size() == first.end + 6,
              "packet budget must be filtered for the whole batch before padding");
    }
    {
        vless::VisionTrafficState state;
        std::array<uint8_t, 8> false_hello{0, 0, 0x16, 3, 3, 0, 1, 2};
        state.FilterTLS(false_hello);
        Check(!state.is_tls, "embedded handshake prefix misclassified as TLS");
        std::array<uint8_t, 6> other_handshake{0x16, 3, 3, 0, 1, 4};
        state.FilterTLS(other_handshake);
        Check(!state.is_tls, "non-Hello handshake misclassified as TLS");
        const std::array<uint8_t, 6> maximum_length_hello{0x16, 3, 3, 0xff, 0xff, 2};
        state.FilterTLS(maximum_length_hello);
        Check(state.is_tls12_or_above && state.remaining_server_hello == 65534,
              "ServerHello length plus record header wrapped at 65535");
    }
    {
        // Boundary-size short padding must stay in [0,255], also for TLS.
        for (size_t size : {size_t(899), size_t(900), size_t(8170), size_t(8192)}) {
            vless::VisionTrafficState state;
            state.is_tls = state.is_tls12_or_above = true;
            state.packets_to_filter = 0;
            Capture sink;
            vless::VisionWriter writer(sink, uuid, state);
            std::vector<uint8_t> body(size, 0x42);
            std::array<net::const_buffer, 1> buffers{net::buffer(body)};
            co_await writer.WriteBuffers(buffers);
            auto f = Parse(sink, 0, true);
            if (size == 899) Check(f.padding >= 1 && f.padding <= 500, "899-byte long padding");
            else Check(f.padding <= 255, "large-content short padding");
            FragmentReader source(sink.bytes);
            vless::VisionTrafficState read_state;
            vless::VisionReader reader(source, uuid, read_state);
            std::vector<uint8_t> decoded;
            for (;;) {
                auto mb = co_await reader.ReadMultiBuffer();
                if (mb.empty()) break;
                for (auto* b : mb) decoded.insert(decoded.end(), b->Bytes().begin(), b->Bytes().end());
            }
            Check(decoded == body, "one-byte frame fragmentation corrupted content");
        }
    }
    {
        // The opposite direction's classification controls writer padding.
        vless::VisionTrafficState state;
        state.FilterTLS(hello);
        Capture sink;
        vless::VisionWriter writer(sink, uuid, state);
        std::array<net::const_buffer, 1> buffers{net::buffer(record)};
        co_await writer.WriteBuffers(buffers);
        Check(Parse(sink, 0, true).command == 1, "shared TLS state not used by writer");
    }
    for (size_t chunk : {size_t(1), size_t(65536)}) {
        // cmd2 must not switch before all padding is consumed. Prefetched bytes
        // after that frame must precede future raw socket reads.
        std::vector<uint8_t> wire(uuid.begin(), uuid.end());
        wire.insert(wire.end(), {2, 0, 3, 0, 2, 10, 11, 12, 0, 0, 13, 14});
        FragmentReader source(wire, chunk);
        vless::VisionTrafficState state;
        vless::VisionReader reader(source, uuid, state);
        std::vector<uint8_t> decoded;
        for (;;) {
            auto mb = co_await reader.ReadMultiBuffer();
            if (mb.empty()) break;
            for (auto* b : mb) decoded.insert(decoded.end(), b->Bytes().begin(), b->Bytes().end());
        }
        Check(decoded == std::vector<uint8_t>({10, 11, 12, 13, 14}), "direct prefetch ordering");
        Check(source.switched_at >= 26, "raw read switched before padding boundary");
    }
}
}
TEST(VlessVision, Contract) {
    net::io_context io;
    auto result = net::co_spawn(io, Exercise(), net::use_future);
    io.run();
    try { result.get(); } catch (const std::exception& e) { std::cerr << e.what() << '\n'; FAIL() << e.what(); }
}
