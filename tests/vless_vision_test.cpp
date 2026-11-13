#include <stdexcept>
#include <gtest/gtest.h>

// Wire timing reference: XTLS/Xray-core a4a3dff5b20c2faae567b742c172c7b95e75c083
// proxy/proxy.go: VisionWriter.WriteMultiBuffer, IsCompleteRecord, XtlsPadding.
#include "proxy/vless/vless_codec.hpp"
#include "common/byte_reader.hpp"
#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <algorithm>
#include <array>
#include <vector>

namespace {
class Capture final : public transport::MultiBufferWriter {
public:
    std::vector<uint8_t> bytes;
    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        const auto span = mb.FrontSpan();
        bytes.insert(bytes.end(), span.begin(), span.end());
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
    EXPECT_LE(offset + 5, sink.bytes.size());
    if (offset + 5 > sink.bytes.size()) throw std::runtime_error("missing Vision frame header");
    const auto* p = sink.bytes.data() + offset;
    Frame f{p[0], common::LoadU16BE(p + 1), common::LoadU16BE(p + 3), 0};
    f.end = offset + 5 + f.content + f.padding;
    EXPECT_LE(f.end, sink.bytes.size());
    EXPECT_LE(f.content + f.padding, 8192u - 21u);
    if (f.end > sink.bytes.size()) throw std::runtime_error("truncated Vision frame");
    return f;
}
class FragmentReader final : public transport::MultiBufferReader {
public:
    FragmentReader(const std::vector<uint8_t>& bytes, size_t chunk = 1)
        : bytes_(bytes), chunk_(chunk) {}
    bool EnableRawRead() noexcept override { switched_at = offset_; return true; }
    size_t switched_at = 0;
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        common::MultiBuffer mb;
        if (offset_ < bytes_.size()) {
            const auto n = std::min(chunk_, bytes_.size() - offset_);
            EXPECT_TRUE((mb.AppendSpan(std::span(bytes_).subspan(offset_, n)))) << "allocation";
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
const std::array<uint8_t, 16> uuid{};
const std::array<uint8_t, 6> hello{0x16, 0x03, 0x01, 0, 1, 1};
const std::array<uint8_t, 9> record{0x17, 0x03, 0x03, 0, 4, 1, 2, 3, 4};

net::awaitable<void> EndsPaddingAfterCompleteRecord() {
    {
        proxy::VisionTrafficState state;
        Capture sink;
        proxy::VisionWriter writer(sink, uuid, state);
        std::array<net::const_buffer, 1> buffers{net::buffer(hello)};
        co_await writer.WriteBuffers(buffers);
        auto f = Parse(sink, 0, true);
        EXPECT_TRUE((f.command == 0 && f.content == 6 && f.padding >= 894 && f.padding <= 1393)) << "ClientHello long padding range";
        sink.bytes.clear();
        // A record prefix is not enough: no padding-end before complete records.
        buffers[0] = net::buffer(record.data(), 6);
        co_await writer.WriteBuffers(buffers);
        f = Parse(sink, 0, false);
        EXPECT_EQ(f.command, 0) << "partial TLS record prematurely ended padding";
        sink.bytes.clear();
        std::array<net::const_buffer, 2> split{
            net::buffer(record.data(), 6), net::buffer(record.data() + 6, 3)};
        co_await writer.WriteBuffers(split);
        f = Parse(sink, 0, false);
        EXPECT_TRUE((f.command == 0 && f.content == 6)) << "batch ended before last fragment";
        auto last = Parse(sink, f.end, false);
        EXPECT_TRUE((last.command == 1 && last.content == 3 && last.padding <= 255)) << "last fragment did not end padding with short padding";
        sink.bytes.clear();
        buffers[0] = net::buffer(record);
        co_await writer.WriteBuffers(buffers);
        EXPECT_EQ(sink.bytes, std::vector<uint8_t>(record.begin(), record.end())) << "post-end bytes not raw";
    }
}
net::awaitable<void> FiltersBatchBeforePadding() {
    {
        proxy::VisionTrafficState state;
        Capture sink;
        proxy::VisionWriter writer(sink, uuid, state);
        const std::array<uint8_t, 1> plain{0x41};
        std::array<net::const_buffer, 7> batch;
        batch.fill(net::buffer(plain));
        co_await writer.WriteBuffers(batch);
        auto first = Parse(sink, 0, true);
        EXPECT_TRUE((first.command == 1 && sink.bytes.size() == first.end + 6)) << "packet budget must be filtered for the whole batch before padding";
    }
}
TEST(VlessVision, ClassifiesOnlyHelloPrefixesAndPreservesMaximumRecordLength) {
    {
        proxy::VisionTrafficState state;
        std::array<uint8_t, 8> false_hello{0, 0, 0x16, 3, 3, 0, 1, 2};
        state.FilterTLS(false_hello);
        EXPECT_FALSE(state.is_tls) << "embedded handshake prefix misclassified as TLS";
        std::array<uint8_t, 6> other_handshake{0x16, 3, 3, 0, 1, 4};
        state.FilterTLS(other_handshake);
        EXPECT_FALSE(state.is_tls) << "non-Hello handshake misclassified as TLS";
        const std::array<uint8_t, 6> maximum_length_hello{0x16, 3, 3, 0xff, 0xff, 2};
        state.FilterTLS(maximum_length_hello);
        EXPECT_TRUE((state.is_tls12_or_above && state.remaining_server_hello == 65534)) << "ServerHello length plus record header wrapped at 65535";
    }
}
net::awaitable<void> RecoversFragmentedContent(size_t size) {
    {
        // Boundary-size short padding must stay in [0,255], also for TLS.
        {
            proxy::VisionTrafficState state;
            state.is_tls = state.is_tls12_or_above = true;
            state.packets_to_filter = 0;
            Capture sink;
            proxy::VisionWriter writer(sink, uuid, state);
            std::vector<uint8_t> body(size, 0x42);
            std::array<net::const_buffer, 1> buffers{net::buffer(body)};
            co_await writer.WriteBuffers(buffers);
            auto f = Parse(sink, 0, true);
            if (size == 899) EXPECT_TRUE((f.padding >= 1 && f.padding <= 500)) << "899-byte long padding";
            else EXPECT_LE(f.padding, 255) << "large-content short padding";
            FragmentReader source(sink.bytes);
            proxy::VisionTrafficState read_state;
            proxy::VisionReader reader(source, uuid, read_state);
            std::vector<uint8_t> decoded;
            for (;;) {
                auto mb = co_await reader.ReadMultiBuffer();
                if (mb.empty()) break;
                const auto span = mb.FrontSpan();
                decoded.insert(decoded.end(), span.begin(), span.end());
            }
            EXPECT_EQ(decoded, body) << "one-byte frame fragmentation corrupted content";
        }
    }
}
net::awaitable<void> UsesOppositeDirectionTlsClassification() {
    {
        // The opposite direction's classification controls writer padding.
        proxy::VisionTrafficState state;
        state.FilterTLS(hello);
        Capture sink;
        proxy::VisionWriter writer(sink, uuid, state);
        std::array<net::const_buffer, 1> buffers{net::buffer(record)};
        co_await writer.WriteBuffers(buffers);
        EXPECT_EQ(Parse(sink, 0, true).command, 1) << "shared TLS state not used by writer";
    }
}
net::awaitable<void> SwitchesToRawAfterPadding(size_t chunk) {
    {
        // cmd2 must not switch before all padding is consumed. Prefetched bytes
        // after that frame must precede future raw socket reads.
        std::vector<uint8_t> wire(uuid.begin(), uuid.end());
        wire.insert(wire.end(), {2, 0, 3, 0, 2, 10, 11, 12, 0, 0, 13, 14});
        FragmentReader source(wire, chunk);
        proxy::VisionTrafficState state;
        proxy::VisionReader reader(source, uuid, state);
        std::vector<uint8_t> decoded;
        for (;;) {
            auto mb = co_await reader.ReadMultiBuffer();
            if (mb.empty()) break;
            const auto span = mb.FrontSpan();
            decoded.insert(decoded.end(), span.begin(), span.end());
        }
        EXPECT_EQ(decoded, std::vector<uint8_t>({10, 11, 12, 13, 14})) << "direct prefetch ordering";
        EXPECT_GE(source.switched_at, 26) << "raw read switched before padding boundary";
    }
}
}
TEST(VlessVision, EndsPaddingOnlyAfterCompleteTlsRecordThenWritesRaw) {
    net::io_context io;
    auto result = net::co_spawn(io, EndsPaddingAfterCompleteRecord(), net::use_future);
    io.run();
    result.get();
}
TEST(VlessVision, FiltersWholeBatchBeforeChoosingPadding) {
    net::io_context io;
    auto result = net::co_spawn(io, FiltersBatchBeforePadding(), net::use_future);
    io.run();
    result.get();
}
TEST(VlessVision, WriterUsesOppositeDirectionTlsClassification) {
    net::io_context io;
    auto result = net::co_spawn(io, UsesOppositeDirectionTlsClassification(), net::use_future);
    io.run();
    result.get();
}
namespace {
class VisionContentSize : public testing::TestWithParam<size_t> {};
TEST_P(VisionContentSize, BoundedPaddingAndByteFragmentationPreserveContent) {
    net::io_context io;
    auto result = net::co_spawn(io, RecoversFragmentedContent(GetParam()), net::use_future);
    io.run();
    result.get();
}
INSTANTIATE_TEST_SUITE_P(Boundaries, VisionContentSize,
    testing::Values(size_t(899), size_t(900), size_t(8170), size_t(8192)));
class VisionReadChunk : public testing::TestWithParam<size_t> {};
TEST_P(VisionReadChunk, DirectCommandDrainsPaddingBeforeRawReadAndPreservesPrefetchOrder) {
    net::io_context io;
    auto result = net::co_spawn(io, SwitchesToRawAfterPadding(GetParam()), net::use_future);
    io.run();
    result.get();
}
INSTANTIATE_TEST_SUITE_P(Layouts, VisionReadChunk, testing::Values(size_t(1), size_t(65536)));
}
