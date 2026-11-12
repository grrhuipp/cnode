#include <gtest/gtest.h>

#include "proxy/anytls/anytls_codec.hpp"
#include "transport/async_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <array>
#include <cstdlib>
#include <string>
#include <tuple>
#include <cstring>
#include <stdexcept>
#include <limits>
#include <vector>

namespace {
enum class Fault { None, Memory, Link, Cancelled, Timeout, Reset, Unexpected, NonStandard };

[[noreturn]] void Raise(Fault fault) {
    switch (fault) {
        case Fault::Memory: throw std::bad_alloc();
        case Fault::Link: throw transport::LinkError(common::ErrorCode::BLOCKED);
        case Fault::Cancelled: throw IoSystemError(io_error::operation_aborted);
        case Fault::Timeout: throw IoSystemError(io_error::timed_out);
        case Fault::Reset: throw IoSystemError(io_error::connection_reset);
        case Fault::Unexpected: throw std::runtime_error("codec-test-original-exception");
        case Fault::NonStandard: throw 42;
        default: std::abort();
    }
}

class Stream final : public transport::AsyncStream {
public:
    Fault fault = Fault::None;
    size_t threshold = 0;
    size_t transferred = 0;
    size_t eof_after = std::numeric_limits<size_t>::max();
    size_t failures = 0;
    bool closed = false;
    net::awaitable<void> Fail() {
        if (threshold != 0) co_await net::post(net::use_awaitable);
        ++failures;
        Raise(fault);
    }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (fault != Fault::None && transferred >= threshold) co_await Fail();
        const size_t count = fault == Fault::None
            ? std::min(buffer.size(), eof_after - transferred)
            : std::min(buffer.size(), threshold - transferred);
        std::memset(buffer.data(), 0, count);
        transferred += count;
        co_return count;
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (fault != Fault::None) {
            const size_t count = std::min(buffer.size(), threshold - std::min(threshold, transferred));
            transferred += count;
            if (count < buffer.size()) co_await Fail();
        } else transferred += buffer.size();
        co_return buffer.size();
    }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override { co_return buf::MultiBuffer{}; }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override { closed = true; }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return !closed; }
};

buf::MultiBuffer Payload(size_t count) {
    buf::MultiBuffer result;
    for (size_t i = 0; i < count; ++i) {
        buf::BufferGuard block{buf::Buffer::New()};
        if (!block) throw std::bad_alloc();
        block->Tail()[0] = uint8_t(i);
        block->Produce(1);
        result.push_back(std::move(block));
    }
    return result;
}

template<class T> common::ErrorCode Result(const tl::expected<T, common::ErrorCode>& value) {
    return value ? common::ErrorCode::OK : value.error();
}

net::awaitable<common::ErrorCode> Invoke(Stream& stream, int operation) {
    const proxy::anytls::PaddingScheme no_padding;
    const auto padding = *proxy::anytls::ParsePaddingScheme("stop=2\n1=64-65\n");
    const std::array<uint8_t, 9> bytes{1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::array<net::const_buffer, 9> buffers;
    for (size_t i = 0; i < buffers.size(); ++i) buffers[i] = net::buffer(bytes.data() + i, 1);
    switch (operation) {
        case 0: co_return Result(co_await proxy::anytls::ReadFrameHeader(stream));
        case 1: co_return Result(co_await proxy::anytls::ReadFrameText(stream, 19));
        case 2: co_return Result(co_await proxy::anytls::DiscardFramePayload(stream, 9000));
        case 3: co_return Result(co_await proxy::anytls::ReadFramePayload(stream, 9000));
        case 4: co_return Result(co_await proxy::anytls::WriteAll(stream, bytes));
        case 5: co_return Result(co_await proxy::anytls::WriteFrame(stream, 2, 1, bytes));
        case 6: {
            auto body = Payload(1);
            co_return Result(co_await proxy::anytls::WriteFrame(stream, 2, 1, (*body.begin())->Bytes()));
        }
        case 7: co_return Result(co_await proxy::anytls::WriteMultiBufferAsFrameBatch(stream, 2, 1, Payload(1)));
        case 8: co_return Result(co_await proxy::anytls::WriteMultiBufferAsFrameBatch(stream, 2, 1, Payload(9)));
        case 9: co_return Result(co_await proxy::anytls::WriteMultiBufferAsFramesWithPadding(stream, padding, 1, 2, 1, Payload(9)));
        case 10: co_return Result(co_await proxy::anytls::WriteBuffersAsFramesWithPadding(stream, no_padding, 0, 2, 1, std::span(buffers).first(1)));
        case 11: co_return Result(co_await proxy::anytls::WriteBuffersAsFramesWithPadding(stream, no_padding, 0, 2, 1, buffers));
        case 12: co_return Result(co_await proxy::anytls::WriteBuffersAsFramesWithPadding(stream, padding, 1, 2, 1, buffers));
        case 13: co_return Result(co_await proxy::anytls::WritePacketWithPadding(stream, padding, 1, std::pmr::vector<uint8_t>(bytes.begin(), bytes.end(), memory::process_resource())));
        case 14: co_return Result(co_await proxy::anytls::WritePacketWithPadding(stream, no_padding, 0, std::pmr::vector<uint8_t>(bytes.begin(), bytes.end(), memory::process_resource())));
        case 16: {
            const auto large = *proxy::anytls::ParsePaddingScheme("stop=2\n1=65535-65535,65535-65535\n");
            co_return Result(co_await proxy::anytls::WritePacketWithPadding(stream, large, 1,
                std::pmr::vector<uint8_t>(bytes.begin(), bytes.end(), memory::process_resource())));
        }
        case 17: {
            const auto split = *proxy::anytls::ParsePaddingScheme("stop=2\n1=1-1,7-7,8-8\n");
            co_return Result(co_await proxy::anytls::WritePacketWithPadding(stream, split, 1,
                std::pmr::vector<uint8_t>(bytes.begin(), bytes.end(), memory::process_resource())));
        }
        default: co_return Result(co_await proxy::anytls::WriteMultiBufferAsFramesWithPadding(stream, no_padding, 0, 2, 1, Payload(9)));
    }
}

TEST(AnytlsCodecErrors, FrameBatchReencodesAfterGrowthAndShrink) {
    proxy::anytls::FrameBatch batch;
    for (size_t count : {size_t(1), size_t(9), size_t(1), size_t(0)}) {
        SCOPED_TRACE(count);
        auto payload = Payload(count);
        ASSERT_TRUE(batch.Encode(2, 1, payload));
        const auto buffers = batch.Buffers();
        ASSERT_EQ(buffers.size(), count * 2);
        size_t index = 0;
        for (const auto* block : payload) {
            const auto& header = buffers[index * 2];
            const auto& body = buffers[index * 2 + 1];
            ASSERT_EQ(header.size(), 7);
            const std::array<uint8_t, 7> expected{2, 0, 0, 0, 1, 0, 1};
            EXPECT_EQ(std::memcmp(header.data(), expected.data(), expected.size()), 0);
            ASSERT_EQ(body.size(), 1);
            EXPECT_EQ(*static_cast<const uint8_t*>(body.data()), block->Bytes()[0]);
            ++index;
        }
    }
}

TEST(AnytlsCodecErrors, DeferredBatchOwnsPayloadUntilAwaited) {
    net::io_context io;
    Stream stream;
    auto pending = proxy::anytls::WriteMultiBufferAsFrameBatch(stream, 2, 1, Payload(1));
    EXPECT_EQ(stream.transferred, 0);
    bool returned = false;
    common::ErrorCode code = common::ErrorCode::INTERNAL;
    net::co_spawn(io, std::move(pending), [&](std::exception_ptr error, tl::expected<void, common::ErrorCode> result) {
        returned = error == nullptr;
        code = Result(result);
    });
    EXPECT_EQ(stream.transferred, 0);
    io.run();
    EXPECT_TRUE(returned);
    EXPECT_EQ(code, common::ErrorCode::OK);
    EXPECT_EQ(stream.transferred, proxy::anytls::kFrameHeaderSize + 1);
    EXPECT_EQ(memory::detail::test_buffers_live, 0);
}

void ExerciseOperation(int operation, Fault fault, size_t threshold) {
    net::io_context io;
    Stream stream;
    stream.fault = fault;
    stream.threshold = threshold;
    bool returned = false;
    common::ErrorCode code = common::ErrorCode::INTERNAL;
    Fault observed = Fault::None;
    net::co_spawn(io, Invoke(stream, operation), [&](std::exception_ptr error, common::ErrorCode result) {
        returned = true;
        code = result;
        if (!error) return;
        try { std::rethrow_exception(error); }
        catch (const std::bad_alloc&) { observed = Fault::Memory; }
        catch (const transport::LinkError& e) { if (e.code() == common::ErrorCode::BLOCKED) observed = Fault::Link; }
        catch (const std::runtime_error& e) {
            if (std::string_view(e.what()) == "codec-test-original-exception") observed = Fault::Unexpected;
        }
        catch (int value) { if (value == 42) observed = Fault::NonStandard; }
        catch (...) {}
    });
    io.run();
    const bool read = operation < 4;
    const common::ErrorCode expected = fault == Fault::Cancelled ? common::ErrorCode::CANCELLED
        : fault == Fault::Timeout ? common::ErrorCode::TIMEOUT
        : fault == Fault::Reset ? (read ? common::ErrorCode::SOCKET_READ_FAILED : common::ErrorCode::SOCKET_CLOSED)
        : read && fault == Fault::Memory ? common::ErrorCode::RESOURCE_EXHAUSTED : common::ErrorCode::OK;
    const bool exceptional = (!read && fault == Fault::Memory) || fault == Fault::Link || fault == Fault::Unexpected || fault == Fault::NonStandard;
    ASSERT_TRUE(returned);
    EXPECT_FALSE(stream.closed);
    if (exceptional) {
        EXPECT_EQ(observed, fault);
    } else {
        EXPECT_EQ(observed, Fault::None);
        EXPECT_EQ(code, expected);
    }
    if (fault != Fault::None) {
        EXPECT_EQ(stream.failures, 1);
        EXPECT_EQ(stream.transferred, threshold);
    }
    EXPECT_EQ(memory::detail::test_buffers_live, 0);
}
}

class AnytlsCodecOperation : public testing::TestWithParam<int> {};

TEST_P(AnytlsCodecOperation, CompletesAndReleasesPayload) {
    ExerciseOperation(GetParam(), Fault::None, 0);
}


constexpr std::array operation_names{
    "ReadHeader", "ReadText", "DiscardPayload", "ReadPayload", "WriteAll",
    "WriteFrame", "WriteOwnedFrame", "WriteSingleBatch", "WriteLargeBatch",
    "WritePaddedBatch", "WriteSingleBuffer", "WriteBuffers", "WritePaddedBuffers",
    "WritePaddedPacket", "WritePacket", "WriteUnpaddedBatch", "WriteLargePadding",
    "WriteSplitPadding"};
INSTANTIATE_TEST_SUITE_P(Operations, AnytlsCodecOperation, testing::Range(0, 18),
    [](const testing::TestParamInfo<int>& info) { return operation_names[info.param]; });

class AnytlsCodecFault : public testing::TestWithParam<std::tuple<int, int, size_t>> {};

TEST_P(AnytlsCodecFault, PreservesFailureAndReleasesPayload) {
    const auto [operation, fault, threshold] = GetParam();
    ExerciseOperation(operation, Fault(fault), threshold);
}

INSTANTIATE_TEST_SUITE_P(IoBoundaries, AnytlsCodecFault, testing::Combine(
    testing::Range(0, 18), testing::Range(1, 8), testing::Values(size_t{0}, size_t{3})),
    ([](const testing::TestParamInfo<AnytlsCodecFault::ParamType>& info) {
        const auto [operation, fault, threshold] = info.param;
        return std::string(operation_names[operation]) + "Fault" + std::to_string(fault) +
            "After" + std::to_string(threshold);
    }));

class AnytlsLargePaddingFault : public testing::TestWithParam<int> {};

TEST_P(AnytlsLargePaddingFault, ReleasesPayloadAfterPartialWrite) {
    ExerciseOperation(16, Fault(GetParam()), 65536);
}
INSTANTIATE_TEST_SUITE_P(Faults, AnytlsLargePaddingFault, testing::Range(1, 8));

TEST(AnytlsCodecErrors, HandshakeEofDistinguishesCloseFromTruncation) {
    for (size_t prefix = 0; prefix < proxy::anytls::kFrameHeaderSize; ++prefix) {
        net::io_context io;
        Stream stream;
        stream.eof_after = prefix;
        common::ErrorCode result = common::ErrorCode::INTERNAL;
        std::exception_ptr failure;
        bool has_header = true;
        net::co_spawn(io, proxy::anytls::ReadFrameHeader(stream),
            [&](std::exception_ptr error, tl::expected<proxy::anytls::FrameHeader, common::ErrorCode> header) {
                failure = error;
                has_header = header.has_value();
                if (!header) result = header.error();
            });
        io.run();
        ASSERT_FALSE(failure);
        ASSERT_FALSE(has_header);
        EXPECT_EQ(result, prefix == 0 ? common::ErrorCode::SOCKET_EOF
                                     : common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
}
