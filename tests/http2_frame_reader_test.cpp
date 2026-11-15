#include "transport/h2_frame.hpp"

#include <gtest/gtest.h>

#include <asio/co_spawn.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <exception>
#include <optional>
#include <span>
#include <vector>

namespace {

using namespace ::transport;
using Bytes = std::vector<uint8_t>;

// A connection whose reads are scripted: every step is one received Buffer
// or an aborted read, and past the script the connection is at EOF.
class ScriptedConnection final : public AsyncStream {
public:
    void Receive(std::span<const uint8_t> bytes) {
        script_.emplace_back(Bytes(bytes.begin(), bytes.end()));
    }
    void ReceiveInChunks(std::span<const uint8_t> bytes, size_t chunk) {
        for (size_t offset = 0; offset < bytes.size(); offset += chunk) {
            Receive(bytes.subspan(offset, std::min(chunk, bytes.size() - offset)));
        }
    }
    void AbortRead() { script_.emplace_back(std::nullopt); }

    [[nodiscard]] size_t Reads() const noexcept { return reads_; }
    // The Buffer the latest read handed out, to recognise a payload that took it over.
    [[nodiscard]] const common::Buffer* LastReceived() const noexcept { return last_received_; }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        ++reads_;
        if (script_.empty()) co_return common::MultiBuffer{};
        const auto step = std::move(script_.front());
        script_.pop_front();
        if (!step) throw IoSystemError(io_error::operation_aborted, "scripted read aborted");
        common::MultiBuffer received;
        if (!received.AppendSpan(*step)) throw std::bad_alloc();
        last_received_ = received.FrontBuffer();
        co_return received;
    }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer) override {
        throw IoSystemError(io_error::operation_not_supported);
    }
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer>) override {
        throw IoSystemError(io_error::operation_not_supported);
    }
    void ShutdownWrite() override {}
    void Cancel() noexcept override {}
    void Close() override {}
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }

private:
    std::deque<std::optional<Bytes>> script_;
    const common::Buffer* last_received_ = nullptr;
    size_t reads_ = 0;
};

Bytes Pattern(size_t size, uint8_t seed) {
    Bytes bytes(size);
    for (size_t index = 0; index < size; ++index) {
        bytes[index] = static_cast<uint8_t>(seed + index * 31);
    }
    return bytes;
}

void AppendFrame(Bytes& wire, H2FrameType type, uint8_t flags, uint32_t stream_id,
                 std::span<const uint8_t> payload) {
    const size_t start = wire.size();
    wire.resize(start + kHttp2FrameHeaderSize);
    EncodeH2FrameHeader(
        wire.data() + start, static_cast<uint32_t>(payload.size()), type, flags, stream_id);
    wire.insert(wire.end(), payload.begin(), payload.end());
}

void ExpectFrame(const std::optional<H2Frame>& frame, H2FrameType type, uint8_t flags,
                 uint32_t stream_id, const Bytes& payload) {
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->type, type);
    EXPECT_EQ(frame->flags, flags);
    EXPECT_EQ(frame->stream_id, stream_id);
    const auto actual = frame->Payload();
    EXPECT_TRUE(std::equal(actual.begin(), actual.end(), payload.begin(), payload.end()));
    EXPECT_EQ(frame->buffer_payload != nullptr, payload.size() > H2Frame::kInlinePayloadCapacity);
}

// The reader as a session drives it: buffered frames first, then a read.
net::awaitable<std::optional<H2Frame>> NextFrame(H2FrameReader& reader, AsyncStream& stream) {
    auto frame = reader.TryNext();
    if (!frame) frame = co_await reader.Next(stream);
    co_return frame;
}

// The error a frame read fails with; none when it returns.
net::awaitable<IoErrorCode> ReadFailure(H2FrameReader& reader, AsyncStream& stream) {
    try {
        (void)co_await NextFrame(reader, stream);
    } catch (const IoSystemError& error) {
        co_return error.code();
    }
    co_return IoErrorCode{};
}

template <class Body>
void RunToCompletion(Body body) {
    net::io_context io;
    std::exception_ptr failure;
    net::co_spawn(io, std::move(body),
        [&failure](std::exception_ptr error) { failure = error; });
    io.run();
    if (failure) std::rethrow_exception(failure);
}

TEST(Http2FrameReader, FramesOfOneBufferNeedOneReadAndTheLastPayloadTakesTheBuffer) {
    const Bytes ping = Pattern(8, 1);
    const Bytes shared = Pattern(100, 2);
    const Bytes last = Pattern(200, 3);
    Bytes wire;
    AppendFrame(wire, H2FrameType::PING, kFlagAck, 0, ping);
    AppendFrame(wire, H2FrameType::DATA, 0, 1, shared);
    AppendFrame(wire, H2FrameType::DATA, kFlagEndStream, 3, last);
    ScriptedConnection connection;
    connection.Receive(wire);

    RunToCompletion([&]() -> net::awaitable<void> {
        H2FrameReader reader;
        EXPECT_FALSE(reader.TryNext().has_value());
        auto frame = co_await reader.Next(connection);
        ExpectFrame(frame, H2FrameType::PING, kFlagAck, 0, ping);

        frame = reader.TryNext();
        ExpectFrame(frame, H2FrameType::DATA, 0, 1, shared);
        if (frame) EXPECT_NE(frame->buffer_payload.get(), connection.LastReceived());

        frame = reader.TryNext();
        ExpectFrame(frame, H2FrameType::DATA, kFlagEndStream, 3, last);
        if (frame) EXPECT_EQ(frame->buffer_payload.get(), connection.LastReceived());

        EXPECT_FALSE(reader.TryNext().has_value());
        EXPECT_EQ(connection.Reads(), 1u);
        EXPECT_FALSE((co_await reader.Next(connection)).has_value());
    });
}

class Http2FrameReaderSplit : public testing::TestWithParam<size_t> {};

TEST_P(Http2FrameReaderSplit, FramesSurviveAnySegmentation) {
    const Bytes largest = Pattern(kHttp2MaxFramePayload, 5);
    const Bytes ping = Pattern(8, 6);
    const Bytes headers = Pattern(H2Frame::kInlinePayloadCapacity + 1, 7);
    const Bytes body = Pattern(common::Buffer::kSize, 8);
    Bytes wire;
    AppendFrame(wire, H2FrameType::DATA, 0, 5, largest);
    AppendFrame(wire, H2FrameType::PING, 0, 0, ping);
    AppendFrame(wire, H2FrameType::HEADERS, kFlagEndHeaders, 7, headers);
    AppendFrame(wire, H2FrameType::DATA, kFlagPadded, 7, body);
    AppendFrame(wire, H2FrameType::DATA, kFlagEndStream, 7, {});
    ScriptedConnection connection;
    connection.ReceiveInChunks(wire, GetParam());

    RunToCompletion([&]() -> net::awaitable<void> {
        H2FrameReader reader;
        const auto first = co_await NextFrame(reader, connection);
        ExpectFrame(first, H2FrameType::DATA, 0, 5, largest);
        if (first && GetParam() <= common::Buffer::kSize) {
            // Assembled from smaller Buffers: storage grew with the bytes that
            // arrived and stopped at the frame's size.
            EXPECT_EQ(first->buffer_payload->capacity, kHttp2MaxFramePayload);
        }
        ExpectFrame(co_await NextFrame(reader, connection), H2FrameType::PING, 0, 0, ping);
        ExpectFrame(co_await NextFrame(reader, connection),
                    H2FrameType::HEADERS, kFlagEndHeaders, 7, headers);
        ExpectFrame(co_await NextFrame(reader, connection),
                    H2FrameType::DATA, kFlagPadded, 7, body);
        ExpectFrame(co_await NextFrame(reader, connection),
                    H2FrameType::DATA, kFlagEndStream, 7, {});
        EXPECT_FALSE((co_await NextFrame(reader, connection)).has_value());
    });
}

INSTANTIATE_TEST_SUITE_P(ChunkSizes, Http2FrameReaderSplit, testing::Values(
    size_t{1}, size_t{2}, size_t{8}, size_t{9}, size_t{10}, size_t{73}, size_t{4096},
    size_t{8191}, size_t{8192}, size_t{8201}, size_t{16393}, size_t{64 * 1024}));

TEST(Http2FrameReader, EofIsCleanOnlyAtAFrameBoundary) {
    Bytes wire;
    AppendFrame(wire, H2FrameType::DATA, 0, 1, Pattern(100, 9));
    const std::span<const uint8_t> frame(wire);
    const std::array<size_t, 4> truncations{
        1, kHttp2FrameHeaderSize - 1, kHttp2FrameHeaderSize, wire.size() - 1};

    RunToCompletion([&]() -> net::awaitable<void> {
        {
            ScriptedConnection connection;
            connection.Receive(frame);
            H2FrameReader reader;
            EXPECT_TRUE((co_await NextFrame(reader, connection)).has_value());
            EXPECT_FALSE((co_await NextFrame(reader, connection)).has_value());
        }
        for (const size_t truncated : truncations) {
            ScriptedConnection connection;
            connection.Receive(frame.first(truncated));
            H2FrameReader reader;
            EXPECT_EQ(co_await ReadFailure(reader, connection), io_error::connection_reset)
                << "frame truncated after " << truncated << " octets";
        }
    });
}

TEST(Http2FrameReader, AbortedReadTearsOnlyAnIncompleteFrame) {
    const Bytes payload = Pattern(100, 10);
    Bytes wire;
    AppendFrame(wire, H2FrameType::DATA, 0, 1, payload);
    const std::span<const uint8_t> frame(wire);
    const std::array<size_t, 3> interruptions{1, kHttp2FrameHeaderSize, wire.size() - 1};

    RunToCompletion([&]() -> net::awaitable<void> {
        {
            // Between frames nothing is torn: the read can be retried.
            ScriptedConnection connection;
            connection.AbortRead();
            connection.Receive(frame);
            H2FrameReader reader;
            EXPECT_EQ(co_await ReadFailure(reader, connection), io_error::operation_aborted);
            ExpectFrame(co_await NextFrame(reader, connection), H2FrameType::DATA, 0, 1, payload);
        }
        for (const size_t received : interruptions) {
            ScriptedConnection connection;
            connection.Receive(frame.first(received));
            connection.AbortRead();
            H2FrameReader reader;
            EXPECT_EQ(co_await ReadFailure(reader, connection), io_error::connection_reset)
                << "read aborted after " << received << " octets of a frame";
        }
    });
}

TEST(Http2FrameReader, FrameBeyondTheReceiveLimitFailsBeforeItsPayload) {
    Bytes header(kHttp2FrameHeaderSize);
    EncodeH2FrameHeader(header.data(), static_cast<uint32_t>(kHttp2MaxFramePayload + 1),
                        H2FrameType::DATA, 0, 1);
    ScriptedConnection connection;
    connection.Receive(header);

    RunToCompletion([&]() -> net::awaitable<void> {
        H2FrameReader reader;
        EXPECT_EQ(co_await ReadFailure(reader, connection), io_error::message_size);
        EXPECT_EQ(connection.Reads(), 1u);
    });
}

TEST(Http2FrameReader, ClearDropsBufferedFramesAndTheFrameUnderAssembly) {
    Bytes wire;
    AppendFrame(wire, H2FrameType::PING, 0, 0, Pattern(8, 11));
    AppendFrame(wire, H2FrameType::DATA, 0, 1, Pattern(100, 12));
    AppendFrame(wire, H2FrameType::DATA, 0, 1, Pattern(300, 13));
    const std::span<const uint8_t> frames(wire);

    RunToCompletion([&]() -> net::awaitable<void> {
        {
            ScriptedConnection connection;
            connection.Receive(frames);
            H2FrameReader reader;
            EXPECT_TRUE((co_await NextFrame(reader, connection)).has_value());
            reader.Clear();
            EXPECT_FALSE(reader.TryNext().has_value());
        }
        {
            ScriptedConnection connection;
            connection.Receive(frames.first(frames.size() - 1));
            H2FrameReader reader;
            EXPECT_TRUE((co_await NextFrame(reader, connection)).has_value());
            EXPECT_TRUE(reader.TryNext().has_value());
            EXPECT_FALSE(reader.TryNext().has_value());
            reader.Clear();
            // Nothing is left of the incomplete frame: EOF is at a boundary again.
            EXPECT_FALSE((co_await reader.Next(connection)).has_value());
        }
    });
}

}  // namespace
