#include "transport/xhttp_session.hpp"
#include "transport/xhttp_upload_relay.hpp"

#include <gtest/gtest.h>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <deque>
#include <exception>
#include <memory>
#include <string>

namespace {

using namespace ::transport;
using namespace std::chrono_literals;

// Two Workers' io_contexts driven alternately on the test thread: every relay
// message crosses a real ring and doorbell, without thread timing.
struct WorkerPair {
    net::io_context session_io;
    net::io_context upload_io;

    WorkerPair() {
        const std::array<net::io_context*, 2> workers{&session_io, &upload_io};
        common::InstallWorkerMesh<XHttpUploadRelay>(workers);
    }
    ~WorkerPair() {
        common::StopWorkerMesh<XHttpUploadRelay>(session_io);
        common::StopWorkerMesh<XHttpUploadRelay>(upload_io);
        Poll();
    }

    XHttpUploadRelay& SessionRelay() { return *common::FindWorkerMesh<XHttpUploadRelay>(session_io); }
    XHttpUploadRelay& UploadRelay() { return *common::FindWorkerMesh<XHttpUploadRelay>(upload_io); }
    size_t SessionEndpoint() { return *UploadRelay().EndpointOf(session_io); }

    void Poll() {
        for (auto* io : {&session_io, &upload_io}) {
            if (io->stopped()) io->restart();
            io->poll();
        }
    }

    template <class Predicate>
    bool RunUntil(Predicate predicate, std::chrono::milliseconds limit = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + limit;
        while (!predicate()) {
            if (std::chrono::steady_clock::now() >= deadline) return false;
            Poll();
        }
        return true;
    }

    void Settle() {
        for (int n = 0; n != 200; ++n) Poll();
    }
};

// A stream-up body arriving as many tiny reads, each in its own receive
// Buffer, as a client trickling one-byte DATA frames produces.
class TrickleUpload final : public AsyncStream {
public:
    explicit TrickleUpload(size_t reads) : left_(reads) {}

    [[nodiscard]] size_t Left() const noexcept { return left_; }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        if (left_ == 0) co_return common::MultiBuffer{};
        --left_;
        common::BufferGuard buffer{common::Buffer::New()};
        if (!buffer) throw std::bad_alloc();
        buffer->data[0] = static_cast<uint8_t>('a' + left_ % 26);
        buffer->Produce(1);
        co_return common::MultiBuffer{std::move(buffer)};
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
    size_t left_;
};

}  // namespace

// The stream window bounds the memory a remote upload holds on its way to an
// unread session, not just its payload bytes: one-byte reads in full-size
// receive Buffers stop the upload after a window's worth of Buffers.
TEST(XHttpUploadRelayWindow, TinyReadsAreBoundedByTheirBufferStorage) {
    WorkerPair pair;
    auto session = std::make_shared<XHttpPacketUpSession>(pair.session_io);
    const uint64_t token = pair.SessionRelay().ReserveSessionToken();
    pair.SessionRelay().BindSession(token, *session);

    constexpr size_t kReads = 4096;
    TrickleUpload upload(kReads);
    bool pumped = false;
    std::exception_ptr pump_failure;
    net::co_spawn(pair.upload_io,
        pair.UploadRelay().PumpStream(pair.SessionEndpoint(), token, upload),
        [&](std::exception_ptr error) { pump_failure = error; pumped = true; });

    // Nothing is read: at most 1 MiB of Buffers may be in flight.
    pair.Settle();
    EXPECT_FALSE(pumped);
    const size_t in_flight = kReads - upload.Left();
    EXPECT_LE(in_flight * common::Buffer::kSize, size_t{1024 * 1024} + common::Buffer::kSize)
        << in_flight << " one-byte Buffers in flight toward an unread session";

    // The session then reads everything, in order, and the upload ends.
    std::string received;
    bool eof = false;
    std::exception_ptr read_failure;
    net::co_spawn(pair.session_io, [&]() -> net::awaitable<void> {
        for (;;) {
            auto payload = co_await session->ReadMultiBuffer();
            if (payload.empty()) break;
            const auto bytes = payload.FrontBuffer()->Bytes();
            received.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        }
        eof = true;
    }, [&](std::exception_ptr error) { read_failure = error; });
    ASSERT_TRUE(pair.RunUntil([&] { return (eof || read_failure) && pumped; }, 10s));
    EXPECT_FALSE(read_failure);
    EXPECT_FALSE(pump_failure);
    ASSERT_EQ(received.size(), kReads);
    for (size_t n = 0; n != kReads; ++n) {
        ASSERT_EQ(received[n], static_cast<char>('a' + (kReads - 1 - n) % 26)) << "byte " << n;
    }
}
