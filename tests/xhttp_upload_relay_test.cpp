#include "transport/xhttp_session.hpp"
#include "transport/xhttp_upload_relay.hpp"

#include <gtest/gtest.h>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <exception>
#include <memory>
#include <optional>
#include <string>

namespace {
namespace net = ::net;
using namespace ::transport;
using namespace std::chrono_literals;

// Two Workers' io_contexts driven alternately on the test thread: every
// relay message crosses a real ring and doorbell, without thread timing.
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
    // Relay index of the session Worker, as seen from the upload Worker.
    size_t SessionEndpoint() { return *UploadRelay().EndpointOf(session_io); }

    void Poll() {
        for (auto* io : {&session_io, &upload_io}) {
            if (io->stopped()) io->restart();
            io->poll();
        }
    }

    template <class Predicate>
    bool RunUntil(Predicate predicate, std::chrono::milliseconds limit = 3s) {
        const auto deadline = std::chrono::steady_clock::now() + limit;
        while (!predicate()) {
            if (std::chrono::steady_clock::now() >= deadline) return false;
            Poll();
        }
        return true;
    }

    // Runs the relay for a while without expecting progress.
    void Settle() {
        for (int n = 0; n != 50; ++n) Poll();
    }
};

common::MultiBuffer Bytes(std::string_view text) {
    common::MultiBuffer payload;
    if (!payload.AppendSpan(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(text.data()), text.size()))) {
        throw std::bad_alloc();
    }
    return payload;
}

std::string Text(const common::MultiBuffer& payload) {
    if (payload.empty()) return {};
    const auto bytes = payload.FrontBuffer()->Bytes();
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

// An upload body under test control: chunks, EOF, a read failure, and
// whether the relay cancelled a pending read.
class ScriptedUpload final : public AsyncStream {
public:
    explicit ScriptedUpload(net::io_context& io) : signal_(io.get_executor(), 1) {}

    void Feed(std::string chunk) { chunks_.push_back(std::move(chunk)); Wake(); }
    void End() { ended_ = true; Wake(); }
    void Fail() { failed_ = true; Wake(); }
    [[nodiscard]] bool CancelledRead() const noexcept { return cancelled_read_; }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        for (;;) {
            if (!chunks_.empty()) {
                auto payload = Bytes(chunks_.front());
                chunks_.pop_front();
                co_return payload;
            }
            if (failed_) throw IoSystemError(io_error::connection_reset, "scripted upload failed");
            if (ended_) co_return common::MultiBuffer{};
            const uint64_t epoch = epoch_;
            auto [error] = co_await signal_.async_receive(net::as_tuple(net::use_awaitable));
            (void)error;
            if (epoch != epoch_) {
                cancelled_read_ = true;
                throw IoSystemError(io_error::operation_aborted, "scripted upload cancelled");
            }
        }
    }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer) override {
        throw IoSystemError(io_error::operation_not_supported);
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer) override {
        throw IoSystemError(io_error::operation_not_supported);
    }
    void ShutdownWrite() override {}
    void Cancel() noexcept override {
        ++epoch_;
        Wake();
    }
    void Close() override {}
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }

private:
    void Wake() noexcept { (void)signal_.try_send(IoErrorCode{}); }

    common::SignalChannel signal_;
    std::deque<std::string> chunks_;
    uint64_t epoch_ = 0;
    bool ended_ = false;
    bool failed_ = false;
    bool cancelled_read_ = false;
};

struct SessionReader {
    std::string bytes;
    bool eof = false;
    std::exception_ptr failure;
};

void ReadSession(net::io_context& io, std::shared_ptr<XHttpPacketUpSession> session,
                 SessionReader& reader, size_t limit = SIZE_MAX) {
    net::co_spawn(io, [session, &reader, limit]() -> net::awaitable<void> {
        while (reader.bytes.size() < limit) {
            auto payload = co_await session->ReadMultiBuffer();
            if (payload.empty()) {
                reader.eof = true;
                co_return;
            }
            reader.bytes += Text(payload);
        }
    }, [&reader](std::exception_ptr error) { reader.failure = error; });
}

void SendPacket(WorkerPair& pair, uint64_t token, uint64_t seq, std::string_view text,
                CancellationSource& request, std::optional<XHttpCommit>& result) {
    const size_t owner = pair.SessionEndpoint();
    EXPECT_TRUE(pair.UploadRelay().TryReservePacketBytes(owner, text.size()));
    net::co_spawn(pair.upload_io,
        [&pair, owner, token, seq, payload = Bytes(text), reserved = text.size(),
         &request, &result]() mutable -> net::awaitable<void> {
            result = co_await pair.UploadRelay().SendPacket(
                owner, token, seq, std::move(payload), reserved, request);
        }, net::detached);
}

TEST(XHttpUploadRelay, PacketWaitsForItsSessionThenCommitsOrReportsWhy) {
    WorkerPair pair;
    CancellationSource request;
    auto session = std::make_shared<XHttpPacketUpSession>(pair.session_io);
    const uint64_t token = pair.SessionRelay().ReserveSessionToken();

    // The directory may publish the token before the session exists.
    std::optional<XHttpCommit> early;
    SendPacket(pair, token, 0, "early", request, early);
    pair.Settle();
    EXPECT_FALSE(early) << "a packet for an unbound token was answered";
    pair.SessionRelay().BindSession(token, *session);
    ASSERT_TRUE(pair.RunUntil([&] { return early.has_value(); }));
    EXPECT_EQ(*early, XHttpCommit::Committed);

    SessionReader reader;
    ReadSession(pair.session_io, session, reader, 5);
    ASSERT_TRUE(pair.RunUntil([&] { return reader.bytes.size() >= 5 || reader.failure; }));
    EXPECT_EQ(reader.bytes, "early");

    // Beyond the reorder window: the session refuses the packet.
    std::optional<XHttpCommit> far;
    SendPacket(pair, token, 5000, "far", request, far);
    ASSERT_TRUE(pair.RunUntil([&] { return far.has_value(); }));
    EXPECT_EQ(*far, XHttpCommit::Rejected);

    // An ended session no longer has a token.
    session->Close();
    std::optional<XHttpCommit> late;
    SendPacket(pair, token, 1, "late", request, late);
    ASSERT_TRUE(pair.RunUntil([&] { return late.has_value(); }));
    EXPECT_EQ(*late, XHttpCommit::Missing);

    // Every answered packet returned its budget.
    const size_t owner = pair.SessionEndpoint();
    EXPECT_TRUE(pair.UploadRelay().TryReservePacketBytes(owner, 4 * XHttpPacketQueue::kMaxQueuedBytes));
    pair.UploadRelay().ReleasePacketBytes(owner, 4 * XHttpPacketQueue::kMaxQueuedBytes);
}

TEST(XHttpUploadRelay, StreamCrossesSeveralWindowsInOrderThenEnds) {
    WorkerPair pair;
    auto session = std::make_shared<XHttpPacketUpSession>(pair.session_io);
    const uint64_t token = pair.SessionRelay().ReserveSessionToken();
    pair.SessionRelay().BindSession(token, *session);

    ScriptedUpload upload(pair.upload_io);
    std::string sent;
    for (size_t n = 0; sent.size() < 3 * 1024 * 1024; ++n) {
        std::string chunk(16 * 1024, static_cast<char>('a' + n % 26));
        sent += chunk;
        upload.Feed(std::move(chunk));
    }
    upload.End();
    bool pumped = false;
    std::exception_ptr pump_failure;
    net::co_spawn(pair.upload_io,
        pair.UploadRelay().PumpStream(pair.SessionEndpoint(), token, upload),
        [&](std::exception_ptr error) { pump_failure = error; pumped = true; });

    // Nothing is read yet: the upload stops at its window.
    pair.Settle();
    EXPECT_FALSE(pumped) << "upload ran past the session's window";

    SessionReader reader;
    ReadSession(pair.session_io, session, reader);
    ASSERT_TRUE(pair.RunUntil([&] { return (reader.eof || reader.failure) && pumped; }, 10s));
    EXPECT_FALSE(reader.failure);
    EXPECT_FALSE(pump_failure);
    EXPECT_EQ(reader.bytes.size(), sent.size());
    EXPECT_TRUE(reader.bytes == sent) << "stream bytes reordered or changed";
}

TEST(XHttpUploadRelay, SessionEndStopsTheUploadAndCancelsItsRead) {
    WorkerPair pair;
    auto session = std::make_shared<XHttpPacketUpSession>(pair.session_io);
    const uint64_t token = pair.SessionRelay().ReserveSessionToken();
    pair.SessionRelay().BindSession(token, *session);

    ScriptedUpload upload(pair.upload_io);
    upload.Feed("first");
    bool pumped = false;
    std::exception_ptr pump_failure;
    net::co_spawn(pair.upload_io,
        pair.UploadRelay().PumpStream(pair.SessionEndpoint(), token, upload),
        [&](std::exception_ptr error) { pump_failure = error; pumped = true; });

    SessionReader reader;
    ReadSession(pair.session_io, session, reader, 5);
    ASSERT_TRUE(pair.RunUntil([&] { return reader.bytes.size() >= 5; }));
    EXPECT_EQ(reader.bytes, "first");
    EXPECT_FALSE(pumped);

    session->Close();
    ASSERT_TRUE(pair.RunUntil([&] { return pumped; }));
    EXPECT_FALSE(pump_failure) << "a session ending its upload is not an upload failure";
    EXPECT_TRUE(upload.CancelledRead());
}

TEST(XHttpUploadRelay, UploadFailureAbortsTheSessionRead) {
    WorkerPair pair;
    auto session = std::make_shared<XHttpPacketUpSession>(pair.session_io);
    const uint64_t token = pair.SessionRelay().ReserveSessionToken();
    pair.SessionRelay().BindSession(token, *session);

    ScriptedUpload upload(pair.upload_io);
    upload.Feed("first");
    upload.Fail();
    bool pumped = false;
    std::exception_ptr pump_failure;
    net::co_spawn(pair.upload_io,
        pair.UploadRelay().PumpStream(pair.SessionEndpoint(), token, upload),
        [&](std::exception_ptr error) { pump_failure = error; pumped = true; });

    SessionReader reader;
    ReadSession(pair.session_io, session, reader);
    ASSERT_TRUE(pair.RunUntil([&] { return pumped && (reader.failure || reader.eof); }));
    EXPECT_TRUE(pump_failure);
    EXPECT_EQ(reader.bytes, "first");
    ASSERT_TRUE(reader.failure) << "an aborted upload looked like its end";
    try {
        std::rethrow_exception(reader.failure);
    } catch (const IoSystemError& error) {
        EXPECT_EQ(error.code(), io_error::connection_reset);
    }
}

TEST(XHttpUploadRelay, StreamForUnknownSessionEndsWithoutReading) {
    WorkerPair pair;
    ScriptedUpload upload(pair.upload_io);
    bool pumped = false;
    std::exception_ptr pump_failure;
    // No session ever had this token.
    net::co_spawn(pair.upload_io,
        pair.UploadRelay().PumpStream(pair.SessionEndpoint(), 404, upload),
        [&](std::exception_ptr error) { pump_failure = error; pumped = true; });
    ASSERT_TRUE(pair.RunUntil([&] { return pumped; }));
    EXPECT_FALSE(pump_failure);
    EXPECT_TRUE(upload.CancelledRead());
}

}  // namespace
