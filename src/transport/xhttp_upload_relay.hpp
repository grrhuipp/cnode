#pragma once

#include "common/asio_types.hpp"
#include "common/multi_buffer.hpp"
#include "common/worker_mesh.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace transport {

class XHttpPacketUpSession;

// Outcome of handing a packet-up body to its session.
enum class XHttpCommit : uint8_t {
    Committed,
    // The session no longer exists (HTTP 404).
    Missing,
    // The session refused the packet: queue full or input closed (HTTP 503).
    Rejected,
};

enum class XHttpRelayKind : uint8_t {
    // Upload Worker -> session Worker.
    Packet,
    StreamOpen,
    StreamData,
    StreamEnd,
    StreamAbort,
    // Session Worker -> upload Worker.
    PacketDone,
    StreamCredit,
    StreamClosed,
};

// `payload` is an owned Buffer while in flight.
struct XHttpRelayMessage {
    XHttpRelayKind kind = XHttpRelayKind::Packet;
    XHttpCommit commit = XHttpCommit::Missing;
    uint32_t slot = 0;
    uint32_t generation = 0;
    // Session token (Packet, StreamOpen).
    uint64_t session = 0;
    // Packet sequence (Packet) or returned stream bytes (StreamCredit).
    uint64_t value = 0;
    common::Buffer* payload = nullptr;
};

inline void ReleaseWorkerMessage(XHttpRelayMessage& message) noexcept {
    common::Buffer::Free(std::exchange(message.payload, nullptr));
}

// One Worker's end of the XHTTP upload relay. Workers share nothing but the
// bounded lock-free SPSC rings of the mesh: an upload received on one Worker
// reaches its session on another as messages that transfer buffer ownership.
// Every member runs on the owning io_context's thread.
class XHttpUploadRelay final {
public:
    using Mesh = common::WorkerMesh<XHttpRelayMessage, 256>;

    XHttpUploadRelay(net::io_context& io_context, std::shared_ptr<Mesh> mesh, size_t index);
    ~XHttpUploadRelay();
    XHttpUploadRelay(const XHttpUploadRelay&) = delete;
    XHttpUploadRelay& operator=(const XHttpUploadRelay&) = delete;

    // The Worker stops: no more messages are consumed or accepted, so the
    // relay no longer keeps its io_context running. On the relay's thread.
    void Stop() noexcept;
    // The io_context is shutting down: drops queued messages and detaches
    // this Worker's sessions and streams from the relay.
    void Shutdown() noexcept;

    // Index of the relay endpoint of `owner`, if it has one.
    [[nodiscard]] std::optional<size_t> EndpointOf(const net::io_context& owner) const noexcept;

    // ---- Session Worker side ----------------------------------------------
    // Tokens name this Worker's sessions in messages from other Workers. A
    // token is reserved before the session directory publishes it, so a
    // message may arrive before the session exists; such messages wait until
    // BindSession or ReleaseSessionToken.
    [[nodiscard]] uint64_t ReserveSessionToken();
    void BindSession(uint64_t token, XHttpPacketUpSession& session);
    void ReleaseSessionToken(uint64_t token) noexcept;

    // ---- Upload Worker side -----------------------------------------------
    // Packet bytes read toward `owner` and not yet taken by its session are
    // bounded; TryReservePacketBytes fails while that budget is spent and
    // AwaitPacketBudget waits for a release. AwaitPacketBudget returns false
    // once `cancellation` fires.
    [[nodiscard]] bool TryReservePacketBytes(size_t owner, size_t bytes) noexcept;
    void ReleasePacketBytes(size_t owner, size_t bytes) noexcept;
    [[nodiscard]] net::awaitable<bool> AwaitPacketBudget(
        size_t owner, common::CancellationSource& cancellation);

    // Hands one complete packet to session `token` on `owner`. The `reserved`
    // budget travels with the payload and returns when the session takes it.
    // Missing once `cancellation` fires before the session answers.
    [[nodiscard]] net::awaitable<XHttpCommit> SendPacket(
        size_t owner, uint64_t token, uint64_t seq, common::MultiBuffer payload,
        size_t reserved, common::CancellationSource& cancellation);

    // Streams `upload` into session `token` on `owner` until its EOF, within
    // the window the session grants. Returns once EOF is sent or the session
    // ends the upload; throws on an `upload` read failure, which aborts it.
    net::awaitable<void> PumpStream(size_t owner, uint64_t token, AsyncStream& upload);

private:
    friend class XHttpRemoteUploadStream;
    friend class XHttpPacketUpSession;
    struct State;

    std::unique_ptr<State> state_;
};
}  // namespace transport
