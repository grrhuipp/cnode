#pragma once

#include "app/session_owner_directory.hpp"
#include "common/asio_types.hpp"
#include "common/multi_buffer.hpp"
#include "common/worker_mesh.hpp"
#include "transport/link.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

namespace app {
struct AdmissionEnvironment;
struct StatsShard;
}  // namespace app
namespace common {
struct Context;
}  // namespace common
namespace infra {
struct TimeoutsConfig;
}  // namespace infra
namespace routing {
class Dispatcher;
struct DispatchPolicy;
}  // namespace routing

namespace proxy {

// XUDP (Xray common/mux): a UDP Mux.Cool sub-session carrying a non-zero
// Global ID names one UDP flow that outlives its Mux connection. A later
// sub-session with the same Global ID, on any connection and any Worker,
// takes the flow over: same outbound, same dispatch. A flow left without a
// sub-session ends after kXudpExpiry.
inline constexpr auto kXudpExpiry = std::chrono::minutes(1);

using XudpGlobalId = std::array<uint8_t, 8>;

// The Mux sub-session side of an XUDP attachment on this Worker. Implemented
// by the Mux server's UDP sub-session.
class XudpClient {
public:
    // Queues one reply datagram toward the client; false once it takes no more.
    bool PushReply(common::MultiBuffer datagram);
    // The flow left this sub-session (taken over or ended): it ends.
    void Release() noexcept;

protected:
    XudpClient() = default;
    ~XudpClient() = default;
};

class XudpSession;

enum class XudpRelayKind : uint8_t {
    // Client Worker -> flow Worker.
    Attach,
    Uplink,
    Detach,
    // Flow Worker -> client Worker.
    Attached,
    Reply,
    Detached,
};

// `payload` is an owned Buffer carrying its UDP endpoint while in flight.
struct XudpRelayMessage {
    XudpRelayKind kind = XudpRelayKind::Attach;
    // Detached: the token named no flow, so the client may claim anew.
    bool refused = false;
    uint32_t slot = 0;
    uint32_t generation = 0;
    uint64_t token = 0;
    common::Buffer* payload = nullptr;
};

inline void ReleaseWorkerMessage(XudpRelayMessage& message) noexcept {
    common::Buffer::Free(std::exchange(message.payload, nullptr));
}

// One Worker's end of the XUDP relay: attaches Mux sub-sessions of this
// Worker to flows of other Workers, and serves this Worker's flows to theirs.
// Every member runs on the owning io_context's thread.
class XudpRelay final {
public:
    using Mesh = common::WorkerMesh<XudpRelayMessage, 256>;

    XudpRelay(net::io_context& io_context, std::shared_ptr<Mesh> mesh, size_t index);
    ~XudpRelay();
    XudpRelay(const XudpRelay&) = delete;
    XudpRelay& operator=(const XudpRelay&) = delete;

    void Stop() noexcept;
    void Shutdown() noexcept;
    [[nodiscard]] uint32_t Index() const noexcept;

    // ---- Flow Worker side --------------------------------------------------
    [[nodiscard]] uint64_t ReserveToken(XudpSession& session);
    void ReleaseToken(uint64_t token) noexcept;
    void BindAttachment(uint32_t from, uint32_t slot, uint32_t generation, XudpSession& session);
    void ForgetAttachment(uint32_t from, uint32_t slot, uint32_t generation) noexcept;
    void SendAttached(uint32_t to, uint32_t slot, uint32_t generation) noexcept;
    void SendReply(uint32_t to, uint32_t slot, uint32_t generation,
                   common::MultiBuffer datagram) noexcept;
    void SendDetached(uint32_t to, uint32_t slot, uint32_t generation, bool refused) noexcept;

    // ---- Client Worker side ------------------------------------------------
    struct Attachment {
        uint32_t owner = 0;
        uint32_t slot = 0;
        uint32_t generation = 0;
    };
    // Asks flow `token` of `owner` to take `client`.
    [[nodiscard]] Attachment Open(uint32_t owner, uint64_t token, XudpClient& client);
    // True once the flow took the attachment; false when it refused it or
    // `cancellation` (the sub-session's) fired first.
    [[nodiscard]] net::awaitable<bool> AwaitAttached(
        const Attachment& attachment, transport::CancellationSource& cancellation);
    void SendUplink(const Attachment& attachment, common::MultiBuffer datagram) noexcept;
    // The sub-session ends: tells the flow Worker unless it detached first.
    void Close(const Attachment& attachment) noexcept;

    void Receive(size_t from, XudpRelayMessage& message) noexcept;

private:
    struct ClientSlot {
        uint32_t generation = 0;
        bool busy = false;
        bool attached = false;
        bool detached = false;
        bool refused = false;
        XudpClient* client = nullptr;
        // Frame-local channel of a coroutine waiting for the acknowledgement.
        common::SignalChannel* wake = nullptr;
    };
    struct AttachmentKey {
        uint32_t from;
        uint32_t slot;
        uint32_t generation;
        bool operator==(const AttachmentKey&) const = default;
    };
    struct AttachmentKeyHash {
        [[nodiscard]] size_t operator()(const AttachmentKey& key) const noexcept;
    };

    void ReceiveAttach(uint32_t from, const XudpRelayMessage& message);
    [[nodiscard]] ClientSlot* SlotFor(uint32_t slot, uint32_t generation) noexcept;

    std::unordered_map<uint64_t, XudpSession*> tokens_;
    std::unordered_map<AttachmentKey, XudpSession*, AttachmentKeyHash> attachments_;
    std::deque<ClientSlot> slots_;
    std::vector<uint32_t> free_slots_;
    uint64_t next_token_ = 0;
    // Last: destroyed first, before the maps its receiver touches.
    common::WorkerMeshEndpoint<XudpRelay, XudpRelayMessage, 256> endpoint_;

    friend class XudpSession;
};

// What a flow started by a sub-session dispatches with: the sub-session's
// Worker runtime, which outlives every flow it runs.
struct XudpDispatchEnvironment {
    net::io_context& io_context;
    routing::Dispatcher& dispatcher;
    const routing::DispatchPolicy& policy;
    const app::AdmissionEnvironment& admission;
    app::StatsShard& stats;
    const infra::TimeoutsConfig& timeouts;
};

// Carries one UDP sub-session that holds Global ID `global_id`: attaches it
// to the flow of that ID wherever the flow runs, starting the flow here when
// none runs. Returns when the sub-session ends or the flow leaves it; false
// when no flow can take it (the Worker is full or stopping), so the caller
// dispatches it as a plain UDP sub-session.
[[nodiscard]] net::awaitable<bool> RunXudpSubSession(
    const XudpDispatchEnvironment& environment, common::Context& sub_ctx,
    XudpGlobalId global_id, XudpClient& client, transport::MultiBufferReader& uplink);

// Worker shutdown: ends every flow of `io_context`, then joins them.
void StopXudpSessions(net::io_context& io_context) noexcept;
[[nodiscard]] net::awaitable<void> JoinXudpSessions(net::io_context& io_context);

}  // namespace proxy
