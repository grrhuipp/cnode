#pragma once

#include "common/asio_types.hpp"
#include "common/multi_buffer.hpp"
#include "common/worker_mesh.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>

namespace app {

class UdpIngress;

// A client endpoint as plain bytes, so it can cross Workers in a ring slot.
struct PackedUdpEndpoint {
    std::array<uint8_t, 16> address{};
    uint32_t scope = 0;
    uint16_t port = 0;
    bool v6 = false;

    [[nodiscard]] static PackedUdpEndpoint From(const udp::endpoint& endpoint) noexcept;
    [[nodiscard]] udp::endpoint Endpoint() const noexcept;
};

enum class UdpRelayKind : uint8_t {
    // Forwarding Worker -> session Worker: one authenticated datagram.
    Datagram,
    // Session Worker -> forwarding Worker: the token names no session.
    Gone,
};

// `payload` is an owned Buffer carrying the datagram's target while in flight.
struct UdpRelayMessage {
    UdpRelayKind kind = UdpRelayKind::Datagram;
    uint64_t token = 0;
    uint64_t packet_id = 0;
    PackedUdpEndpoint client;
    common::Buffer* payload = nullptr;
};

inline void ReleaseWorkerMessage(UdpRelayMessage& message) noexcept {
    common::Buffer::Free(std::exchange(message.payload, nullptr));
}

// One Worker's end of the native UDP session relay. A datagram of a session
// that another Worker runs (an SS2022 client after NAT rebinding) is decoded
// where it arrives and handed to that Worker through the SPSC rings; replies
// leave from the session Worker's own socket of the same listener.
// Every member runs on the owning io_context's thread.
class UdpSessionRelay final {
public:
    using Mesh = common::WorkerMesh<UdpRelayMessage, 256>;

    UdpSessionRelay(net::io_context& io_context, std::shared_ptr<Mesh> mesh, size_t index);
    ~UdpSessionRelay();
    UdpSessionRelay(const UdpSessionRelay&) = delete;
    UdpSessionRelay& operator=(const UdpSessionRelay&) = delete;

    void Stop() noexcept;
    void Shutdown() noexcept;
    [[nodiscard]] uint32_t Index() const noexcept;

    // ---- Session Worker side ----------------------------------------------
    // A token names a session of `ingress` in messages from other Workers.
    [[nodiscard]] uint64_t ReserveToken(UdpIngress& ingress);
    void ReleaseToken(uint64_t token) noexcept;
    void SendGone(uint32_t to, uint64_t token) noexcept;

    // ---- Forwarding Worker side -------------------------------------------
    // `ingress` forwards to session `token` of `owner`; the Gone that ends
    // that session reaches it.
    void AddRoute(uint32_t owner, uint64_t token, UdpIngress& ingress);
    void RemoveRoute(uint32_t owner, uint64_t token) noexcept;
    // Hands one datagram (a single Buffer carrying its target) to session
    // `token` of `owner`. Dropped like any datagram when it cannot be queued.
    void Forward(uint32_t owner, uint64_t token, uint64_t packet_id,
                 const udp::endpoint& client, common::MultiBuffer payload) noexcept;

    void Receive(size_t from, UdpRelayMessage& message) noexcept;

private:
    struct RouteKeyHash {
        [[nodiscard]] size_t operator()(const std::pair<uint32_t, uint64_t>& key) const noexcept;
    };

    std::unordered_map<uint64_t, UdpIngress*> owned_;
    std::unordered_map<std::pair<uint32_t, uint64_t>, UdpIngress*, RouteKeyHash> routes_;
    uint64_t next_token_ = 0;
    // Last: destroyed first, before the maps its receiver touches.
    common::WorkerMeshEndpoint<UdpSessionRelay, UdpRelayMessage, 256> endpoint_;
};

}  // namespace app
