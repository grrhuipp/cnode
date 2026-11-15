#include "app/udp_session_relay.hpp"

#include "app/udp_ingress.hpp"
#include "common/hash.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace app {

PackedUdpEndpoint PackedUdpEndpoint::From(const udp::endpoint& endpoint) noexcept {
    PackedUdpEndpoint packed;
    packed.port = endpoint.port();
    const auto address = endpoint.address();
    if (address.is_v6()) {
        const auto v6 = address.to_v6();
        packed.v6 = true;
        packed.address = v6.to_bytes();
        packed.scope = v6.scope_id();
    } else {
        const auto bytes = address.to_v4().to_bytes();
        std::copy(bytes.begin(), bytes.end(), packed.address.begin());
    }
    return packed;
}

udp::endpoint PackedUdpEndpoint::Endpoint() const noexcept {
    if (v6) return udp::endpoint(net::ip::address_v6(address, scope), port);
    net::ip::address_v4::bytes_type bytes;
    std::copy_n(address.begin(), bytes.size(), bytes.begin());
    return udp::endpoint(net::ip::address_v4(bytes), port);
}

UdpSessionRelay::UdpSessionRelay(net::io_context& io_context,
                                 std::shared_ptr<Mesh> mesh, size_t index)
    : endpoint_(*this, io_context, std::move(mesh), index) {}

UdpSessionRelay::~UdpSessionRelay() = default;

void UdpSessionRelay::Stop() noexcept { endpoint_.Stop(); }

void UdpSessionRelay::Shutdown() noexcept {
    endpoint_.Shutdown();
    owned_.clear();
    routes_.clear();
}

uint32_t UdpSessionRelay::Index() const noexcept {
    return static_cast<uint32_t>(endpoint_.Index());
}

uint64_t UdpSessionRelay::ReserveToken(UdpIngress& ingress) {
    const uint64_t token = ++next_token_;
    owned_.emplace(token, &ingress);
    return token;
}

void UdpSessionRelay::ReleaseToken(uint64_t token) noexcept {
    owned_.erase(token);
    common::MaybeShrinkHashContainer(owned_);
}

void UdpSessionRelay::SendGone(uint32_t to, uint64_t token) noexcept {
    try {
        endpoint_.Post(to, UdpRelayMessage{.kind = UdpRelayKind::Gone, .token = token,
                                           .packet_id = 0, .client = {}, .payload = nullptr});
    } catch (...) {
        // Allocation failure: the forwarder keeps its route until its next
        // datagram draws another Gone.
    }
}

void UdpSessionRelay::AddRoute(uint32_t owner, uint64_t token, UdpIngress& ingress) {
    routes_.insert_or_assign({owner, token}, &ingress);
}

void UdpSessionRelay::RemoveRoute(uint32_t owner, uint64_t token) noexcept {
    routes_.erase({owner, token});
    common::MaybeShrinkHashContainer(routes_);
}

void UdpSessionRelay::Forward(uint32_t owner, uint64_t token, uint64_t packet_id,
                              const udp::endpoint& client, common::MultiBuffer payload) noexcept {
    // Datagrams waiting for ring room toward one Worker; beyond, they drop.
    constexpr size_t kMaxBacklog = 1024;
    if (payload.empty()) return;
    (void)endpoint_.TryPost(owner, UdpRelayMessage{
        .kind = UdpRelayKind::Datagram, .token = token, .packet_id = packet_id,
        .client = PackedUdpEndpoint::From(client), .payload = payload.pop_front().release()},
        kMaxBacklog);
}

void UdpSessionRelay::Receive(size_t from, UdpRelayMessage& message) noexcept {
    const auto source = static_cast<uint32_t>(from);
    switch (message.kind) {
    case UdpRelayKind::Datagram: {
        const auto found = owned_.find(message.token);
        if (found == owned_.end()) {
            SendGone(source, message.token);
            return;
        }
        found->second->ReceiveRelayedDatagram(
            source, message.token, message.packet_id, message.client.Endpoint(),
            common::MultiBuffer{common::BufferGuard{std::exchange(message.payload, nullptr)}});
        return;
    }
    case UdpRelayKind::Gone: {
        const auto found = routes_.find({source, message.token});
        if (found == routes_.end()) return;
        auto* ingress = found->second;
        routes_.erase(found);
        ingress->ForgetRemoteRoute(source, message.token);
        return;
    }
    }
}

}  // namespace app
