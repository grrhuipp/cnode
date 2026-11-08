#pragma once

#include "../../outbound_stream_endpoint.hpp"
#include "../../udp_target.hpp"
#include "../ss_udp.hpp"
#include "common/buf/contiguous_buffer_view.hpp"

#include "common/unsafe.hpp"
#include <array>
#include <optional>

namespace proxy::shadowsocks::outbound {

// One authenticated UDP association, with a fixed proxy next hop. The inner
// packet target is encoded as supplied; only the server name is resolved here.
class UdpRequest final : public ::proxy::OutboundDatagramEndpointBase {
public:
    UdpRequest(net::io_context& io, app::dns::DNS& dns,
               const net::ip::address& bind_address, TargetAddress server,
               const ss::SsCipherInfo& cipher_info, const ss::KeyBytes& master_key,
               std::span<const ss::KeyBytes> psk_chain,
               ForwardedMetadataView forwarded = {})
        : OutboundDatagramEndpointBase(io, bind_address), io_(io), dns_(dns), server_(std::move(server)),
          cipher_info_(cipher_info), master_key_(master_key), psk_chain_(psk_chain) {
        if (!forwarded.Empty()) {
            auto& owned = forwarded_.emplace();
            owned.user_id = forwarded.user_id;
            owned.user_email.assign(forwarded.user_email.data(), forwarded.user_email.size());
            owned.client_ip = forwarded.client_ip;
            owned.inbound_tag.assign(forwarded.inbound_tag.data(), forwarded.inbound_tag.size());
        }
        if (ss::Is2022Cipher(cipher_info_.type)) {
            ss2022_state_.emplace();
            if (!ss::Init2022UdpSessionState(*ss2022_state_, cipher_info_, master_key_))
                throw transport::LinkError(ErrorCode::INTERNAL);
        }
        if (server_.resolved_addr) {
            if (server_.resolved_addr->is_v6() != socket_.IsIPv6())
                throw transport::LinkError(ErrorCode::SOCKET_BIND_FAILED);
            server_endpoint_.emplace(*server_.resolved_addr, server_.port);
        }
    }

    ~UdpRequest() noexcept override {
        ::SecureZeroMemory(master_key_.bytes.data(), master_key_.bytes.size());
        if (ss2022_state_) {
            ::SecureZeroMemory(ss2022_state_->key.bytes.data(),
                                     ss2022_state_->key.bytes.size());
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        // Keep one absolute read budget across unauthenticated or wrong-source
        // packets. Only an authenticated payload is valid receive activity.
        auto read = socket_.StartRead();
        while (true) {
            auto packet = co_await read.Receive();
            if (!server_endpoint_ || packet.source != *server_endpoint_) continue;
            const buf::ContiguousBufferView view(packet.payload);
            const auto bytes = view.Bytes();
            auto decoded = ss2022_state_
                ? ss::Decode2022UdpResponsePacket(bytes.data(), bytes.size(), *ss2022_state_)
                : ss::DecodeUdpPacketWithKey(bytes.data(), bytes.size(), master_key_.span(),
                    cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size);
            if (!decoded) continue;
            ::SecureZeroMemory(decoded->session_owner.bytes.data(),
                                     decoded->session_owner.bytes.size());
            if (!decoded->target.IsValid()) continue;
            socket_.TouchActivity();
            co_return std::move(decoded->payload);
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
        const auto datagram = buf::InspectUdpDatagram(payload);
        if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
        if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid())
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        if (write_closed_) throw transport::WriteClosed{};
        auto write = socket_.StartWrite();
        if (!server_endpoint_) {
            auto& reactor = ExecutionDomain::Current()
                ? ExecutionDomain::Current()->Reactor()
                : io_;
            auto server = co_await ResolveUdpEndpoint(dns_, server_, socket_, write, reactor);
            if (!server) throw transport::LinkError(server.error());
            server_endpoint_ = *server;
        }
        if (write.Cancelled()) throw transport::LinkError(write.CancellationReason());
        const buf::ContiguousBufferView view(payload);
        const auto bytes = view.Bytes();
        const size_t encoded_len = EncodedPacketSize(*datagram.target, bytes);
        const size_t maximum = server_endpoint_->address().is_v6() ? 65527 : 65507;
        if (encoded_len == 0 || encoded_len > maximum)
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        buf::ContiguousWriteBuffer encoded;
        uint8_t* dst = encoded.Prepare(encoded_len);
        if (EncodePacketTo(*datagram.target, bytes, dst, encoded_len) != encoded_len)
            throw transport::LinkError(ErrorCode::INTERNAL);
        const std::array<net::const_buffer, 1> buffers{net::buffer(dst, encoded_len)};
        co_await write.SendTo(*server_endpoint_, buffers);
    }
private:
    size_t EncodedPacketSize(const TargetAddress& target, std::span<const uint8_t> payload) {
        return EncodePacketTo(target, payload, nullptr, 0);
    }
    size_t EncodePacketTo(const TargetAddress& target, std::span<const uint8_t> payload,
                          uint8_t* output, size_t output_size) {
        const ForwardedMetadataView forwarded =
            forwarded_ ? forwarded_->View() : ForwardedMetadataView{};
        if (ss2022_state_)
            return ss::Encode2022UdpRequestPacketTo(target, payload.data(), payload.size(),
                *ss2022_state_, psk_chain_, output, output_size, forwarded);
        return ss::EncodeUdpPacketTo(target, payload.data(), payload.size(), master_key_.span(),
            cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size,
            output, output_size, forwarded);
    }

    net::io_context& io_;
    app::dns::DNS& dns_;
    const TargetAddress server_;
    std::optional<udp::endpoint> server_endpoint_;
    const ss::SsCipherInfo cipher_info_;
    ss::KeyBytes master_key_;
    const std::span<const ss::KeyBytes> psk_chain_;
    std::optional<ForwardedMetadata> forwarded_;
    std::optional<ss::Ss2022UdpSessionState> ss2022_state_;
};

}  // namespace proxy::shadowsocks::outbound
