#pragma once

#include "../../udp_target.hpp"
#include "../ss_udp.hpp"
#include "acppnode/common/buf/contiguous_buffer_view.hpp"

#include <array>
#include <optional>

namespace acpp::proxy::shadowsocks::outbound {

// One authenticated UDP association, with a fixed proxy next hop. The inner
// packet target is encoded as supplied; only the server name is resolved here.
class UdpRequest final {
public:
    UdpRequest(net::io_context& io, app::dns::DNS& dns,
               const net::ip::address& bind_address, TargetAddress server,
               const ss::SsCipherInfo& cipher_info, const ss::KeyBytes& master_key,
               std::span<const ss::KeyBytes> psk_chain)
        : io_(io), dns_(dns), socket_(io, bind_address), server_(std::move(server)),
          cipher_info_(cipher_info), master_key_(master_key), psk_chain_(psk_chain) {
        if (ss::Is2022Cipher(cipher_info_)) {
            ss2022_state_.emplace();
            if (!ss::Init2022UdpSessionState(*ss2022_state_, cipher_info_, master_key_))
                throw transport::LinkError(ErrorCode::INTERNAL);
        }
        if (server_.resolved_addr)
            server_endpoint_.emplace(*server_.resolved_addr, server_.port);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() {
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
            if (!decoded || !buf::HasData(decoded->payload)) continue;
            for (auto* buffer : decoded->payload) buffer->SetUDP(decoded->target);
            socket_.TouchActivity();
            co_return std::move(decoded->payload);
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) {
        const auto datagram = buf::InspectUdpDatagram(payload);
        if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
        if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid())
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        if (write_closed_) throw transport::WriteClosed{};
        auto write = socket_.StartWrite();
        if (!server_endpoint_) {
            auto server = co_await ResolveUdpEndpoint(dns_, server_, socket_, write, io_);
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
        if (encoded_len <= buf::Buffer::kSize) {
            buf::BufferGuard encoded{buf::Buffer::New()};
            if (!encoded) throw std::bad_alloc();
            if (EncodePacketTo(*datagram.target, bytes, encoded->Tail().data(), encoded->Available()) != encoded_len)
                throw transport::LinkError(ErrorCode::INTERNAL);
            const std::array<net::const_buffer, 1> buffers{net::buffer(encoded->Tail().data(), encoded_len)};
            co_await write.SendTo(*server_endpoint_, buffers);
        } else {
            // Encryption requires contiguous output. Send that stage-owned
            // output directly instead of copying it through another endpoint.
            memory::ByteVector encoded(encoded_len);
            if (EncodePacketTo(*datagram.target, bytes, encoded.data(), encoded.size()) != encoded_len)
                throw transport::LinkError(ErrorCode::INTERNAL);
            const std::array<net::const_buffer, 1> buffers{net::buffer(encoded.data(), encoded.size())};
            co_await write.SendTo(*server_endpoint_, buffers);
        }
    }

    net::awaitable<void> AsyncShutdownWrite() { write_closed_ = true; co_return; }
    void Cancel() noexcept { socket_.Cancel(); }
    void Close() noexcept { socket_.Close(); }
    transport::CancellationSource& Cancellation() noexcept { return socket_.Cancellation(); }
    void SetIdleTimeout(std::chrono::seconds value) { socket_.SetIdleTimeout(value); }
    void SetReadTimeout(std::chrono::seconds value) { socket_.SetReadTimeout(value); }
    void SetWriteTimeout(std::chrono::seconds value) { socket_.SetWriteTimeout(value); }
    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds value) { return socket_.StartPhaseDeadline(value); }
    void ClearPhaseDeadline() noexcept { socket_.ClearPhaseDeadline(); }
    bool ConsumeIdleTimeout() noexcept { return socket_.ConsumeIdleTimeout(); }
    bool ConsumeReadTimeout() noexcept { return socket_.ConsumeReadTimeout(); }
    bool ConsumeWriteTimeout() noexcept { return socket_.ConsumeWriteTimeout(); }
    bool ConsumePhaseDeadline() noexcept { return socket_.ConsumePhaseDeadline(); }

private:
    size_t EncodedPacketSize(const TargetAddress& target, std::span<const uint8_t> payload) {
        return EncodePacketTo(target, payload, nullptr, 0);
    }
    size_t EncodePacketTo(const TargetAddress& target, std::span<const uint8_t> payload,
                          uint8_t* output, size_t output_size) {
        if (ss2022_state_)
            return ss::Encode2022UdpRequestPacketTo(target, payload.data(), payload.size(),
                *ss2022_state_, psk_chain_, output, output_size);
        return ss::EncodeUdpPacketTo(target, payload.data(), payload.size(), master_key_.span(),
            cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size, output, output_size);
    }

    net::io_context& io_;
    app::dns::DNS& dns_;
    transport::internet::DatagramSocket socket_;
    const TargetAddress server_;
    std::optional<udp::endpoint> server_endpoint_;
    const ss::SsCipherInfo cipher_info_;
    const ss::KeyBytes master_key_;
    const std::span<const ss::KeyBytes> psk_chain_;
    std::optional<ss::Ss2022UdpSessionState> ss2022_state_;
    bool write_closed_ = false;
};

}  // namespace acpp::proxy::shadowsocks::outbound
