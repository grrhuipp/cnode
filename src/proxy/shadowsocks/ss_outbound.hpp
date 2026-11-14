#pragma once

#include "proxy/outbound_stream_endpoint.hpp"
#include "proxy/outbound_endpoint_base.hpp"
#include "app/relay.hpp"
#include "proxy/uot/uot.hpp"
#include "app/user_store.hpp"
#include "common/multi_buffer.hpp"
#include "common/user_online_tracker.hpp"
#include "common/target_address.hpp"
#include <openssl/mem.h>
#include "proxy/inbound.hpp"
#include "proxy/outbound.hpp"
#include "proxy/shadowsocks/shadowsocks_protocol.hpp"
#include "proxy/shadowsocks/ss_stream.hpp"
#include "transport/async_stream.hpp"
#include "transport/outbound_target_builder.hpp"
#include "transport/link.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>
#include <vector>

#include "proxy/shadowsocks/ss_udp.hpp"
#include "proxy/udp_datagram_frame.hpp"
// ============================================================================
// SS Outbound 配置
// ============================================================================
namespace proxy {

struct SsOutboundConfig {
    transport::OutboundServer server;
    std::optional<proxy::UotVersion> uot_version;
};

}  // namespace proxy

// ============================================================================
// SsOutbound — 出站编排（握手、初始 payload、relay、收尾）
// 协议加密状态由 shadowsocks_protocol.cpp 承担。
// ============================================================================
namespace proxy {

// One authenticated UDP association, with a fixed proxy next hop. The inner
// packet target is encoded as supplied; only the server name is resolved here.
class SsUdpRequest final : public ::proxy::OutboundDatagramEndpointBase {
public:
    SsUdpRequest(net::io_context& io, app::DNS& dns,
               const net::ip::address& bind_address, common::TargetAddress server,
               const proxy::SsCipherInfo& cipher_info, const proxy::KeyBytes& master_key,
               std::span<const proxy::KeyBytes> psk_chain,
               common::ForwardedMetadataView forwarded = {})
        : OutboundDatagramEndpointBase(io, bind_address), dns_(dns), server_(std::move(server)),
          cipher_info_(cipher_info), master_key_(master_key), psk_chain_(psk_chain) {
        forwarded_ = common::ForwardedMetadata::FromView(forwarded);
        if (proxy::Is2022Cipher(cipher_info_.type)) {
            ss2022_state_.emplace();
            if (!proxy::Init2022UdpSessionState(*ss2022_state_, cipher_info_, master_key_))
                throw transport::LinkError(common::ErrorCode::INTERNAL);
        }
        if (server_.resolved_addr) {
            if (server_.resolved_addr->is_v6() != socket_.IsIPv6())
                throw transport::LinkError(common::ErrorCode::SOCKET_BIND_FAILED);
            server_endpoint_.emplace(*server_.resolved_addr, server_.port);
        }
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        // Keep one absolute read budget across unauthenticated or wrong-source
        // packets. Only an authenticated payload is valid receive activity.
        auto read = socket_.StartRead();
        while (true) {
            auto packet = co_await read.Receive();
            if (!server_endpoint_ || packet.source != *server_endpoint_) continue;
            const auto bytes = packet.payload.FrontSpan();
            auto decoded = ss2022_state_
                ? proxy::Decode2022UdpResponsePacket(bytes.data(), bytes.size(), *ss2022_state_)
                : proxy::DecodeUdpPacketWithKey(bytes.data(), bytes.size(), master_key_.span(),
                    cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size);
            if (!decoded) continue;
            if (!decoded->target.IsValid()) continue;
            socket_.TouchActivity();
            co_return std::move(decoded->payload);
        }
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer payload) override {
        const auto datagram = proxy::RequireUdpDatagram(payload, nullptr);
        if (!datagram) co_return;
        if (write_closed_) throw transport::WriteClosed{};
        auto write = socket_.StartWrite();
        if (!server_endpoint_) {
            auto server = co_await ResolveUdpEndpoint(dns_, server_, socket_, write);
            if (!server) throw transport::LinkError(server.error());
            server_endpoint_ = *server;
        }
        if (write.Cancelled()) throw transport::LinkError(write.CancellationReason());
        const auto bytes = payload.FrontSpan();
        const size_t encoded_len = EncodedPacketSize(*datagram->target, bytes);
        const size_t maximum = server_endpoint_->address().is_v6() ? 65527 : 65507;
        if (encoded_len == 0 || encoded_len > maximum)
            throw transport::LinkError(common::ErrorCode::INVALID_ARGUMENT);
        common::BufferGuard encoded{common::Buffer::New(encoded_len)};
        if (!encoded) throw std::bad_alloc();
        if (EncodePacketTo(*datagram->target, bytes, encoded->Tail().data(), encoded_len) != encoded_len)
            throw transport::LinkError(common::ErrorCode::INTERNAL);
        encoded->Produce(encoded_len);
        payload.clear();
        co_await write.SendTo(*server_endpoint_, common::MultiBuffer{std::move(encoded)});
    }
private:
    size_t EncodedPacketSize(const common::TargetAddress& target, std::span<const uint8_t> payload) {
        return EncodePacketTo(target, payload, nullptr, 0);
    }
    size_t EncodePacketTo(const common::TargetAddress& target, std::span<const uint8_t> payload,
                          uint8_t* output, size_t output_size) {
        const common::ForwardedMetadataView forwarded =
            forwarded_ ? forwarded_->View() : common::ForwardedMetadataView{};
        if (ss2022_state_)
            return proxy::Encode2022UdpRequestPacketTo(target, payload.data(), payload.size(),
                *ss2022_state_, psk_chain_, output, output_size, forwarded);
        return proxy::EncodeUdpPacketTo(target, payload.data(), payload.size(), master_key_.span(),
            cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size,
            output, output_size, forwarded);
    }

    app::DNS& dns_;
    const common::TargetAddress server_;
    std::optional<udp::endpoint> server_endpoint_;
    const proxy::SsCipherInfo cipher_info_;
    proxy::KeyBytes master_key_;
    const std::span<const proxy::KeyBytes> psk_chain_;
    std::optional<common::ForwardedMetadata> forwarded_;
    std::optional<proxy::Ss2022UdpSessionState> ss2022_state_;
};

// A complete, validated credential value. Preparation never drops a chain link
// or substitutes a different cipher; Worker handlers only consume this value.
class SsCredentials {
public:
    [[nodiscard]] static std::optional<SsCredentials> Prepare(
        const proxy::SsCipherInfo& cipher, std::string_view password);

    [[nodiscard]] const proxy::SsCipherInfo& Cipher() const noexcept { return cipher_; }
    [[nodiscard]] const proxy::KeyBytes& MasterKey() const noexcept { return master_key_; }
    [[nodiscard]] std::span<const proxy::KeyBytes> PskChain() const noexcept {
        return psk_chain_;
    }

private:
    SsCredentials(proxy::SsCipherInfo cipher, proxy::KeyBytes master_key,
                std::vector<proxy::KeyBytes> psk_chain)
        : cipher_(cipher), master_key_(master_key), psk_chain_(std::move(psk_chain)) {}

    proxy::SsCipherInfo cipher_;
    proxy::KeyBytes master_key_;
    std::vector<proxy::KeyBytes> psk_chain_;
};


struct SsPreparedSettings {
    SsOutboundConfig config;
    SsCredentials credentials;
};

struct WriteTCPRequestResult {
    SsStreamWriter request_writer;
    KeyBytes request_salt;
};

[[nodiscard]] net::awaitable<tl::expected<WriteTCPRequestResult, common::ErrorCode>>
WriteTCPRequest(const common::TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                std::span<const KeyBytes> psk_chain,
                transport::AsyncStream& stream,
                common::ForwardedMetadataView forwarded = {});

struct ReadTCPResponseResult {
    BodyReader reader;
    common::MultiBuffer initial_payload;
};

[[nodiscard]] net::awaitable<tl::expected<ReadTCPResponseResult, common::ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                const KeyBytes& request_salt,
                transport::AsyncStream& stream);
}  // namespace proxy
