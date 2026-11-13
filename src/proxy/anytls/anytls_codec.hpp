#pragma once

#include "proxy/outbound_endpoint_base.hpp"
#include "transport/outbound_target_builder.hpp"
#include "app/relay.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/target_address.hpp"
#include <openssl/mem.h>
#include "infra/outbound_types.hpp"
#include "proxy/anytls_padding.hpp"
#include "proxy/inbound.hpp"
#include "proxy/outbound.hpp"
#include <openssl/evp.h>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <vector>

namespace transport {

class AsyncStream;

}  // namespace transport
namespace common {

class AwaitableTaskGroup;

}  // namespace common
namespace app {

struct StatsShard;
struct AdmissionEnvironment;

}  // namespace app
namespace proxy {

[[nodiscard]] inline std::array<uint8_t, 32> HashAnyTlsPassword(std::string_view password) noexcept {
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 0;
    EVP_Digest(password.data(), password.size(), out.data(), &out_len,
               EVP_sha256(), nullptr);
    return out;
}

inline constexpr uint8_t kCmdWaste = 0;
inline constexpr uint8_t kCmdSYN = 1;
inline constexpr uint8_t kCmdPSH = 2;
inline constexpr uint8_t kCmdFIN = 3;
inline constexpr uint8_t kCmdSettings = 4;
inline constexpr uint8_t kCmdAlert = 5;
inline constexpr uint8_t kCmdUpdatePaddingScheme = 6;
inline constexpr uint8_t kCmdSYNACK = 7;
inline constexpr uint8_t kCmdHeartRequest = 8;
inline constexpr uint8_t kCmdHeartResponse = 9;
inline constexpr uint8_t kCmdServerSettings = 10;

inline constexpr size_t kFrameHeaderSize = 7;
inline constexpr size_t kAuthHashSize = 32;
inline constexpr size_t kAuthPrefixSize = kAuthHashSize + sizeof(uint16_t);

inline constexpr uint32_t kProtocolVersion = 2;

enum class SessionVersion : uint8_t { V1 = 1, V2 = 2 };

struct PeerSettings {
    SessionVersion version = SessionVersion::V1;
    std::string_view padding_md5; // Handshake-only metadata view, never retained by a session.
};

[[nodiscard]] tl::expected<PeerSettings, common::ErrorCode> ParsePeerSettings(std::string_view text);

struct AnyTlsFrameHeader {
    uint8_t cmd = 0;
    uint32_t sid = 0;
    uint16_t length = 0;
};

// Write-phase encoding storage. Payloads remain borrowed from the caller's
// MultiBuffer; this object must not move or outlive that write operation.
class FrameBatch {
public:
    FrameBatch() = default;
    FrameBatch(const FrameBatch&) = delete;
    FrameBatch& operator=(const FrameBatch&) = delete;
    [[nodiscard]] tl::expected<void, common::ErrorCode> Encode(
        uint8_t cmd, uint32_t sid, const common::MultiBuffer& payload);
    [[nodiscard]] tl::expected<void, common::ErrorCode> Encode(
        uint8_t cmd, uint32_t sid, std::span<const net::const_buffer> buffers);
    [[nodiscard]] std::span<const net::const_buffer> Buffers() const noexcept {
        return spilled_ ? std::span<const net::const_buffer>(spill_buffers_)
                        : std::span<const net::const_buffer>(buffers_.data(), count_);
    }
private:
    void Begin(size_t frames);
    [[nodiscard]] bool Append(uint8_t cmd, uint32_t sid, std::span<const uint8_t> bytes);

    static constexpr size_t kInlineFrames = common::MultiBuffer::kInlineCapacity;
    std::array<std::array<uint8_t, kFrameHeaderSize>, kInlineFrames> headers_{};
    std::array<net::const_buffer, kInlineFrames * 2> buffers_{};
    std::vector<std::array<uint8_t, kFrameHeaderSize>> spill_headers_;
    std::vector<net::const_buffer> spill_buffers_;
    size_t count_ = 0;
    bool spilled_ = false;
};

[[nodiscard]] std::string ClientSettings(const AnyTlsPaddingScheme& scheme);
[[nodiscard]] tl::expected<void, common::ErrorCode> AppendFrameBytesTo(
    std::vector<uint8_t>& out,
    uint8_t cmd,
    uint32_t sid,
    std::span<const uint8_t> payload);

// Protocol validation and actual I/O errors are values. Non-I/O exceptions
// retain their types for the owning request/session boundary to classify.
net::awaitable<tl::expected<void, common::ErrorCode>>
WriteAll(transport::AsyncStream& stream, std::span<const uint8_t> data);

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteFrame(transport::AsyncStream& stream, uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload);

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteAnyTlsPacketWithPadding(transport::AsyncStream& stream,
                       std::span<const PaddingRecord> record_rules,
                       std::vector<uint8_t> packet);

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteMultiBufferAsFrameBatch(transport::AsyncStream& stream, uint8_t cmd, uint32_t sid, common::MultiBuffer mb);

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteBuffersAsFrameBatch(transport::AsyncStream& stream,
                         uint8_t cmd,
                         uint32_t sid,
                         std::span<const net::const_buffer> buffers);

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteAnyTlsMultiBufferAsFramesWithPadding(transport::AsyncStream& stream,
                                    const AnyTlsPaddingScheme& scheme,
                                    uint32_t packet_index,
                                    uint8_t cmd,
                                    uint32_t sid,
                                    common::MultiBuffer mb);

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteAnyTlsBuffersAsFramesWithPadding(transport::AsyncStream& stream,
                                const AnyTlsPaddingScheme& scheme,
                                uint32_t packet_index,
                                uint8_t cmd,
                                uint32_t sid,
                                std::span<const net::const_buffer> buffers);

net::awaitable<tl::expected<AnyTlsFrameHeader, common::ErrorCode>>
ReadAnyTlsFrameHeader(transport::AsyncStream& stream);

net::awaitable<tl::expected<std::string, common::ErrorCode>>
ReadFrameText(transport::AsyncStream& stream, uint16_t length);

net::awaitable<tl::expected<void, common::ErrorCode>>
DiscardFramePayload(transport::AsyncStream& stream, uint16_t length);

net::awaitable<tl::expected<common::MultiBuffer, common::ErrorCode>>
ReadFramePayload(transport::AsyncStream& stream, uint16_t length);

// ============================================================================
// AnyTlsInboundHandler - AnyTLS inbound proxy
//
// AnyTLS 服务端侧协议处理器：负责 sha256(password) 认证头、
// settings/SYN/PSH/FIN 帧解析，并将单请求 TCP framed stream 交给 dispatcher。
// ============================================================================
class AnyTlsInboundHandler final : public Inbound {
public:
    AnyTlsInboundHandler(const app::AdmissionEnvironment& environment,
            std::shared_ptr<const AnyTlsPaddingScheme> padding_scheme = {});

    net::awaitable<app::RelayResult> Process(
        std::unique_ptr<transport::AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const app::ReceiverSettings& receiver,
        net::io_context& io_context,
        common::Context& ctx,
        const infra::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    const app::AdmissionEnvironment& environment_;
    std::shared_ptr<const AnyTlsPaddingScheme> padding_scheme_;
};
// ============================================================================
// Handler - AnyTLS outbound proxy
//
// AnyTLS 客户端侧协议处理器：负责 TLS 承载连接、sha256(password)
// 认证头、settings/SYN/PSH/FIN 帧、padding scheme、session read loop
// sid demux 和 Xray-core 风格 idle session pool 复用。物理连接经 Handler 的
// OutboundDialer 拨号。
// ============================================================================
class AnyTlsOutboundHandler final : public Outbound {
public:
    // `tasks` accounts and joins physical readers on the Worker thread.
    // Idle sessions are pooled locally; negotiated padding is published to
    // AnyTlsOutboundHandler::padding_ and captured for each new handshake.
    AnyTlsOutboundHandler(std::string_view tag,
            net::io_context& io_context,
            std::shared_ptr<const infra::AnyTlsSettings> settings,
            common::AwaitableTaskGroup& tasks);
    ~AnyTlsOutboundHandler() noexcept override;

    net::awaitable<OutboundProcessResult> Process(
        common::Context& ctx,
        transport::Link inbound,
        transport::OutboundDialer& dialer,
        const infra::TimeoutsConfig& timeouts,
        app::StatsShard& stats,
        const app::RelayConfig& relay_config,
        common::MultiBufferBatch first_payload) override;

private:
    struct ClientSession;
    class SessionPool;
    struct LogicalStreamLease;

    net::awaitable<OutboundProcessResult> ProcessSession(
        common::Context& ctx, transport::Link inbound, transport::OutboundDialer& dialer,
        const infra::TimeoutsConfig& timeouts, app::StatsShard& stats, const app::RelayConfig& relay_config,
        common::MultiBufferBatch first_payload,
        std::shared_ptr<ClientSession> session, bool& reusable);
    std::string tag_;
    std::shared_ptr<const infra::AnyTlsSettings> settings_;
    std::shared_ptr<const AnyTlsPaddingScheme> padding_;
    std::shared_ptr<SessionPool> pool_;
};

}  // namespace proxy
