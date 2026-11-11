#pragma once

#include "proxy/outbound_endpoint_base.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "app/relay.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/target_address.hpp"
#include <openssl/mem.h>
#include "infra/json.hpp"
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

class AsyncStream;
class AwaitableTaskGroup;
struct StatsShard;
namespace anytls {

[[nodiscard]] inline std::array<uint8_t, 32> PasswordHash(std::string_view password) noexcept {
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

[[nodiscard]] tl::expected<PeerSettings, ErrorCode> ParsePeerSettings(std::string_view text);

struct FrameHeader {
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
    [[nodiscard]] tl::expected<void, ErrorCode> Encode(
        uint8_t cmd, uint32_t sid, const buf::MultiBuffer& payload);
    [[nodiscard]] tl::expected<void, ErrorCode> Encode(
        uint8_t cmd, uint32_t sid, std::span<const net::const_buffer> buffers);
    [[nodiscard]] std::span<const net::const_buffer> Buffers() const noexcept {
        return spilled_ ? std::span<const net::const_buffer>(spill_buffers_)
                        : std::span<const net::const_buffer>(buffers_.data(), count_);
    }
private:
    void Begin(size_t frames);
    [[nodiscard]] bool Append(uint8_t cmd, uint32_t sid, std::span<const uint8_t> bytes);

    static constexpr size_t kInlineFrames = buf::MultiBuffer::kInlineCapacity;
    std::array<std::array<uint8_t, kFrameHeaderSize>, kInlineFrames> headers_{};
    std::array<net::const_buffer, kInlineFrames * 2> buffers_{};
    memory::Vector<std::array<uint8_t, kFrameHeaderSize>> spill_headers_;
    memory::Vector<net::const_buffer> spill_buffers_;
    size_t count_ = 0;
    bool spilled_ = false;
};

[[nodiscard]] memory::String ClientSettings(const PaddingScheme& scheme);
[[nodiscard]] tl::expected<void, ErrorCode> AppendFrameBytesTo(
    memory::ByteVector& out,
    uint8_t cmd,
    uint32_t sid,
    std::span<const uint8_t> payload);

// Protocol validation and actual I/O errors are values. Non-I/O exceptions
// retain their types for the owning request/session boundary to classify.
net::awaitable<tl::expected<void, ErrorCode>>
WriteAll(AsyncStream& stream, std::span<const uint8_t> data);

net::awaitable<tl::expected<void, ErrorCode>>
WriteFrame(AsyncStream& stream, uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload);

net::awaitable<tl::expected<void, ErrorCode>>
WritePacketWithPadding(AsyncStream& stream,
                       std::span<const PaddingRecord> record_rules,
                       memory::ByteVector packet);

net::awaitable<tl::expected<void, ErrorCode>>
WritePacketWithPadding(AsyncStream& stream,
                       const PaddingScheme& scheme,
                       uint32_t packet_index,
                       memory::ByteVector packet);

net::awaitable<tl::expected<void, ErrorCode>>
WriteMultiBufferAsFrameBatch(AsyncStream& stream, uint8_t cmd, uint32_t sid, buf::MultiBuffer mb);

net::awaitable<tl::expected<void, ErrorCode>>
WriteBuffersAsFrameBatch(AsyncStream& stream,
                         uint8_t cmd,
                         uint32_t sid,
                         std::span<const net::const_buffer> buffers);

net::awaitable<tl::expected<void, ErrorCode>>
WriteMultiBufferAsFramesWithPadding(AsyncStream& stream,
                                    const PaddingScheme& scheme,
                                    uint32_t packet_index,
                                    uint8_t cmd,
                                    uint32_t sid,
                                    buf::MultiBuffer mb);

net::awaitable<tl::expected<void, ErrorCode>>
WriteBuffersAsFramesWithPadding(AsyncStream& stream,
                                const PaddingScheme& scheme,
                                uint32_t packet_index,
                                uint8_t cmd,
                                uint32_t sid,
                                std::span<const net::const_buffer> buffers);

net::awaitable<tl::expected<FrameHeader, ErrorCode>>
ReadFrameHeader(AsyncStream& stream);

net::awaitable<tl::expected<memory::String, ErrorCode>>
ReadFrameText(AsyncStream& stream, uint16_t length);

net::awaitable<tl::expected<void, ErrorCode>>
DiscardFramePayload(AsyncStream& stream, uint16_t length);

net::awaitable<tl::expected<buf::MultiBuffer, ErrorCode>>
ReadFramePayload(AsyncStream& stream, uint16_t length);

}  // namespace anytls

namespace proxy::anytls::inbound {

// ============================================================================
// Handler - AnyTLS inbound proxy
//
// AnyTLS 服务端侧协议处理器：负责 sha256(password) 认证头、
// settings/SYN/PSH/FIN 帧解析，并将单请求 TCP framed stream 交给 dispatcher。
//
// 协议核心 codec 位于 anytls；handler 与其它协议一致归于
// proxy::<name>::inbound（对应 vmess core=vmess, handler=proxy::vmess::*）。
// ============================================================================
class Handler final : public Inbound {
public:
    Handler(UserOnlineTracker& tracker,
            StatsShard& stats,
            ConnectionLimiter* limiter,
            std::shared_ptr<const ::anytls::PaddingScheme> padding_scheme = {});

    net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::io_context& io_context,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    UserOnlineTracker& tracker_;
    StatsShard& stats_;
    ConnectionLimiter* limiter_;
    std::shared_ptr<const ::anytls::PaddingScheme> padding_scheme_;
};

}  // namespace proxy::anytls::inbound

// 协议核心 codec/validator 位于 anytls；handler 与其它协议一致归于
// proxy::<name>::outbound（对应 vmess core=vmess, handler=proxy::vmess::*）。
namespace proxy::anytls::outbound {

// 传输层与 sendThrough 属于 Handler 的 sender settings。
struct Settings {
    OutboundServer server;
    std::array<uint8_t, 32> password_hash{};
    std::chrono::seconds idle_session_check_interval{30};
    std::chrono::seconds idle_session_timeout{60};
    size_t min_idle_sessions = 0;

    Settings() = default;
    Settings(const Settings&) = default;
    Settings& operator=(const Settings&) = default;
    Settings(Settings&&) noexcept = default;
    Settings& operator=(Settings&&) noexcept = default;
    ~Settings() noexcept {
        OPENSSL_cleanse(password_hash.data(), password_hash.size());
    }
};

[[nodiscard]] tl::expected<Settings, std::string> ParseSettings(
    const json::object& source);

// ============================================================================
// Handler - AnyTLS outbound proxy
//
// AnyTLS 客户端侧协议处理器：负责 TLS 承载连接、sha256(password)
// 认证头、settings/SYN/PSH/FIN 帧、padding scheme、session read loop
// sid demux 和 Xray-core 风格 idle session pool 复用。物理连接经 Handler 的
// OutboundDialer 拨号。
// ============================================================================
class Handler final : public Outbound {
public:
    // `tasks` accounts and joins physical readers on the Worker thread.
    // Idle sessions are pooled locally; negotiated padding is published to
    // PaddingState and captured for each new handshake.
    Handler(std::string_view tag,
            net::io_context& io_context,
            std::shared_ptr<const Settings> settings,
            AwaitableTaskGroup& tasks);
    ~Handler() noexcept override;

    net::awaitable<OutboundProcessResult> Process(
        session::Context& ctx,
        transport::Link inbound,
        OutboundDialer& dialer,
        const TimeoutsConfig& timeouts,
        StatsShard& stats,
        const RelayConfig& relay_config,
        buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    struct PaddingState;
    struct ClientSession;
    class SessionPool;
    struct LogicalStreamLease;

    net::awaitable<OutboundProcessResult> ProcessSession(
        session::Context& ctx, transport::Link inbound, OutboundDialer& dialer,
        const TimeoutsConfig& timeouts, StatsShard& stats, const RelayConfig& relay_config,
        buf::MultiBufferBatch first_payload, std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout,
        std::shared_ptr<ClientSession> session, bool& reusable);
    memory::String tag_;
    std::shared_ptr<const Settings> settings_;
    std::shared_ptr<PaddingState> padding_;
    std::shared_ptr<SessionPool> pool_;
};

}  // namespace proxy::anytls::outbound
