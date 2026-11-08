#pragma once

#include "common/allocator.hpp"
#include "proxy/outbound.hpp"
#include "transport/internet/outbound_sender.hpp"

#include <array>
#include "common/unsafe.hpp"
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>


class AwaitableTaskGroup;

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
        ::SecureZeroMemory(password_hash.data(), password_hash.size());
    }
};

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
    // `tasks` accounts and joins physical readers, but each reader executes in
    // its own leaseable domain. The host retains the original configuration/
    // credential namespace; idle sessions are selected only on their current
    // Worker. Negotiated padding is published on that host, then captured with
    // checkout for each new handshake. The host task owner outlives Handler.
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
    memory::ThreadLocalString tag_;
    std::shared_ptr<const Settings> settings_;
    std::shared_ptr<PaddingState> padding_;
    std::unique_ptr<SessionPool> pool_;
};

}  // namespace proxy::anytls::outbound
