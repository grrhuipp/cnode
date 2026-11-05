#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/transport/internet/transport_security.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace acpp {

class AwaitableTaskGroup;

namespace app::dns {
class DNS;
}  // namespace app::dns

// 协议核心 codec/validator 位于 acpp::anytls；handler 与其它协议一致归于
// acpp::proxy::<name>::outbound（对应 vmess core=acpp::vmess, handler=acpp::proxy::vmess::*）。
namespace proxy::anytls::outbound {

struct Settings {
    std::string address;
    uint16_t port = 0;
    std::array<uint8_t, 32> password_hash{};
    std::optional<net::ip::address> literal_address;
    OutboundBind send_through;
    std::chrono::seconds idle_session_check_interval{30};
    std::chrono::seconds idle_session_timeout{60};
    size_t min_idle_sessions = 0;
};

struct PreparedSettings {
    Settings settings;
    StreamSettings stream_settings;
};

// ============================================================================
// Handler - AnyTLS outbound proxy
//
// AnyTLS 客户端侧协议处理器：负责 TLS 承载连接、sha256(password)
// 认证头、settings/SYN/PSH/FIN 帧、padding scheme、session read loop
// sid demux 和 Xray-core 风格 idle session pool 复用。
// ============================================================================
class Handler final : public Outbound {
public:
    // Physical session read loops outlive requests and this Handler; `tasks`
    // owns and joins them, and must outlive the Handler.
    Handler(std::string_view tag,
            net::io_context& io_context,
            std::shared_ptr<const PreparedSettings> prepared,
            std::chrono::seconds dial_timeout,
            app::dns::DNS& dns_service,
            AwaitableTaskGroup& tasks);
    ~Handler() noexcept override;

    net::awaitable<OutboundProcessResult> Process(
        net::io_context& io_context,
        const tcp::endpoint* inbound_local_addr,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        transport::Link inbound,
        StatsShard& stats,
        const RelayConfig& relay_config,
        buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

    [[nodiscard]] std::string_view Tag() const noexcept override {
        return tag_;
    }

private:
    struct PaddingState;
    struct ClientSession;
    class SessionPool;
    struct LogicalStreamLease;

    memory::ThreadLocalString tag_;
    std::shared_ptr<const PreparedSettings> prepared_;
    TransportSecurity security_;  // This Worker's contexts for prepared_->stream_settings.
    std::chrono::seconds dial_timeout_;
    app::dns::DNS& dns_service_;
    std::shared_ptr<PaddingState> padding_;
    std::unique_ptr<SessionPool> pool_;
};

}  // namespace proxy::anytls::outbound
}  // namespace acpp
