#pragma once

#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/features/outbound/outbound.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace acpp::proxyman::outbound {

// ============================================================================
// Handler - per-Worker outbound handler
//
// 对齐 xray-core app/proxyman/outbound.Handler 的职责：绑定 tag、sender
// runtime settings 和 proxy.Outbound 实例。cnode 的 SenderConfig 已在冷路径
// 准备为 immutable runtime entry，热路径只读 Binding。
// ============================================================================
class Handler final : public features::outbound::Handler {
public:
    Handler(std::string tag, std::unique_ptr<Outbound> proxy, StatsShard& stats);

    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;
    Handler(Handler&&) noexcept = default;
    Handler& operator=(Handler&&) noexcept = default;

    [[nodiscard]] std::string_view Tag() const noexcept override {
        return tag_;
    }

    [[nodiscard]] net::awaitable<std::optional<RelayResult>> Dispatch(
        net::io_context& io_context,
        const tcp::endpoint* inbound_local_addr,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        transport::Link inbound_link,
        const RelayConfig& relay_config,
        std::span<const uint8_t> initial_payload,
        buf::MultiBuffer& first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    std::string tag_;
    std::unique_ptr<Outbound> proxy_;
    StatsShard* stats_ = nullptr;
};

}  // namespace acpp::proxyman::outbound
