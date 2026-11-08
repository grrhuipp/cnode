#pragma once

#include "api/api.hpp"
#include "app/prepared_inbound.hpp"
#include "app/proxyman/inbound/prepared_config.hpp"
#include "app/proxyman/outbound/prepared_config.hpp"
#include "node_state.hpp"
#include "infra/panel_config.hpp"

#include <memory>
#include <string>
#include <vector>

class Worker;

namespace controller {

// The concrete cold-path boundary for all-Worker mutations. Each asynchronous
// operation joins every started Worker task before it completes or throws.
class NodeRuntime {
public:
    NodeRuntime(net::io_context& io_context,
                const std::vector<std::unique_ptr<Worker>>& workers,
                const PanelConfig& config,
                NodeState& state,
                const bool& stopping)
        : io_context_(io_context), workers_(workers), config_(config), state_(state),
          stopping_(stopping) {}

    net::awaitable<void> RemoveInbound(const std::string& tag);
    net::awaitable<void> RemoveOutbound(const std::string& tag);
    net::awaitable<bool> AddInbound(const PreparedInbound& inbound);
    net::awaitable<void> AddOutbound(const proxyman::outbound::PreparedOutboundConfig& prepared);
    net::awaitable<void> UpdateRules(const std::string& tag, const std::vector<rule::DetectRule>& rules);
    net::awaitable<void> ApplyUsers(const std::string& tag, const proxyman::inbound::UserSet& users);
    net::awaitable<void> ClearUsers(const std::string& tag, const std::string& protocol);
    net::awaitable<void> RecoverUsers();
    [[nodiscard]] bool IsStopping() const noexcept { return stopping_; }

private:
    void ThrowIfStopping() const;
    net::io_context& io_context_;
    const std::vector<std::unique_ptr<Worker>>& workers_;
    const PanelConfig& config_;
    NodeState& state_;
    const bool& stopping_;
};

}  // namespace controller
