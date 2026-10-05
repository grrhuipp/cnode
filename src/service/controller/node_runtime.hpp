#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/service/controller/config.hpp"

#include <memory>
#include <string>
#include <vector>

namespace acpp {
class Runtime;
class ConnectionLimiter;

namespace controller {

// The concrete cold-path boundary for all-Runtime mutations. Each asynchronous
// operation joins every started Runtime task before it completes or throws.
class NodeRuntime {
public:
    NodeRuntime(Runtime& runtime, ConnectionLimiter& limiter, const PanelConfig& config)
        : runtime_(runtime), limiter_(limiter), config_(config) {}

    net::awaitable<void> RemoveInbound(const std::string& tag);
    net::awaitable<void> RemoveOutbound(const std::string& tag);
    net::awaitable<bool> AddInbound(const api::NodeInfo& config);
    net::awaitable<bool> AddOutbound(const std::string& tag);
    net::awaitable<void> UpdateRules(const std::string& tag, const std::vector<api::DetectRule>& rules);
    void ApplyUsers(const std::string& tag, const proxyman::inbound::UserSet& users);
    void ClearUsers(const std::string& tag, const std::string& protocol);

private:
    Runtime& runtime_;
    ConnectionLimiter& limiter_;
    const PanelConfig& config_;
};

}  // namespace controller
}  // namespace acpp
