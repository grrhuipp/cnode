#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/service/controller/config.hpp"

#include <memory>
#include <string>
#include <vector>

namespace acpp {
class Worker;
class ConnectionLimiter;

namespace controller {

// The concrete cold-path boundary for all-Worker mutations. Each asynchronous
// operation joins every started Worker task before it completes or throws.
class NodeRuntime {
public:
    NodeRuntime(net::io_context& io_context,
                const std::vector<std::unique_ptr<Worker>>& workers,
                const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters,
                const PanelConfig& config)
        : io_context_(io_context), workers_(workers), limiters_(limiters), config_(config) {}

    net::awaitable<void> RemoveInbound(const std::string& tag);
    net::awaitable<void> RemoveOutbound(const std::string& tag);
    net::awaitable<bool> AddInbound(const api::NodeInfo& config);
    net::awaitable<bool> AddOutbound(const std::string& tag);
    net::awaitable<void> UpdateRules(const std::string& tag, const std::vector<api::DetectRule>& rules);
    void ApplyUsers(const std::string& tag, const proxyman::inbound::UserSet& users);
    void ClearUsers(const std::string& tag, const std::string& protocol);

private:
    net::io_context& io_context_;
    const std::vector<std::unique_ptr<Worker>>& workers_;
    const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters_;
    const PanelConfig& config_;
};

}  // namespace controller
}  // namespace acpp
