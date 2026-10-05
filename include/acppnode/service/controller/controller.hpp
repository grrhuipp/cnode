#pragma once

// ============================================================================
// service/controller/controller.hpp - XrayR-style node controller public API
//
// The panel sync state, node/user caches, traffic aggregation, and builder
// helpers are cold-path controller implementation details. Keep this public
// boundary narrow so panel synchronization cannot leak into Runtime hot paths.
// ============================================================================

#include "acppnode/common/asio_types.hpp"
#include "acppnode/runtime/channel.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

class ConnectionLimiter;
class Runtime;
struct PanelConfig;

namespace api {
class API;
}  // namespace api

class Controller {
public:
    Controller(net::any_io_executor executor, Runtime& runtime, ConnectionLimiter& limiter);
    ~Controller();

    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;
    Controller(Controller&&) = delete;
    Controller& operator=(Controller&&) = delete;

    void AddPanel(std::unique_ptr<api::API> panel, const PanelConfig& panel_config);
    net::awaitable<void> Run();
    [[nodiscard]] bool RequestStop();

    struct NodeStatsInfo {
        std::string panel_name;
        int         node_id      = 0;
        std::string network;
        uint16_t    port         = 0;
        size_t      total_users  = 0;
        size_t      online_users = 0;
        uint64_t    bytes_up     = 0;
        uint64_t    bytes_down   = 0;
    };
    [[nodiscard]] net::awaitable<std::vector<NodeStatsInfo>> GetNodeStats() const;

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
    ServiceChannel::Reservation stop_ticket_;
};

}  // namespace acpp
