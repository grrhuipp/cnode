#pragma once

// ============================================================================
// service/controller/controller.hpp - XrayR-style node controller public API
//
// The panel sync state, node/user caches, traffic aggregation, and builder
// helpers are cold-path controller implementation details. Keep this public
// boundary narrow so panel synchronization cannot leak into Worker hot paths.
// ============================================================================

#include "acppnode/common/asio_types.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

class ConnectionLimiter;
class Worker;
struct PanelConfig;

namespace api {
class API;
}  // namespace api

class Controller {
public:
    Controller(net::io_context& io_context,
               std::vector<std::unique_ptr<Worker>>& workers,
               const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters);
    ~Controller();

    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;
    Controller(Controller&&) noexcept;
    Controller& operator=(Controller&&) noexcept;

    void AddPanel(std::unique_ptr<api::API> panel, const PanelConfig& panel_config);
    void Start();
    void Stop();

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
    [[nodiscard]] std::vector<NodeStatsInfo> GetNodeStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp
