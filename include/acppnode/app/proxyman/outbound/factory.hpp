#pragma once

#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace acpp {
class UDPSessionManager;
}  // namespace acpp

namespace acpp::proxyman::outbound {

// Prepared configs are runtime invariants. Construction failures throw;
// callers must not continue with a partially installed outbound table.
[[nodiscard]] std::unique_ptr<::acpp::Outbound> NewHandler(
    const PreparedOutboundConfig& config,
    ::acpp::net::io_context& io_context,
    ::acpp::app::dns::DNS& dns,
    ::acpp::UDPSessionManager* udp_mgr,
    std::chrono::seconds dial_timeout);

[[nodiscard]] bool HasProxy(std::string_view protocol);

[[nodiscard]] std::vector<std::string> RegisteredProtocols();

}  // namespace acpp::proxyman::outbound
