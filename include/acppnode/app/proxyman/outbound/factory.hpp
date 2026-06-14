#pragma once

#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/app/proxyman/outbound/handler.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace acpp {
class UDPSessionManager;
struct StatsShard;
}  // namespace acpp

namespace acpp::proxyman::outbound {

[[nodiscard]] std::unique_ptr<Handler> NewHandler(
    const PreparedOutboundConfig& config,
    ::acpp::net::io_context& io_context,
    ::acpp::app::dns::DNS& dns,
    ::acpp::UDPSessionManager* udp_mgr,
    ::acpp::StatsShard& stats,
    std::chrono::seconds dial_timeout);

[[nodiscard]] bool HasProxy(std::string_view protocol);

[[nodiscard]] std::vector<std::string> RegisteredProtocols();

}  // namespace acpp::proxyman::outbound
