#pragma once

#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <chrono>
#include <memory>

namespace acpp::proxyman::outbound {

// Prepared configs are runtime invariants. Construction failures throw;
// callers must not continue with a partially installed outbound table.
// `tasks` must outlive the handler and join everything it starts.
[[nodiscard]] std::unique_ptr<::acpp::Outbound> NewHandler(
    const PreparedOutboundConfig& config,
    ::acpp::net::io_context& io_context,
    ::acpp::app::dns::DNS& dns,
    std::chrono::seconds dial_timeout,
    ::acpp::AwaitableTaskGroup& tasks);

[[nodiscard]] bool HasProxy(std::string_view protocol);


}  // namespace acpp::proxyman::outbound
