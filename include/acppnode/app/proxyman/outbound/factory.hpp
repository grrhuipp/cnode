#pragma once

#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <memory>
#include <string_view>

namespace acpp::proxyman::outbound {

// Prepared configs are runtime invariants. Construction failures throw;
// callers must not continue with a partially installed outbound handler.
// `tasks` must outlive the protocol instance and join everything it starts.
[[nodiscard]] std::unique_ptr<::acpp::Outbound> NewProxy(
    const PreparedOutboundConfig& config,
    ::acpp::net::io_context& io_context,
    ::acpp::AwaitableTaskGroup& tasks);

[[nodiscard]] bool HasProxy(std::string_view protocol);

}  // namespace acpp::proxyman::outbound
