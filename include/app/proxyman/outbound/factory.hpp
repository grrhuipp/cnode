#pragma once

#include "app/proxyman/outbound/prepared_config.hpp"
#include "proxy/outbound.hpp"

#include <memory>
#include <string_view>

namespace proxyman::outbound {

// Prepared configs are runtime invariants. Construction failures throw;
// callers must not continue with a partially installed outbound handler.
// `tasks` must outlive the protocol instance and join everything it starts.
[[nodiscard]] std::unique_ptr<::Outbound> NewProxy(
    const PreparedOutboundConfig& config,
    ::net::io_context& io_context,
    ::AwaitableTaskGroup& tasks);

[[nodiscard]] bool HasProxy(std::string_view protocol);

}  // namespace proxyman::outbound
