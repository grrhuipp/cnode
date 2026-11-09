#pragma once

#include "app/proxyman/outbound/prepared_config.hpp"
#include "infra/config_types.hpp"
#include "proxy/outbound.hpp"

#include <memory>
#include <optional>
#include <string_view>

namespace proxyman::outbound {

// What a protocol contributes to its Handler: the protocol constructor and the
// sender settings with its stream defaults applied. The top-level sendThrough
// of the source config overrides the protocol's default bind.
struct PreparedOutboundProxy {
    PreparedOutboundCreator create;
    OutboundSenderSettings sender;
};

// Cold-path registration API. Proxyman receives an already normalized
// source config and produces an immutable prepared handler constructor.
void RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundProxy> (*)(
        const infra::OutboundSourceConfig& config));

[[nodiscard]] std::optional<PreparedOutboundConfig> PrepareOutboundConfig(
    const infra::OutboundSourceConfig& config);

// Prepared configs are runtime invariants. Construction failures throw;
// callers must not continue with a partially installed outbound handler.
// `tasks` must outlive the protocol instance and join everything it starts.
[[nodiscard]] std::unique_ptr<::Outbound> NewProxy(
    const PreparedOutboundConfig& config,
    ::net::io_context& io_context,
    ::AwaitableTaskGroup& tasks);

[[nodiscard]] bool HasProxy(std::string_view protocol);

}  // namespace proxyman::outbound
