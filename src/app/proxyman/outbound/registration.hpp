#pragma once

#include "app/proxyman/outbound/prepared_config.hpp"
#include "infra/outbound_source_config.hpp"

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

// Private cold-path registration API. Proxyman receives an already normalized
// source config and produces an immutable prepared handler constructor.
void RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundProxy> (*)(
        const infra::OutboundSourceConfig& config));

[[nodiscard]] std::optional<PreparedOutboundConfig> PrepareOutboundConfig(
    const infra::OutboundSourceConfig& config);

}  // namespace proxyman::outbound
