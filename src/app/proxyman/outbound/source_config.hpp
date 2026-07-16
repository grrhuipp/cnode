#pragma once

#include "acppnode/infra/json.hpp"
#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp::proxyman::outbound {

struct OutboundSourceConfig {
    std::string tag;
    std::string protocol;
    json::object settings;
    StreamSettings stream_settings;
    std::optional<OutboundBind> send_through;

    static OutboundSourceConfig FromJson(const json::object& j);
};

// Private cold-path API: protocols register source parsers here; public
// proxyman outbound headers expose only prepared runtime handler construction.
bool RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundConfig> (*)(
        const OutboundSourceConfig& config));

[[nodiscard]] std::optional<PreparedOutboundConfig> PrepareOutboundConfig(
    const OutboundSourceConfig& config);

}  // namespace acpp::proxyman::outbound
