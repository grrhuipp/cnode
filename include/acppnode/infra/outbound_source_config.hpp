#pragma once

#include "acppnode/infra/json.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp::infra {

struct OutboundSourceConfig {
    std::string tag;
    std::string protocol;
    json::object settings;
    StreamSettings stream_settings;
    std::optional<OutboundBind> send_through;

    static OutboundSourceConfig FromJson(const json::object& j);
};

}  // namespace acpp::infra
