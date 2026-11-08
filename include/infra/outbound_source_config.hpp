#pragma once

#include "infra/json.hpp"
#include "transport/internet/outbound_bind.hpp"
#include "transport/internet/stream_settings.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace infra {

struct OutboundSourceConfig {
    std::string tag;
    std::string protocol;
    json::object settings;
    StreamSettings stream_settings;
    std::optional<OutboundBind> send_through;
    bool passthrough = false;
    static OutboundSourceConfig FromJson(const json::object& j);
};

}  // namespace infra
