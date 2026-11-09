#include "infra/outbound_source_config.hpp"
#include "core/naming.hpp"
#include "infra/json_field.hpp"
#include "infra/outbound_bind_config.hpp"

#include <stdexcept>
#include <utility>

namespace infra {

OutboundSourceConfig OutboundSourceConfig::FromJson(const json::object& j) {
    OutboundSourceConfig cfg;

    cfg.tag = JsonStringOr(j, "tag", "");
    cfg.protocol = naming::LowerAscii(JsonStringOr(j, "protocol", ""));

    auto settings = ParseJsonObject(j, "settings");
    if (!settings) {
        throw std::invalid_argument(std::move(settings.error()));
    }
    if (*settings) {
        cfg.settings = **settings;
    }

    auto stream_settings = ParseJsonObject(
        j, "streamSettings");
    if (!stream_settings) {
        throw std::invalid_argument(std::move(stream_settings.error()));
    }
    if (*stream_settings) {
        cfg.stream_settings = StreamSettings::FromJson(
            **stream_settings, StreamEndpointRole::Outbound);
    }

    cfg.send_through = ParseOptionalOutboundBind(j, "outbound");
    cfg.passthrough = JsonBoolOr(j, "passthrough", false);

    return cfg;
}

}  // namespace infra
