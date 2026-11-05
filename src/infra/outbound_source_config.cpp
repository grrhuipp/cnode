#include "acppnode/infra/outbound_source_config.hpp"
#include "acppnode/infra/json_field.hpp"
#include "acppnode/infra/outbound_bind_config.hpp"

#include <stdexcept>
#include <utility>

namespace acpp::infra {

OutboundSourceConfig OutboundSourceConfig::FromJson(const json::object& j) {
    OutboundSourceConfig cfg;

    cfg.tag = JsonStringOr(j, "tag", "");
    cfg.protocol = JsonStringOr(j, "protocol", "");

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

    if (j.contains("send_through") || j.contains("send_through_strategy")) {
        throw std::invalid_argument("outbound binding must use sendThrough/sendThroughStrategy without underscores");
    }
    const auto* send_through = j.if_contains("sendThrough");
    const auto* strategy = j.if_contains("sendThroughStrategy");
    if (strategy && !send_through) {
        throw std::invalid_argument("sendThroughStrategy requires sendThrough");
    }
    if (send_through) {
        cfg.send_through = ParseOutboundBindConfig(*send_through, strategy);
    }

    return cfg;
}

}  // namespace acpp::infra
