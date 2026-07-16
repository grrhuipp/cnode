#include "source_config.hpp"
#include "acppnode/infra/json_object.hpp"

#include <format>
#include <stdexcept>
#include <utility>

namespace acpp::proxyman::outbound {

OutboundSourceConfig OutboundSourceConfig::FromJson(const json::object& j) {
    OutboundSourceConfig cfg;

    auto read_string = [&](std::string_view key) -> std::string {
        if (const auto* value = j.if_contains(key);
            value && value->is_string()) {
            return std::string(value->as_string());
        }
        return {};
    };
    cfg.tag = read_string("tag");
    cfg.protocol = read_string("protocol");

    auto settings = ParseAliasedJsonObject(j, {"settings"});
    if (!settings) {
        throw std::invalid_argument(std::move(settings.error()));
    }
    if (*settings) {
        cfg.settings = **settings;
    }

    auto stream_settings = ParseAliasedJsonObject(
        j, {"streamSettings", "stream_settings"});
    if (!stream_settings) {
        throw std::invalid_argument(std::move(stream_settings.error()));
    }
    if (*stream_settings) {
        cfg.stream_settings = StreamSettings::FromJson(**stream_settings);
    }

    const json::value* send_through = j.if_contains("sendThrough");
    if (!send_through) {
        send_through = j.if_contains("send_through");
    }
    if (send_through) {
        if (!send_through->is_string()) {
            throw std::invalid_argument("outbound sendThrough must be a string");
        }
        const auto text = send_through->as_string();
        cfg.send_through = OutboundBind::Parse(text);
        if (!cfg.send_through) {
            throw std::invalid_argument(std::format(
                "outbound sendThrough '{}' must be auto, wildcard, or an IP address",
                text));
        }
    }

    return cfg;
}

}  // namespace acpp::proxyman::outbound
