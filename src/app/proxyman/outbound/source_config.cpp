#include "source_config.hpp"

#include <format>
#include <stdexcept>

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
    auto read_object = [&](std::string_view key) -> const json::object* {
        if (const auto* value = j.if_contains(key);
            value && value->is_object()) {
            return &value->as_object();
        }
        return nullptr;
    };

    cfg.tag = read_string("tag");
    cfg.protocol = read_string("protocol");

    if (const auto* settings = read_object("settings")) {
        cfg.settings = *settings;
    }

    if (const auto* camel_stream_settings = read_object("streamSettings")) {
        cfg.stream_settings = StreamSettings::FromJson(*camel_stream_settings);
    } else if (const auto* snake_stream_settings = read_object("stream_settings")) {
        cfg.stream_settings = StreamSettings::FromJson(*snake_stream_settings);
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
