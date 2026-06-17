#include "source_config.hpp"

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

    cfg.send_through = read_string("sendThrough");
    if (cfg.send_through.empty()) {
        cfg.send_through = read_string("send_through");
    }

    return cfg;
}

}  // namespace acpp::proxyman::outbound
