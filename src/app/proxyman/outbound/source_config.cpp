#include "source_config.hpp"

namespace acpp::proxyman::outbound {

OutboundSourceConfig OutboundSourceConfig::FromJson(const json::object& j) {
    OutboundSourceConfig cfg;

    if (j.contains("tag")) {
        cfg.tag = std::string(j.at("tag").as_string());
    }

    if (j.contains("protocol")) {
        cfg.protocol = std::string(j.at("protocol").as_string());
    }

    if (j.contains("settings") && j.at("settings").is_object()) {
        cfg.settings = j.at("settings").as_object();
    }

    if (j.contains("streamSettings") && j.at("streamSettings").is_object()) {
        cfg.stream_settings = StreamSettings::FromJson(j.at("streamSettings").as_object());
    }

    if (j.contains("sendThrough") && j.at("sendThrough").is_string()) {
        cfg.send_through = std::string(j.at("sendThrough").as_string());
    }

    return cfg;
}

}  // namespace acpp::proxyman::outbound
