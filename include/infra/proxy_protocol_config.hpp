#pragma once

#include "core/naming.hpp"
#include "infra/json.hpp"
#include "transport/internet/proxy_protocol_mode.hpp"

#include <stdexcept>
#include <string_view>


// Header presence policy is independent of v1/v2 format detection.
[[nodiscard]] inline ProxyProtocolMode ParseProxyProtocolMode(
    const json::object& object, std::string_view key,
    ProxyProtocolMode fallback = ProxyProtocolMode::Auto) {
    const auto* value = object.if_contains(key);
    if (!value) return fallback;
    if (value->is_string()) {
        const auto mode = naming::LowerAscii(value->as_string());
        if (mode == "off") return ProxyProtocolMode::Off;
        if (mode == "auto") return ProxyProtocolMode::Auto;
        if (mode == "on") return ProxyProtocolMode::On;
    }
    throw std::invalid_argument(
        "proxyProtocol must be off, auto or on");
}

