#include "acppnode/service/controller/config.hpp"

#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"

#include <format>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace acpp {

namespace {

inline std::string jstr(const json::object& obj,
                        std::string_view key,
                        std::string_view def = "") {
    auto* p = obj.if_contains(key);
    if (p && p->is_string()) return std::string(p->as_string());
    return std::string(def);
}

inline bool jbool(const json::object& obj,
                  std::string_view key,
                  bool def = false) {
    auto* p = obj.if_contains(key);
    if (p && p->is_bool()) return p->as_bool();
    return def;
}

std::string LowerCopy(std::string_view value) {
    std::string out(value);
    std::ranges::transform(out, out.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return out;
}

ProxyProtocolMode ParseProxyProtocolMode(const json::object& obj,
                                         std::string_view key,
                                         ProxyProtocolMode def) {
    auto* p = obj.if_contains(key);
    if (!p) return def;
    if (p->is_bool()) {
        return p->as_bool() ? ProxyProtocolMode::Auto : ProxyProtocolMode::Off;
    }
    if (!p->is_string()) {
        return def;
    }

    const auto mode = LowerCopy(p->as_string());
    if (mode == "auto" || mode == "detect") {
        return ProxyProtocolMode::Auto;
    }
    if (mode == "on" || mode == "true" || mode == "strict" ||
        mode == "require" || mode == "required") {
        return ProxyProtocolMode::On;
    }
    if (mode == "off" || mode == "false" || mode == "disable" ||
        mode == "disabled" || mode == "none") {
        return ProxyProtocolMode::Off;
    }
    return def;
}

} // anonymous namespace

PanelConfig PanelConfig::FromJson(const json::object& j) {
    PanelConfig cfg;
    cfg.Name      = jstr(j, "Name");
    cfg.Type      = jstr(j, "Type", std::string(constants::panel::kV2BoardType));
    cfg.APIHost   = jstr(j, "APIHost");
    cfg.Key       = jstr(j, "Key");

    const auto raw_node_type =
        jstr(j, "NodeType", std::string(constants::panel::kDefaultNodeType));
    cfg.NodeType = naming::NormalizePanelNodeProtocol(raw_node_type);

    if (const auto* node_ids = j.if_contains("NodeIDs")) {
        cfg.NodeIDs = PanelNodeIds::Parse(*node_ids);
    }
    if (cfg.Name.empty() && !cfg.NodeIDs.Empty()) {
        cfg.Name = std::format("{}-{}", cfg.NodeType, cfg.NodeIDs.Front());
    }
    if (const auto* listen_ip = j.if_contains("ListenIP")) {
        if (!listen_ip->is_string()) {
            throw std::invalid_argument("Panel ListenIP must be a string");
        }
        auto parsed = InboundListen::Parse(listen_ip->as_string());
        if (!parsed) {
            throw std::invalid_argument(std::format(
                "Panel ListenIP '{}' must be auto or an IP address",
                listen_ip->as_string()));
        }
        cfg.ListenIP = std::move(*parsed);
    }
    if (const auto* send_ip = j.if_contains("SendIP")) {
        if (!send_ip->is_string()) {
            throw std::invalid_argument("Panel SendIP must be a string");
        }
        auto parsed = OutboundBind::Parse(send_ip->as_string());
        if (!parsed) {
            throw std::invalid_argument(std::format(
                "Panel SendIP '{}' must be auto, wildcard, or an IP address",
                send_ip->as_string()));
        }
        cfg.SendIP = std::move(*parsed);
    }
    cfg.EnableDNS = jbool(j, "EnableDNS", cfg.EnableDNS);
    cfg.DNSType = jstr(j, "DNSType", cfg.DNSType);
    cfg.ProxyProtocol = ParseProxyProtocolMode(j, "ProxyProtocol", cfg.ProxyProtocol);
    cfg.TLSEnable = jbool(j, "TLSEnable", cfg.TLSEnable);
    cfg.TLSCert   = jstr(j, "TLSCert", cfg.TLSCert);
    cfg.TLSKey    = jstr(j, "TLSKey", cfg.TLSKey);
    return cfg;
}

bool PanelConfig::Validate() const {
    if (Name.empty()) {
        LOG_ERROR("Panel name is required");
        return false;
    }
    if (APIHost.empty()) {
        LOG_ERROR("Panel {} ApiHost is required", Name);
        return false;
    }
    if (Key.empty()) {
        LOG_ERROR("Panel {} ApiKey is required", Name);
        return false;
    }
    if (NodeIDs.Empty()) {
        LOG_ERROR("Panel {} NodeIDs is required", Name);
        return false;
    }
    if (Type != constants::panel::kV2BoardType) {
        LOG_ERROR("Panel {} Type must be {}", Name, constants::panel::kV2BoardType);
        return false;
    }
    if (NodeType != constants::protocol::kVmess &&
        NodeType != constants::protocol::kVless &&
        NodeType != constants::protocol::kTrojan &&
        NodeType != constants::protocol::kShadowsocks &&
        NodeType != constants::protocol::kAnyTLS) {
        LOG_ERROR("Panel {} NodeType must be {}, {}, {}, {} or {}",
                  Name,
                  constants::protocol::kVmess,
                  constants::protocol::kVless,
                  constants::protocol::kTrojan,
                  constants::protocol::kShadowsocks,
                  constants::protocol::kAnyTLS);
        return false;
    }
    if (TLSEnable) {
        if (!TLSCert.empty() && !std::filesystem::exists(TLSCert)) {
            LOG_ERROR("Panel {} TlsCert not found: {}", Name, TLSCert);
            return false;
        }
        if (!TLSKey.empty() && !std::filesystem::exists(TLSKey)) {
            LOG_ERROR("Panel {} TlsKey not found: {}", Name, TLSKey);
            return false;
        }
    }
    return true;
}

}  // namespace acpp
