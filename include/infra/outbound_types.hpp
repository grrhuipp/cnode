#pragma once

#include "common/target_address.hpp"
#include "proxy/freedom/domain_strategy.hpp"
#include "proxy/shadowsocks/cipher.hpp"
#include "proxy/uot/version.hpp"
#include "proxy/vmess/security.hpp"
#include "transport/internet/outbound_server.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace proxy::vless { struct VlessEncryptionConfig; }

namespace infra {

struct FreedomSettings {
    proxy::freedom::outbound::DomainStrategy domain_strategy =
        proxy::freedom::outbound::DomainStrategy::AsIs;
    std::optional<common::TargetAddress> redirect{};
};

struct BlackholeSettings {
    bool http_response = false;
};

struct ShadowsocksSettings {
    transport::internet::OutboundServer server;
    proxy::shadowsocks::SsCipherInfo cipher{proxy::shadowsocks::SsCipherType::AES_256_GCM, 32, 32};
    std::string password;
    std::optional<proxy::uot::Version> uot_version;
};

struct TrojanSettings {
    transport::internet::OutboundServer server;
    std::string password;
    std::string server_name;
    bool allow_insecure = false;
    std::vector<std::string> alpn;
};

enum class PacketEncoding : uint8_t { None, PacketAddr, Xudp };

struct VlessSettings {
    transport::internet::OutboundServer server;
    std::array<uint8_t, 16> id{};
    std::string flow;
    std::shared_ptr<const proxy::vless::VlessEncryptionConfig> encryption;
    PacketEncoding packet_encoding = PacketEncoding::Xudp;
};

struct VmessSettings {
    transport::internet::OutboundServer server;
    std::array<uint8_t, 16> id{};
    proxy::vmess::Security security = proxy::vmess::Security::AES_128_GCM;
};

struct AnyTlsSettings {
    transport::internet::OutboundServer server;
    std::array<uint8_t, 32> password_hash{};
    std::chrono::seconds idle_session_check_interval{30};
    std::chrono::seconds idle_session_timeout{60};
    size_t min_idle_sessions = 0;
};

using OutboundSettings = std::variant<
    std::monostate, FreedomSettings, BlackholeSettings, ShadowsocksSettings,
    TrojanSettings, VlessSettings, VmessSettings, AnyTlsSettings>;

}  // namespace infra
