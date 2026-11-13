#pragma once

#include "common/target_address.hpp"
#include "proxy/freedom/domain_strategy.hpp"
#include "proxy/shadowsocks/cipher.hpp"
#include "proxy/uot/version.hpp"
#include "proxy/vmess/security.hpp"
#include "transport/outbound_server.hpp"
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace proxy { struct VlessEncryptionConfig; }

namespace infra {

struct FreedomSettings {
    proxy::DomainStrategy domain_strategy =
        proxy::DomainStrategy::AsIs;
    std::optional<common::TargetAddress> redirect{};
};

struct BlackholeSettings {
    bool http_response = false;
};

struct ShadowsocksSettings {
    transport::OutboundServer server;
    proxy::SsCipherInfo cipher{proxy::SsCipherType::AES_256_GCM, 32, 32};
    std::string password;
    std::optional<proxy::UotVersion> uot_version;
};

struct TrojanSettings {
    transport::OutboundServer server;
    std::string password;
    std::string server_name;
    bool allow_insecure = false;
    std::vector<std::string> alpn;
};

enum class PacketEncoding : uint8_t { None, PacketAddr, Xudp };

struct VlessSettings {
    transport::OutboundServer server;
    std::array<uint8_t, 16> id{};
    std::string flow;
    std::shared_ptr<const proxy::VlessEncryptionConfig> encryption;
    PacketEncoding packet_encoding = PacketEncoding::Xudp;
};

struct VmessSettings {
    transport::OutboundServer server;
    std::array<uint8_t, 16> id{};
    proxy::VmessSecurity security = proxy::VmessSecurity::AES_128_GCM;
};

struct AnyTlsSettings {
    transport::OutboundServer server;
    std::array<uint8_t, 32> password_hash{};
    std::chrono::seconds idle_session_check_interval{30};
    std::chrono::seconds idle_session_timeout{60};
    size_t min_idle_sessions = 0;
};

using OutboundSettings = std::variant<
    std::monostate, FreedomSettings, BlackholeSettings, ShadowsocksSettings,
    TrojanSettings, VlessSettings, VmessSettings, AnyTlsSettings>;

}  // namespace infra
