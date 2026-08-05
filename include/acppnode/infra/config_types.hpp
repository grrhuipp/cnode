#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json.hpp"
#include "acppnode/infra/runtime_config_types.hpp"
#include "acppnode/proxy/sniff_config.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/transport/internet/inbound_listen.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace acpp {

// ============================================================================
// 日志配置
// ============================================================================
struct LogConfig {
    std::string level = std::string(constants::logging::kDefaultLevel);  // trace/debug/info/warn/error
    std::filesystem::path log_dir = std::filesystem::path(constants::paths::kDefaultLogDir);
    std::filesystem::path access_path;
    std::filesystem::path error_path;
    uint16_t max_days = defaults::kLogRetentionDays;  // 日志保留天数（按天切割）
    bool rotate_daily = true;                         // 按本地日期切割日志
    bool gzip = true;                                 // 历史日志 gzip 压缩
    bool disable_upload = false;                      // true 时关闭结构化集中日志上传

    static LogConfig FromJson(const json::object& j);
};

// ============================================================================
// DNS 配置
// ============================================================================
struct DnsConfig {
    DnsConfig();

    std::vector<net::ip::address> servers;
    uint32_t timeout = defaults::kDnsTimeout;
    uint32_t cache_size = defaults::kDnsCacheSize;
    uint32_t min_ttl = defaults::kDnsMinTTL;
    uint32_t max_ttl = defaults::kDnsMaxTTL;

    static DnsConfig FromJson(const json::object& j);
};

// ============================================================================
// 入站配置
// ============================================================================
struct StaticUser {
    std::string id;
    std::string password;
    std::string email;
    std::string flow;
};

struct StaticUserConfig {
    std::string method = std::string(constants::protocol::kAes256Gcm);
    std::string identity_password;
    std::string padding_scheme;
    std::string vless_decryption = std::string(constants::protocol::kNone);
    std::vector<StaticUser> clients;
};

struct StaticInboundConfig {
    std::vector<std::string> tags;
    std::string protocol;
    InboundListen listen;
    uint16_t port = 0;
    StaticUserConfig static_users;
    StreamSettings stream_settings;
    SniffConfig sniffing;
    bool routing_enabled = false;

    static StaticInboundConfig FromJson(const json::object& j);
};

}  // namespace acpp
