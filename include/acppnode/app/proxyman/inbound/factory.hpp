#pragma once

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/rate_limiter_fwd.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

class Inbound;
struct StaticUserConfig;
struct StatsShard;

namespace vmess {
class TimedUserValidator;
}
namespace trojan {
class Validator;
}
namespace ss {
class Validator;
}
namespace anytls {
class Validator;
}

}  // namespace acpp

namespace acpp::proxyman::inbound {

class UdpHandler;

// ============================================================================
// ProtocolDeps - 入站协议构建依赖（由 inbound manager 提供）
// ============================================================================
struct ProtocolDeps {
    ::acpp::vmess::TimedUserValidator*  vmess_validator  = nullptr;
    ::acpp::trojan::Validator* validator = nullptr;
    ::acpp::ss::Validator*            ss_validator        = nullptr;
    ::acpp::anytls::Validator*        anytls_validator    = nullptr;
    ::acpp::StatsShard*               stats               = nullptr;
};

// ============================================================================
// ProxyRegistration - 入站协议注册项
// ============================================================================
struct ProxyRegistration {
    // 创建 TCP 入站处理器（必须）
    std::unique_ptr<::acpp::Inbound> (*create_tcp_handler)(
        const ProtocolDeps& deps,
        ::acpp::ConnectionLimiterPtr limiter,
        const BuildRequest& req) = nullptr;

    // 创建 UDP 入站处理器（可选）
    std::unique_ptr<UdpHandler> (*create_udp_handler)(
        const ProtocolDeps& deps,
        ::acpp::ConnectionLimiterPtr limiter,
        const BuildRequest& req) = nullptr;

    // 静态配置用户构建属于冷路径，结果再投递到 Worker 本地表。
    std::optional<UserSet> (*build_static_users)(
        std::string_view tag,
        const ::acpp::StaticUserConfig& config) = nullptr;

    void (*apply_worker_users)(
        const ProtocolDeps& deps,
        std::string_view tag,
        const UserSet& users) = nullptr;
    void (*add_worker_users)(
        const ProtocolDeps& deps,
        std::string_view tag,
        const UserSet& users) = nullptr;
    void (*remove_worker_users)(
        const ProtocolDeps& deps,
        std::string_view tag,
        const UserSet& users) = nullptr;

    void (*clear_worker_users)(
        const ProtocolDeps& deps,
        std::string_view tag) = nullptr;
};

bool RegisterProxy(std::string_view protocol, ProxyRegistration registration);

[[nodiscard]] bool HasProxy(std::string_view protocol);

[[nodiscard]] std::vector<std::string> RegisteredProtocols();

[[nodiscard]] std::unique_ptr<::acpp::Inbound> NewHandler(
    std::string_view protocol,
    const ProtocolDeps& deps,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req);

[[nodiscard]] std::unique_ptr<UdpHandler> NewUdpHandler(
    std::string_view protocol,
    const ProtocolDeps& deps,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req);

[[nodiscard]] std::optional<UserSet> BuildStaticUsers(
    std::string_view protocol,
    std::string_view tag,
    const ::acpp::StaticUserConfig& config);

void ApplyWorkerUsers(
    std::string_view protocol,
    const ProtocolDeps& deps,
    std::string_view tag,
    const UserSet& users);

void AddWorkerUsers(
    std::string_view protocol,
    const ProtocolDeps& deps,
    std::string_view tag,
    const UserSet& users);

void RemoveWorkerUsers(
    std::string_view protocol,
    const ProtocolDeps& deps,
    std::string_view tag,
    const UserSet& users);

void ClearWorkerUsers(
    std::string_view protocol,
    const ProtocolDeps& deps,
    std::string_view tag);

}  // namespace acpp::proxyman::inbound
