#pragma once

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/rate_limiter_fwd.hpp"

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

class Inbound;
struct StaticUserConfig;
struct StatsShard;

}  // namespace acpp

namespace acpp::proxyman::inbound {

class UdpHandler;

// ============================================================================
// ProtocolDeps - 入站协议构建依赖（由 inbound manager 提供）
// ============================================================================
struct ProtocolDeps {
    void* validator = nullptr;
    ::acpp::StatsShard* stats = nullptr;

    template <typename T>
    [[nodiscard]] T* ValidatorAs() const noexcept {
        return static_cast<T*>(validator);
    }
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

    // 用户构建属于冷路径，结果发布到进程级只读 UserStore 快照。
    std::optional<UserSet> (*build_static_users)(
        std::string_view tag,
        const ::acpp::StaticUserConfig& config) = nullptr;

    std::optional<UserSet> (*build_users)(
        const BuildRequest& req,
        std::span<const RuntimeUser> users) = nullptr;
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

[[nodiscard]] std::optional<UserSet> BuildUsers(
    std::string_view protocol,
    const BuildRequest& req,
    std::span<const RuntimeUser> users);

}  // namespace acpp::proxyman::inbound
