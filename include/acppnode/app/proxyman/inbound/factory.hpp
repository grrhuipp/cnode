#pragma once

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/rate_limiter_fwd.hpp"
#include "acppnode/common/online_device.hpp"

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

enum class DatagramHandlerBuildStatus : uint8_t {
    Unsupported,
    Failed,
    Ready,
};

struct DatagramHandlerBuildResult {
    DatagramHandlerBuildStatus status =
        DatagramHandlerBuildStatus::Unsupported;
    std::unique_ptr<::acpp::Inbound> handler;
};

// ============================================================================
// ProtocolRuntime - 每个 Worker 的协议私有可变状态
// ============================================================================
class ProtocolRuntime {
public:
    virtual ~ProtocolRuntime() noexcept = default;

    [[nodiscard]] virtual std::vector<::acpp::OnlineDevice>
    GetOnlineDevices(std::string_view tag) const = 0;
};

// ============================================================================
// ProxyRegistration - 入站协议注册项
// ============================================================================
struct ProxyRegistration {
    // Required when either user builder is present. This maps arbitrary
    // registration names to one concrete UserStore partition.
    std::optional<UserProtocol> user_protocol;

    // 创建当前 Worker 独占的协议运行态（必须）。
    std::unique_ptr<ProtocolRuntime> (*create_runtime)() = nullptr;

    // 创建 TCP 入站处理器（必须）
    std::unique_ptr<::acpp::Inbound> (*create_tcp_handler)(
        ProtocolRuntime& runtime,
        ::acpp::StatsShard& stats,
        ::acpp::ConnectionLimiterPtr limiter,
        const BuildRequest& req) = nullptr;

    // 创建 UDP 入站处理器（可选）
    std::unique_ptr<::acpp::Inbound> (*create_datagram_handler)(
        ProtocolRuntime& runtime,
        ::acpp::StatsShard& stats,
        ::acpp::ConnectionLimiterPtr limiter,
        const BuildRequest& req) = nullptr;

    // Parse protocol-specific source fields on the cold path. The returned
    // immutable type remains private to the protocol implementation.
    std::optional<std::shared_ptr<const ProtocolSettings>>
    (*prepare_settings)(
        std::string_view tag,
        const ::acpp::StaticUserConfig& config) = nullptr;

    // 用户构建属于冷路径，结果发布到进程级只读 UserStore 快照。
    std::optional<UserSet> (*build_static_users)(
        std::string_view tag,
        const ::acpp::StaticUserConfig& config) = nullptr;

    std::optional<UserSet> (*build_users)(
        const BuildRequest& req,
        std::span<const RuntimeUser> users) = nullptr;
};

// Registration errors are programming errors during static initialization and
// therefore fail fast instead of returning an ignorable status.
void RegisterProxy(std::string_view protocol, ProxyRegistration registration);

[[nodiscard]] bool HasProxy(std::string_view protocol);

[[nodiscard]] std::vector<std::string> RegisteredProtocols();

[[nodiscard]] std::optional<UserProtocol> RegisteredUserProtocol(
    std::string_view protocol);

[[nodiscard]] std::unique_ptr<ProtocolRuntime> NewProtocolRuntime(
    std::string_view protocol);

[[nodiscard]] std::unique_ptr<::acpp::Inbound> NewHandler(
    std::string_view protocol,
    ProtocolRuntime& runtime,
    ::acpp::StatsShard& stats,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req);

[[nodiscard]] DatagramHandlerBuildResult NewDatagramHandler(
    std::string_view protocol,
    ProtocolRuntime& runtime,
    ::acpp::StatsShard& stats,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req);

[[nodiscard]] std::optional<BuildRequest> PrepareBuildRequest(
    std::string_view protocol,
    std::string_view tag,
    const ::acpp::StaticUserConfig& config);

[[nodiscard]] std::optional<UserSet> BuildStaticUsers(
    std::string_view protocol,
    std::string_view tag,
    const ::acpp::StaticUserConfig& config);

[[nodiscard]] std::optional<UserSet> BuildUsers(
    std::string_view protocol,
    const BuildRequest& req,
    std::span<const RuntimeUser> users);

}  // namespace acpp::proxyman::inbound
