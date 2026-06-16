#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/rule_types.hpp"
#include "acppnode/core/constants.hpp"

#include <optional>
#include <string>
#include <vector>

namespace acpp {

namespace api {

// ============================================================================
// Config - XrayR api.Config style single-node panel client configuration
// ============================================================================
struct Config {
    std::string Name;
    std::string APIHost;
    std::string Key;
    int NodeID = 0;
    std::string NodeType = std::string(constants::panel::kDefaultNodeType);
};

// ============================================================================
// UserInfo / NodeInfo / UserTraffic - XrayR api model names
// ============================================================================
struct UserInfo {
    int64_t UID = 0;
    std::string Email;
    std::string Passwd;
    int Port = 0;
    std::string Method;
    uint64_t SpeedLimit = 0;  // Bps, 0 = unlimited
    int DeviceLimit = 0;
    std::string Protocol;
    std::string ProtocolParam;
    std::string Obfs;
    std::string ObfsParam;
    std::string UUID;
    std::string Flow;
    int AlterID = 0;
    bool Enabled = true;
};

struct NodeInfo {
    std::string NodeType = std::string(constants::protocol::kDefaultNodeProtocol);
    int NodeID = 0;
    uint16_t Port = 0;
    uint64_t SpeedLimit = 0;  // Bps
    int AlterID = 0;
    std::string TransportProtocol = std::string(constants::protocol::kTcp);
    std::string FakeType;
    std::string Host;
    std::string Path;
    bool EnableTLS = false;
    std::string TLSType;
    bool EnableVless = false;
    std::string CypherMethod = std::string(constants::protocol::kAes256Gcm);
    std::string ServiceName;

    // cnode local runtime extensions that are normalized from panel/config cold path.
    std::string TLSServerName;
    std::string TLSCert;
    std::string TLSKey;
    bool SniffEnabled = true;
    std::vector<std::string> DestOverride = {
        std::string(constants::protocol::kTls),
        std::string(constants::protocol::kHttp),
    };
    int PullInterval = defaults::kPanelPullInterval;
    int PushInterval = defaults::kPanelPushInterval;
};

struct UserTraffic {
    int64_t UID = 0;
    std::string Email;
    int64_t Upload = 0;
    int64_t Download = 0;
};

struct OnlineUser {
    int64_t UID = 0;
    std::string IP;
};

struct NodeStatus {
    double CPU = 0.0;
    double Mem = 0.0;
    double Disk = 0.0;
    uint64_t Uptime = 0;
};

using DetectRule = ::acpp::rule::DetectRule;
using DetectResult = ::acpp::rule::DetectResult;

struct ClientInfo {
    std::string APIHost;
    int NodeID = 0;
    std::string Key;
    std::string NodeType;
};

}  // namespace api

struct NodeInfoFetchResult : ResultStatus {
    std::optional<api::NodeInfo> node_info;
    bool missing = false;

    [[nodiscard]] bool Ok() const noexcept {
        return ResultStatus::Ok() && node_info.has_value();
    }

    [[nodiscard]] static NodeInfoFetchResult Success(api::NodeInfo node_info) {
        NodeInfoFetchResult result;
        result.node_info = std::move(node_info);
        return result;
    }

    [[nodiscard]] static NodeInfoFetchResult Missing() {
        NodeInfoFetchResult result;
        result.missing = true;
        return result;
    }

    [[nodiscard]] static NodeInfoFetchResult Fail(ErrorCode code, std::string msg = {}) {
        NodeInfoFetchResult result;
        result.SetError(code, msg);
        return result;
    }
};

struct UserListFetchResult : ResultStatus {
    std::vector<api::UserInfo> users;
    bool not_modified = false;

    [[nodiscard]] bool Ok() const noexcept {
        return ResultStatus::Ok();
    }

    [[nodiscard]] static UserListFetchResult Success(std::vector<api::UserInfo> value) {
        UserListFetchResult result;
        result.users = std::move(value);
        return result;
    }

    [[nodiscard]] static UserListFetchResult Fail(ErrorCode code, std::string msg = {}) {
        UserListFetchResult result;
        result.SetError(code, msg);
        return result;
    }

    [[nodiscard]] static UserListFetchResult NotModified() {
        UserListFetchResult result;
        result.not_modified = true;
        return result;
    }
};

struct RuleListFetchResult : ResultStatus {
    std::vector<api::DetectRule> rules;
    bool not_modified = false;

    [[nodiscard]] bool Ok() const noexcept {
        return ResultStatus::Ok();
    }

    [[nodiscard]] static RuleListFetchResult Success(std::vector<api::DetectRule> value) {
        RuleListFetchResult result;
        result.rules = std::move(value);
        return result;
    }

    [[nodiscard]] static RuleListFetchResult Fail(ErrorCode code, std::string msg = {}) {
        RuleListFetchResult result;
        result.SetError(code, msg);
        return result;
    }

    [[nodiscard]] static RuleListFetchResult NotModified() {
        RuleListFetchResult result;
        result.not_modified = true;
        return result;
    }
};

namespace api {

// ============================================================================
// API - XrayR api.API style panel interface
// ============================================================================
class API {
public:
    virtual ~API() noexcept = default;

    virtual net::awaitable<NodeInfoFetchResult>
    GetNodeInfo() = 0;

    virtual net::awaitable<UserListFetchResult>
    GetUserList() = 0;

    virtual net::awaitable<bool>
    ReportNodeStatus(const api::NodeStatus& node_status) = 0;

    virtual net::awaitable<bool>
    ReportNodeOnlineUsers(const std::vector<api::OnlineUser>& online_users) = 0;

    virtual net::awaitable<bool>
    ReportUserTraffic(const std::vector<api::UserTraffic>& data) = 0;

    virtual ClientInfo Describe() const = 0;

    virtual net::awaitable<RuleListFetchResult>
    GetNodeRule() = 0;

    virtual net::awaitable<bool>
    ReportIllegal(const std::vector<api::DetectResult>& detect_results) = 0;

    virtual void Debug() = 0;
};

}  // namespace api

}  // namespace acpp
