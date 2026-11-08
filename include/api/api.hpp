#pragma once

#include "common/asio_types.hpp"
#include "common/defaults.hpp"
#include "common/error.hpp"
#include "common/rule_types.hpp"
#include "core/constants.hpp"
#include "transport/internet/stream_settings.hpp"
#include "proxy/sniff_config.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <vector>


namespace api {

// ============================================================================
// Config - XrayR api.Config style single-node panel client configuration
// ============================================================================
struct Config {
    std::string Name;
    std::string APIHost;
    std::string Key;
    std::chrono::seconds RequestTimeout{defaults::kPanelRequestTimeout};
    int NodeID = 0;
    std::string NodeType = std::string(constants::panel::kDefaultNodeType);
};

// ============================================================================
// UserInfo / NodeInfo / UserTraffic - XrayR api model names
// ============================================================================
struct UserInfo {
    int64_t UID = 0;
    std::string Email;
    uint64_t SpeedLimit = 0;  // Bps, 0 = unlimited
    uint32_t DeviceLimit = 0;
    std::string UUID;
    std::string Flow;
};

struct NodeInfo {
    std::string NodeType = std::string(constants::protocol::kDefaultNodeProtocol);
    uint16_t Port = 0;
    std::string TransportProtocol = std::string(constants::protocol::kTcp);
    std::string Host;
    std::string Path;
    bool EnableTLS = false;
    bool EnableReality = false;
    std::string Flow;
    std::string ServiceName;
    RealityConfig Reality;
    std::string CypherMethod;
    std::string ShadowsocksServerKey;
    std::string PaddingScheme;
    uint32_t HysteriaUpMbps = 0;
    uint32_t HysteriaDownMbps = 0;
    // cnode local runtime extensions that are normalized from panel/config cold path.
    std::string TLSServerName;
    // V2board does not deliver sniffing; panel nodes use the local default.
    SniffConfig Sniffing{};
    int PullInterval = defaults::kPanelPullInterval;
    int PushInterval = defaults::kPanelPushInterval;
};

struct UserTraffic {
    int64_t UID = 0;
    int64_t Upload = 0;
    int64_t Download = 0;
};

struct OnlineUser {
    int64_t UID = 0;
    std::string IP;
};


}  // namespace api

struct NodeInfoFetchResult : ResultStatus {
    std::optional<api::NodeInfo> node_info;
    std::vector<rule::DetectRule> rules;
    std::string etag;
    bool not_modified = false;

    [[nodiscard]] bool Ok() const noexcept {
        return ResultStatus::Ok() && (not_modified || node_info.has_value());
    }

    [[nodiscard]] static NodeInfoFetchResult Success(
        api::NodeInfo node_info, std::vector<rule::DetectRule> rules, std::string etag) {
        NodeInfoFetchResult result;
        result.node_info = std::move(node_info);
        result.rules = std::move(rules);
        result.etag = std::move(etag);
        return result;
    }

    [[nodiscard]] static NodeInfoFetchResult Fail(ErrorCode code, std::string msg = {}) {
        NodeInfoFetchResult result;
        result.SetError(code, msg);
        return result;
    }

    [[nodiscard]] static NodeInfoFetchResult NotModified() {
        NodeInfoFetchResult result;
        result.not_modified = true;
        return result;
    }
};

struct UserListFetchResult : ResultStatus {
    std::vector<api::UserInfo> users;
    std::string etag;
    bool not_modified = false;

    [[nodiscard]] bool Ok() const noexcept {
        return ResultStatus::Ok();
    }

    [[nodiscard]] static UserListFetchResult Success(
        std::vector<api::UserInfo> value, std::string etag) {
        UserListFetchResult result;
        result.users = std::move(value);
        result.etag = std::move(etag);
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


namespace api {

// ============================================================================
// API - XrayR api.API style panel interface
// ============================================================================
class API {
public:
    virtual ~API() noexcept = default;

    virtual net::awaitable<NodeInfoFetchResult>
    GetNodeInfo(std::string committed_etag) = 0;

    // The validator belongs to the last successfully published user snapshot.
    virtual net::awaitable<UserListFetchResult>
    GetUserList(std::string committed_etag) = 0;

    virtual net::awaitable<bool>
    ReportNodeOnlineUsers(const std::vector<api::OnlineUser>& online_users) = 0;

    virtual net::awaitable<bool>
    ReportUserTraffic(const std::vector<api::UserTraffic>& data) = 0;

};

}  // namespace api

