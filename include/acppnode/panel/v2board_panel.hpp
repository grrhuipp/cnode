#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/dns/dns_service.hpp"
#include "acppnode/protocol/vmess/vmess_protocol.hpp"

#include <boost/asio/ssl/context.hpp>
#include <boost/json.hpp>
#include <boost/beast/http/verb.hpp>

namespace acpp {

// Forward declaration
class IDnsService;

// ============================================================================
// 面板用户信息
// ============================================================================
struct PanelUser {
    int64_t user_id = 0;
    std::string uuid;
    std::string email;
    int speed_limit = 0;      // Mbps, 0 = 无限制
    int device_limit = 0;     // 设备数限制, 0 = 无限制
    bool enabled = true;
};

// ============================================================================
// 节点配置
// ============================================================================
struct NodeConfig {
    int node_id = 0;
    std::string protocol = "vmess";
    uint16_t port = 0;
    
    // Transport
    std::string network = "tcp";   // tcp / ws
    std::string path;              // WebSocket path
    std::string host;              // Host header
    
    // TLS
    bool tls_enabled = false;
    std::string tls_sni;
    std::string tls_cert;          // 证书文件路径（Trojan 需要）
    std::string tls_key;           // 私钥文件路径（Trojan 需要）
    
    // Shadowsocks 专用
    std::string cipher = "aes-256-gcm";  // 加密方法

    // Sniff（默认开启，自动覆盖 TLS/HTTP 目标）
    bool sniff_enabled = true;
    std::vector<std::string> dest_override = {"tls", "http"};
    
    // 同步间隔
    int pull_interval = 60;    // 用户列表刷新间隔
    int push_interval = 60;    // 流量上报间隔
};

// ============================================================================
// 流量数据
// ============================================================================
struct TrafficData {
    int64_t user_id = 0;
    uint64_t upload = 0;
    uint64_t download = 0;
};

struct NodeConfigFetchResult {
    std::optional<NodeConfig> config;
    ErrorCode error = ErrorCode::OK;
    std::string error_msg;
    bool missing = false;

    [[nodiscard]] bool Ok() const noexcept {
        return error == ErrorCode::OK && config.has_value();
    }

    [[nodiscard]] static NodeConfigFetchResult Success(NodeConfig node_config) {
        NodeConfigFetchResult result;
        result.config = std::move(node_config);
        return result;
    }

    [[nodiscard]] static NodeConfigFetchResult Missing() {
        NodeConfigFetchResult result;
        result.missing = true;
        return result;
    }

    [[nodiscard]] static NodeConfigFetchResult Fail(ErrorCode code, std::string msg = {}) {
        NodeConfigFetchResult result;
        result.error = code;
        result.error_msg = std::move(msg);
        return result;
    }
};

struct PanelUsersFetchResult {
    std::vector<PanelUser> users;
    ErrorCode error = ErrorCode::OK;
    std::string error_msg;

    [[nodiscard]] bool Ok() const noexcept {
        return error == ErrorCode::OK;
    }

    [[nodiscard]] static PanelUsersFetchResult Success(std::vector<PanelUser> value) {
        PanelUsersFetchResult result;
        result.users = std::move(value);
        return result;
    }

    [[nodiscard]] static PanelUsersFetchResult Fail(ErrorCode code, std::string msg = {}) {
        PanelUsersFetchResult result;
        result.error = code;
        result.error_msg = std::move(msg);
        return result;
    }
};

// ============================================================================
// IPanel 接口
// ============================================================================
class IPanel {
public:
    virtual ~IPanel() noexcept = default;

    // 获取面板名称
    virtual std::string Name() const = 0;

    // 获取面板类型
    virtual std::string Type() const = 0;

    // 获取节点配置
    virtual cobalt::task<NodeConfigFetchResult>
    FetchNodeConfig(int node_id) = 0;

    // 获取用户列表
    virtual cobalt::task<PanelUsersFetchResult>
    FetchUsers(int node_id) = 0;

    // 上报流量
    virtual cobalt::task<bool>
    ReportTraffic(int node_id, const std::vector<TrafficData>& data) = 0;

    // 上报在线用户
    virtual cobalt::task<bool>
    ReportOnline(int node_id, const std::vector<int64_t>& user_ids) = 0;
};

// ============================================================================
// V2Board 面板配置
// ============================================================================
struct V2BoardConfig {
    std::string name;
    std::string api_host;
    std::string api_key;
    std::vector<int> node_ids;
    std::string node_type = "vmess";
};

// ============================================================================
// HTTP 响应结构
// ============================================================================
struct HttpResponse {
    int status = 0;
    std::string body;
    std::string etag;
    bool not_modified = false;  // 304
};

// ============================================================================
// V2Board 面板实现
// ============================================================================
class V2BoardPanel final : public IPanel {
public:
    V2BoardPanel(net::any_io_executor executor, const V2BoardConfig& config,
                 IDnsService* dns_service = nullptr);
    ~V2BoardPanel() override;

    std::string Name() const override { return config_.name; }
    std::string Type() const override { return "V2Board"; }

    cobalt::task<NodeConfigFetchResult>
    FetchNodeConfig(int node_id) override;

    cobalt::task<PanelUsersFetchResult>
    FetchUsers(int node_id) override;

    cobalt::task<bool>
    ReportTraffic(int node_id, const std::vector<TrafficData>& data) override;

    cobalt::task<bool>
    ReportOnline(int node_id, const std::vector<int64_t>& user_ids) override;

private:
    std::shared_ptr<net::ssl::context> GetOrCreateHttpsContext();

    // HTTP 请求（支持 ETag）
    cobalt::task<HttpResponse>
    HttpGet(const std::string& path, const std::string& etag = "");
    
    cobalt::task<HttpResponse>
    HttpPost(const std::string& path, const boost::json::value& body);

    cobalt::task<HttpResponse>
    HttpRequest(boost::beast::http::verb method, const std::string& path,
                const std::optional<boost::json::value>& body,
                const std::string& if_none_match = "");

    // 解析 URL
    struct UrlParts {
        bool use_ssl = false;
        std::string host;
        std::string port;
        std::string path_prefix;
    };
    static std::optional<UrlParts> ParseUrl(const std::string& url);

    net::any_io_executor executor_;
    V2BoardConfig config_;
    UrlParts url_parts_;
    IDnsService* dns_service_ = nullptr;
    
    // ETag 缓存: node_id -> etag
    std::unordered_map<int, std::string> config_etags_;
    std::unordered_map<int, std::string> users_etags_;
    
    // 缓存的数据（用于 304 时返回）
    std::unordered_map<int, NodeConfig> cached_configs_;
    std::unordered_map<int, std::vector<PanelUser>> cached_users_;
    std::shared_ptr<net::ssl::context> https_context_;
};

// ============================================================================
// 面板管理器
// ============================================================================
class PanelManager {
public:
    explicit PanelManager(net::any_io_executor executor);
    ~PanelManager();

    // 添加面板
    void AddPanel(std::unique_ptr<IPanel> panel);

    // 获取面板
    IPanel* GetPanel(const std::string& name);

    // 获取所有面板
    std::vector<IPanel*> GetAllPanels();

    // 启动同步
    void StartSync();

    // 停止同步
    void StopSync();

    // 设置用户更新回调
    using UserUpdateCallback = std::function<void(
        const std::string& panel_name, 
        int node_id,
        const std::vector<PanelUser>& users)>;
    
    void SetUserUpdateCallback(UserUpdateCallback cb) {
        user_update_callback_ = std::move(cb);
    }

    // 设置流量收集回调
    using TrafficCollector = std::function<std::vector<TrafficData>(
        const std::string& panel_name,
        int node_id)>;
    
    void SetTrafficCollector(TrafficCollector cb) {
        traffic_collector_ = std::move(cb);
    }

private:
    // 同步协程
    cobalt::task<void> SyncLoop(IPanel* panel, int node_id);

    net::any_io_executor executor_;
    std::vector<std::unique_ptr<IPanel>> panels_;
    std::unordered_map<std::string, IPanel*> panel_map_;
    
    UserUpdateCallback user_update_callback_;
    TrafficCollector traffic_collector_;
    
    bool running_ = false;
    std::vector<std::shared_ptr<net::steady_timer>> sync_timers_;
};

// ============================================================================
// 工厂函数
// ============================================================================

std::unique_ptr<IPanel> CreateV2BoardPanel(
    net::any_io_executor executor,
    const V2BoardConfig& config,
    IDnsService* dns_service = nullptr);

}  // namespace acpp
