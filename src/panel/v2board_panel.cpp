#include "acppnode/panel/v2board_panel.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/tcp_stream.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <format>
#include <openssl/x509_vfy.h>

#ifdef _WIN32
#include <openssl/x509.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
// 将 Windows 系统根证书库导入 OpenSSL SSL_CTX
static void LoadWindowsCACerts(boost::asio::ssl::context& ctx) {
    HCERTSTORE h = CertOpenSystemStoreA(0, "ROOT");
    if (!h) return;
    X509_STORE* store = SSL_CTX_get_cert_store(ctx.native_handle());
    for (PCCERT_CONTEXT c = CertEnumCertificatesInStore(h, nullptr);
         c != nullptr;
         c = CertEnumCertificatesInStore(h, c)) {
        const unsigned char* der = c->pbCertEncoded;
        X509* x = d2i_X509(nullptr, &der, static_cast<long>(c->cbCertEncoded));
        if (x) {
            X509_STORE_add_cert(store, x);
            X509_free(x);
        }
    }
    CertCloseStore(h, 0);
}
#endif

namespace acpp {

namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = net::ssl;

// ============================================================================
// V2BoardPanel 实现
// ============================================================================

V2BoardPanel::V2BoardPanel(net::any_io_executor executor, const V2BoardConfig& config,
                           IDnsService* dns_service)
    : executor_(executor)
    , config_(config)
    , dns_service_(dns_service) {
    
    auto parts = ParseUrl(config.api_host);
    if (parts) {
        url_parts_ = *parts;
    } else {
        LOG_ERROR("V2Board[{}]: invalid API host: {}", config.name, config.api_host);
    }
}

V2BoardPanel::~V2BoardPanel() = default;

std::optional<V2BoardPanel::UrlParts> V2BoardPanel::ParseUrl(const std::string& url) {
    UrlParts parts;

    const std::string_view url_view(url);
    const size_t scheme_pos = url_view.find("://");
    if (scheme_pos == std::string_view::npos) {
        return std::nullopt;
    }

    const std::string_view scheme = url_view.substr(0, scheme_pos);
    if (scheme != "http" && scheme != "https") {
        return std::nullopt;
    }
    parts.use_ssl = (scheme == "https");

    std::string_view rest = url_view.substr(scheme_pos + 3);
    const size_t path_pos = rest.find('/');
    const std::string_view authority = path_pos == std::string_view::npos
        ? rest
        : rest.substr(0, path_pos);
    parts.path_prefix = path_pos == std::string_view::npos
        ? ""
        : std::string(rest.substr(path_pos));

    if (authority.empty()) {
        return std::nullopt;
    }

    if (authority.front() == '[') {
        const size_t close_bracket = authority.find(']');
        if (close_bracket == std::string_view::npos) {
            return std::nullopt;
        }

        parts.host = std::string(authority.substr(1, close_bracket - 1));
        if (close_bracket + 1 < authority.size()) {
            if (authority[close_bracket + 1] != ':') {
                return std::nullopt;
            }
            parts.port = std::string(authority.substr(close_bracket + 2));
        }
    } else {
        const size_t first_colon = authority.find(':');
        const size_t last_colon = authority.rfind(':');
        if (first_colon != std::string_view::npos && first_colon == last_colon) {
            parts.host = std::string(authority.substr(0, first_colon));
            parts.port = std::string(authority.substr(last_colon + 1));
        } else {
            parts.host = std::string(authority);
        }
    }

    if (parts.host.empty()) {
        return std::nullopt;
    }
    if (parts.port.empty()) {
        parts.port = parts.use_ssl ? "443" : "80";
    }

    boost::system::error_code ec;
    auto literal = net::ip::make_address(parts.host, ec);
    if (!ec) {
        parts.literal_address = literal;
    }

    // 移除末尾斜杠
    while (!parts.path_prefix.empty() && parts.path_prefix.back() == '/') {
        parts.path_prefix.pop_back();
    }
    
    return parts;
}

cobalt::task<HttpResponse>
V2BoardPanel::HttpPost(const std::string& path, const boost::json::value& body) {
    co_return co_await HttpRequest(http::verb::post, path, body, "");
}

cobalt::task<HttpResponse>
V2BoardPanel::HttpGet(const std::string& path, const std::string& etag) {
    co_return co_await HttpRequest(http::verb::get, path, std::nullopt, etag);
}

std::shared_ptr<net::ssl::context> V2BoardPanel::GetOrCreateHttpsContext() {
    if (!url_parts_.use_ssl) {
        return nullptr;
    }
    if (https_context_) {
        return https_context_;
    }

    auto ctx = std::make_shared<ssl::context>(ssl::context::tlsv12_client);
#ifdef _WIN32
    LoadWindowsCACerts(*ctx);
#else
    ctx->set_default_verify_paths();
#endif
    ctx->set_verify_mode(ssl::verify_peer);
    https_context_ = ctx;
    return https_context_;
}

cobalt::task<HttpResponse>
V2BoardPanel::HttpRequest(http::verb method, const std::string& path,
                          const std::optional<boost::json::value>& body,
                          const std::string& if_none_match) {
    
    HttpResponse result;
    
    try {
        if (url_parts_.host.empty() || url_parts_.port.empty()) {
            result.status = -1;
            result.body = "invalid API host";
            co_return result;
        }

        // 解析主机 - 使用内置 DNS 服务
        tcp::endpoint endpoint;
        uint16_t port = static_cast<uint16_t>(std::stoi(url_parts_.port));

        if (url_parts_.literal_address) {
            endpoint = tcp::endpoint(*url_parts_.literal_address, port);
        } else if (dns_service_) {
            auto dns_result = co_await dns_service_->Resolve(url_parts_.host, false);
            if (!dns_result.Ok() || dns_result.addresses.empty()) {
                result.status = 0;
                result.body = "DNS resolve failed for " + url_parts_.host;
                co_return result;
            }
            endpoint = tcp::endpoint(dns_result.addresses[0], port);
        } else {
            // 回退到 Asio resolver
            tcp::resolver resolver(executor_);
            auto endpoints = co_await resolver.async_resolve(
                url_parts_.host, url_parts_.port, cobalt::use_op);
            if (endpoints.empty()) {
                result.status = 0;
                result.body = "DNS resolve failed";
                co_return result;
            }
            endpoint = endpoints.begin()->endpoint();
        }
        
        // 构建完整路径（所有请求都在 URL 参数中传 token）
        std::string full_path = url_parts_.path_prefix + path;
        if (full_path.find('?') != std::string::npos) {
            full_path += "&token=" + config_.api_key;
        } else {
            full_path += "?token=" + config_.api_key;
        }
        
        auto do_request = [&](auto& stream) -> cobalt::task<void> {
            // 构建请求
            http::request<http::string_body> req{method, full_path, 11};
            req.set(http::field::host,
                    iputil::FormatHttpHostHeader(url_parts_.host, port, url_parts_.use_ssl));
            req.set(http::field::user_agent, "acppnode/1.0");
            req.set(http::field::authorization, "Bearer " + config_.api_key);
            req.set("X-API-Key", config_.api_key);

            // If-None-Match (ETag)
            if (!if_none_match.empty()) {
                req.set(http::field::if_none_match, if_none_match);
            }

            if (body.has_value()) {
                req.set(http::field::content_type, "application/json");
                req.body() = boost::json::serialize(*body);
            }
            req.prepare_payload();

            // 发送请求
            co_await http::async_write(stream, req, cobalt::use_op);

            // 接收响应
            beast::flat_buffer buffer;
            http::response<http::string_body> res;
            co_await http::async_read(stream, buffer, res, cobalt::use_op);
            
            result.status = res.result_int();
            result.body = res.body();
            result.not_modified = (result.status == 304);
            
            // 提取 ETag
            auto etag_it = res.find(http::field::etag);
            if (etag_it != res.end()) {
                result.etag = std::string(etag_it->value());
                // 移除引号
                if (result.etag.size() >= 2 && result.etag.front() == '"' && result.etag.back() == '"') {
                    result.etag = result.etag.substr(1, result.etag.size() - 2);
                }
            }
        };
        
        if (url_parts_.use_ssl) {
            // HTTPS
            auto ssl_ctx = GetOrCreateHttpsContext();
            if (!ssl_ctx) {
                result.status = -1;
                result.body = "SSL context init failed";
                co_return result;
            }

            beast::ssl_stream<beast::tcp_stream> stream(executor_, *ssl_ctx);
            if (url_parts_.literal_address) {
                auto* verify_param = SSL_get0_param(stream.native_handle());
                if (!verify_param ||
                    X509_VERIFY_PARAM_set1_ip_asc(verify_param, url_parts_.host.c_str()) != 1) {
                    result.status = -1;
                    result.body = "SSL IP verify param error";
                    co_return result;
                }
            } else {
                stream.set_verify_callback(ssl::host_name_verification(url_parts_.host));

                if (!SSL_set_tlsext_host_name(stream.native_handle(), url_parts_.host.c_str())) {
                    result.status = -1;
                    result.body = "SSL SNI error";
                    co_return result;
                }
            }
            
            beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
            co_await beast::get_lowest_layer(stream).socket().async_connect(
                endpoint, cobalt::use_op);
            co_await stream.async_handshake(ssl::stream_base::client, cobalt::use_op);
            
            co_await do_request(stream);
            
            boost::system::error_code ec;
            stream.shutdown(ec);
            
        } else {
            // HTTP
            beast::tcp_stream stream(executor_);
            
            stream.expires_after(std::chrono::seconds(30));
            co_await stream.socket().async_connect(endpoint, cobalt::use_op);
            
            co_await do_request(stream);
            
            stream.socket().shutdown(tcp::socket::shutdown_both);
        }
        
        co_return result;
        
    } catch (const std::exception& e) {
        LOG_DEBUG("V2Board[{}]: HTTP error: {}", config_.name, e.what());
        result.status = -1;
        result.body = e.what();
        co_return result;
    }
}

cobalt::task<NodeConfigFetchResult>
V2BoardPanel::FetchNodeConfig(int node_id) {
    
    // GET /api/v1/server/UniProxy/config?node_id=X&node_type=Y
    std::string path = std::format("/api/v1/server/UniProxy/config?node_id={}&node_type={}",
                                   node_id, config_.node_type);
    
    // 使用存储的 ETag
    std::string etag;
    auto etag_it = config_etags_.find(node_id);
    if (etag_it != config_etags_.end()) {
        etag = etag_it->second;
    }
    
    auto resp = co_await HttpGet(path, etag);
    
    // 304 Not Modified - 返回缓存
    if (resp.not_modified) {
        auto cache_it = cached_configs_.find(node_id);
        if (cache_it != cached_configs_.end()) {
            LOG_DEBUG("V2Board[{}]: node {} config not modified (304)", config_.name, node_id);
            co_return NodeConfigFetchResult::Success(cache_it->second);
        }
        co_return NodeConfigFetchResult::Fail(
            ErrorCode::PANEL_INVALID_RESPONSE,
            "received 304 without cached node config");
    }

    if (resp.status == 404) {
        LOG_DEBUG("V2Board[{}]: node {} config not found", config_.name, node_id);
        config_etags_.erase(node_id);
        cached_configs_.erase(node_id);
        co_return NodeConfigFetchResult::Missing();
    }

    if (resp.status != 200) {
        LOG_DEBUG("V2Board[{}]: FetchNodeConfig failed, status={}", config_.name, resp.status);
        co_return NodeConfigFetchResult::Fail(
            ErrorCode::PANEL_API_FAILED,
            std::format("HTTP status {}", resp.status));
    }
    
    try {
        auto jv = boost::json::parse(resp.body);
        auto& j = jv.as_object();

        NodeConfig config;
        config.node_id = node_id;
        config.protocol = config_.node_type;  // 使用面板配置中的节点类型

        auto* sp = j.if_contains("server_port");
        config.port = (sp && sp->is_int64()) ? static_cast<uint16_t>(sp->as_int64()) : 0;
        auto* np = j.if_contains("network");
        config.network = (np && np->is_string()) ? std::string(np->as_string()) : "tcp";

        // networkSettings 可能是 null
        auto* nsp = j.if_contains("networkSettings");
        if (nsp && nsp->is_object()) {
            auto& ns = nsp->as_object();
            auto* pp = ns.if_contains("path");
            config.path = (pp && pp->is_string()) ? std::string(pp->as_string()) : "";
            auto* hp = ns.if_contains("headers");
            if (hp && hp->is_object()) {
                auto* hostp = hp->as_object().if_contains("Host");
                config.host = (hostp && hostp->is_string()) ? std::string(hostp->as_string()) : "";
            }
        }

        // tls 可能是 null 或 0/1
        auto* tlsp = j.if_contains("tls");
        if (tlsp && !tlsp->is_null()) {
            if (tlsp->is_int64()) config.tls_enabled = tlsp->as_int64() != 0;
            else if (tlsp->is_bool()) config.tls_enabled = tlsp->as_bool();
        }

        // server_name / sni
        auto* snip = j.if_contains("server_name");
        if (snip && snip->is_string()) {
            config.tls_sni = std::string(snip->as_string());
        }

        // cipher（Shadowsocks 加密方法）
        auto* ciphp = j.if_contains("cipher");
        if (ciphp && ciphp->is_string()) {
            config.cipher = std::string(ciphp->as_string());
        }

        auto* bcp = j.if_contains("base_config");
        if (bcp && bcp->is_object()) {
            auto& bc = bcp->as_object();
            auto* pi = bc.if_contains("pull_interval");
            config.pull_interval = (pi && pi->is_int64()) ? static_cast<int>(pi->as_int64()) : 60;
            auto* pu = bc.if_contains("push_interval");
            config.push_interval = (pu && pu->is_int64()) ? static_cast<int>(pu->as_int64()) : 60;
        }
        
        // 保存 ETag 和缓存
        if (!resp.etag.empty()) {
            config_etags_[node_id] = resp.etag;
        }
        cached_configs_[node_id] = config;
        
        LOG_DEBUG("V2Board[{}]: node {} config: protocol={}, port={}, network={}", 
                 config_.name, node_id, config.protocol, config.port, config.network);
        
        co_return NodeConfigFetchResult::Success(std::move(config));
        
    } catch (const std::exception& e) {
        LOG_ERROR("V2Board[{}]: parse config error: {}", config_.name, e.what());
        co_return NodeConfigFetchResult::Fail(ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
}

cobalt::task<PanelUsersFetchResult>
V2BoardPanel::FetchUsers(int node_id) {
    
    // GET /api/v1/server/UniProxy/user?node_id=X&node_type=Y
    std::string path = std::format("/api/v1/server/UniProxy/user?node_id={}&node_type={}",
                                   node_id, config_.node_type);
    
    // 使用存储的 ETag
    std::string etag;
    auto etag_it = users_etags_.find(node_id);
    if (etag_it != users_etags_.end()) {
        etag = etag_it->second;
    }
    
    auto resp = co_await HttpGet(path, etag);
    
    // 304 Not Modified - 交给上层直接跳过用户重建，避免额外常驻缓存和拷贝
    if (resp.not_modified) {
        LOG_DEBUG("V2Board[{}]: node {} users not modified (304)",
                 config_.name, node_id);
        co_return PanelUsersFetchResult::NotModified();
    }
    
    if (resp.status != 200) {
        LOG_DEBUG("V2Board[{}]: FetchUsers failed, status={}", config_.name, resp.status);
        co_return PanelUsersFetchResult::Fail(
            ErrorCode::PANEL_API_FAILED,
            std::format("HTTP status {}", resp.status));
    }
    
    try {
        auto jv = boost::json::parse(resp.body);
        auto& j = jv.as_object();

        std::vector<PanelUser> users;

        auto* users_p = j.if_contains("users");
        if (users_p && users_p->is_array()) {
            const auto& users_array = users_p->as_array();
            users.reserve(users_array.size());  // 预分配，避免多次重新分配

            for (const auto& uv : users_array) {
                auto& u = uv.as_object();
                PanelUser user;

                auto* id_p = u.if_contains("id");
                user.user_id = (id_p && id_p->is_int64()) ? id_p->as_int64() : 0;
                auto* uuid_p = u.if_contains("uuid");
                user.uuid = (uuid_p && uuid_p->is_string()) ? std::string(uuid_p->as_string()) : "";

                // speed_limit 和 device_limit 可能是 null
                auto* sl_p = u.if_contains("speed_limit");
                user.speed_limit = (sl_p && sl_p->is_int64()) ? static_cast<int>(sl_p->as_int64()) : 0;

                auto* dl_p = u.if_contains("device_limit");
                user.device_limit = (dl_p && dl_p->is_int64()) ? static_cast<int>(dl_p->as_int64()) : 0;

                auto* email_p = u.if_contains("email");
                user.email = (email_p && email_p->is_string()) ? std::string(email_p->as_string()) : "";
                // 如果没有 email，使用 user_id 作为标识
                if (user.email.empty() && user.user_id > 0) {
                    user.email = std::to_string(user.user_id);
                }
                user.enabled = true;

                if (!user.uuid.empty()) {
                    users.push_back(std::move(user));  // 使用 move 避免拷贝
                }
            }
        }
        
        // 保存 ETag
        if (!resp.etag.empty()) {
            users_etags_[node_id] = resp.etag;
        }

        LOG_DEBUG("V2Board[{}]: fetched {} users for node {}", 
                 config_.name, users.size(), node_id);
        co_return PanelUsersFetchResult::Success(std::move(users));
        
    } catch (const std::exception& e) {
        LOG_ERROR("V2Board[{}]: parse users error: {}", config_.name, e.what());
        co_return PanelUsersFetchResult::Fail(ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
}

cobalt::task<bool>
V2BoardPanel::ReportTraffic(int node_id, const std::vector<TrafficData>& data) {
    
    if (data.empty()) {
        co_return true;
    }
    
    // V2Board UniProxy push 格式: {user_id: [upload, download], ...}
    boost::json::object body;
    for (const auto& t : data) {
        body[std::to_string(t.user_id)] = boost::json::array{
            static_cast<int64_t>(t.upload), static_cast<int64_t>(t.download)};
    }
    
    // 路径包含 node_id 和 node_type
    std::string path = std::format("/api/v1/server/UniProxy/push?node_id={}&node_type={}",
                                   node_id, config_.node_type);
    
    auto resp = co_await HttpPost(path, body);
    
    if (resp.status != 200) {
        LOG_DEBUG("V2Board[{}]: ReportTraffic failed, status={}", config_.name, resp.status);
        co_return false;
    }
    
    LOG_DEBUG("V2Board[{}]: reported traffic for {} users", config_.name, data.size());
    co_return true;
}

cobalt::task<bool>
V2BoardPanel::ReportOnline(int node_id, const std::vector<int64_t>& user_ids) {
    
    if (user_ids.empty()) {
        co_return true;
    }
    
    // 格式: {uid: [ip_nodeid, ...], ...}
    // 根据 PHP alive 接口格式
    boost::json::object body;
    for (int64_t uid : user_ids) {
        // IP_nodeId 格式，这里用 0.0.0.0 占位
        body[std::to_string(uid)] = boost::json::array{"0.0.0.0_" + std::to_string(node_id)};
    }
    
    // 路径包含 node_id 和 node_type
    std::string path = std::format("/api/v1/server/UniProxy/alive?node_id={}&node_type={}",
                                   node_id, config_.node_type);
    
    auto resp = co_await HttpPost(path, body);
    
    if (resp.status != 200) {
        LOG_DEBUG("V2Board[{}]: ReportOnline failed, status={}", config_.name, resp.status);
        co_return false;
    }
    
    LOG_DEBUG("V2Board[{}]: reported {} online users", config_.name, user_ids.size());
    co_return true;
}

// ============================================================================
// PanelManager 实现
// ============================================================================

PanelManager::PanelManager(net::any_io_executor executor)
    : executor_(executor) {
}

PanelManager::~PanelManager() {
    StopSync();
}

void PanelManager::AddPanel(std::unique_ptr<IPanel> panel) {
    if (panel) {
        panel_map_[panel->Name()] = panel.get();
        panels_.push_back(std::move(panel));
    }
}

IPanel* PanelManager::GetPanel(const std::string& name) {
    auto it = panel_map_.find(name);
    return (it != panel_map_.end()) ? it->second : nullptr;
}

std::vector<IPanel*> PanelManager::GetAllPanels() {
    std::vector<IPanel*> result;
    for (const auto& p : panels_) {
        result.push_back(p.get());
    }
    return result;
}

void PanelManager::StartSync() {
    if (running_) return;
    running_ = true;
    
    // 为每个面板的每个节点启动同步协程
    for (const auto& panel : panels_) {
        // 获取节点列表（从配置）
        // TODO: 从配置获取节点列表
        // 暂时使用空实现，节点列表由外部配置
        (void)panel;  // 暂时标记为已使用
    }
}

void PanelManager::StopSync() {
    running_ = false;
    
    for (const auto& timer : sync_timers_) {
        timer->cancel();
    }
    sync_timers_.clear();
}

cobalt::task<void> PanelManager::SyncLoop(IPanel* panel, int node_id) {
    while (running_) {
        try {
            // 获取用户列表
            auto users = co_await panel->FetchUsers(node_id);
            
            if (users.Ok() && !users.not_modified && user_update_callback_) {
                user_update_callback_(panel->Name(), node_id, users.users);
            }
            
            // 收集并上报流量
            if (traffic_collector_) {
                auto traffic = traffic_collector_(panel->Name(), node_id);
                if (!traffic.empty()) {
                    co_await panel->ReportTraffic(node_id, traffic);
                }
            }
            
        } catch (const std::exception& e) {
            LOG_ERROR("PanelManager: sync error for {}/{}: {}", 
                      panel->Name(), node_id, e.what());
        }
        
        // 等待下一次同步
        net::steady_timer timer(executor_);
        timer.expires_after(std::chrono::seconds(60));

        auto [ec] = co_await timer.async_wait(net::as_tuple(cobalt::use_op));

        if (ec == net::error::operation_aborted) {
            break;
        }
    }
}

// ============================================================================
// 工厂函数
// ============================================================================

std::unique_ptr<IPanel> CreateV2BoardPanel(
    net::any_io_executor executor,
    const V2BoardConfig& config,
    IDnsService* dns_service) {
    return std::make_unique<V2BoardPanel>(executor, config, dns_service);
}

}  // namespace acpp
