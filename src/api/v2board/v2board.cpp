#include "acppnode/api/panel_factory.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/infra/json.hpp"
#include "acppnode/infra/log.hpp"
#include "http_response.hpp"
#include "request_task.hpp"
#include "node_info_json.hpp"
#include "online_report.hpp"
#include "user_list_json.hpp"

#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>
#include <asio/connect.hpp>
#include <asio/read.hpp>
#include <asio/read_until.hpp>
#include <asio/write.hpp>
#include <asio/cancel_after.hpp>
#include <cctype>
#include <charconv>
#include <format>
#include <limits>
#include <regex>
#include <stdexcept>
#include <vector>
#include <openssl/x509_vfy.h>

namespace acpp::api::v2board {

namespace ssl = net::ssl;

class APIClient final : public ::acpp::api::API {
public:
    APIClient(net::io_context& io_context, const ::acpp::api::Config& config,
              ::acpp::app::dns::DNS& dns_service);
    ~APIClient() override;

    net::awaitable<NodeInfoFetchResult>
    GetNodeInfo(std::string committed_etag) override;

    net::awaitable<UserListFetchResult>
    GetUserList(std::string committed_etag) override;

    net::awaitable<bool>
    ReportNodeOnlineUsers(const std::vector<::acpp::api::OnlineUser>& online_users) override;

    net::awaitable<bool>
    ReportUserTraffic(const std::vector<::acpp::api::UserTraffic>& data) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

namespace {

constexpr size_t kHttpErrorDetailLimit = 256;

using HttpResponse = http::Response;

enum class HttpMethod : uint8_t {
    Get,
    Post,
};

struct UrlParts {
    bool use_ssl = false;
    std::string host;
    uint16_t port = 0;
    std::string path_prefix;
    std::optional<net::ip::address> literal_address;
};

std::string CompactLogText(std::string_view text) {
    std::string result;
    result.reserve(text.size() < kHttpErrorDetailLimit ? text.size()
                                                       : kHttpErrorDetailLimit);

    bool truncated  = false;
    bool last_space = false;
    for (char ch : text) {
        if (result.size() >= kHttpErrorDetailLimit) {
            truncated = true;
            break;
        }

        const unsigned char uch = static_cast<unsigned char>(ch);
        if (ch == '\r' || ch == '\n' || ch == '\t') {
            ch = ' ';
        } else if (std::iscntrl(uch)) {
            continue;
        }

        if (ch == ' ') {
            if (last_space) continue;
            last_space = true;
        } else {
            last_space = false;
        }

        result.push_back(ch);
    }

    while (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }

    if (truncated) {
        result += "...";
    }
    return result;
}

std::string FormatHttpFailure(const HttpResponse& resp) {
    // Server response bodies can echo request queries, API keys or credentials.
    // Only locally generated transport/parser diagnostics are safe to include.
    const std::string detail = resp.status <= 0 ? CompactLogText(resp.body) : std::string{};

    if (resp.status <= 0) {
        if (!detail.empty()) {
            return std::format(
                "request failed before HTTP response (status {}): {}",
                resp.status, detail);
        }
        return std::format("request failed before HTTP response (status {})",
                           resp.status);
    }

    return std::format("HTTP status {}", resp.status);
}

std::string MethodName(HttpMethod method) {
    switch (method) {
        case HttpMethod::Get: return "GET";
        case HttpMethod::Post: return "POST";
    }
    return "GET";
}

std::optional<uint16_t> ParseHttpPort(std::string_view value) noexcept {
    uint32_t parsed = 0;
    const auto [end, ec] = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (value.empty() || ec != std::errc{} ||
        end != value.data() + value.size() || parsed == 0 ||
        parsed > std::numeric_limits<uint16_t>::max()) {
        return std::nullopt;
    }
    return static_cast<uint16_t>(parsed);
}

std::string JoinRouteMatches(const json::array& matches) {
    std::string pattern;
    for (const auto& match : matches) {
        if (!match.is_string()) {
            throw std::invalid_argument("block route match entries must be strings");
        }
        if (!pattern.empty()) {
            pattern.push_back('|');
        }
        pattern += match.as_string();
    }
    return pattern;
}

std::vector<rule::DetectRule>
ExtractBlockDetectRules(const json::object& config) {
    std::vector<rule::DetectRule> rules;
    const auto* routes_value = config.if_contains("routes");
    if (!routes_value || routes_value->is_null()) {
        return rules;
    }
    if (!routes_value->is_array()) {
        throw std::invalid_argument("routes must be an array");
    }

    const auto& routes = routes_value->as_array();
    rules.reserve(routes.size());
    for (size_t i = 0; i < routes.size(); ++i) {
        const auto& route_value = routes[i];
        if (!route_value.is_object()) {
            throw std::invalid_argument("route entries must be objects");
        }

        const auto& route = route_value.as_object();
        const auto* action = route.if_contains("action");
        if (!action || !action->is_string() || action->as_string() != "block") {
            continue;
        }

        const auto* match_value = route.if_contains("match");
        if (!match_value || !match_value->is_array()) {
            throw std::invalid_argument("block route match must be an array");
        }

        const std::string pattern = JoinRouteMatches(match_value->as_array());
        if (pattern.empty()) {
            continue;
        }

        try {
            rule::DetectRule rule;
            rule.Pattern = std::regex(pattern);
            rules.push_back(std::move(rule));
        } catch (const std::regex_error& e) {
            throw std::invalid_argument(std::format(
                "Invalid block route detect rule {}: {}", i, e.what()));
        }
    }
    return rules;
}

}  // namespace

// ============================================================================
// APIClient 实现
// ============================================================================

static std::optional<UrlParts> ParseUrl(const std::string& url);

struct APIClient::Impl {
    Impl(net::io_context& io_context,
         const ::acpp::api::Config& config,
         ::acpp::app::dns::DNS& dns_service);

    [[nodiscard]] std::string ApiNodeType() const;

    // Parameters are owned by the coroutine frame: RunRequest starts the
    // exchange lazily and may cancel it after the caller's arguments are gone.
    net::awaitable<HttpResponse>
    HttpRequest(HttpMethod method,
                std::string path,
                std::string body_text,
                std::string if_none_match);

    net::awaitable<HttpResponse>
    HttpExchange(HttpMethod method,
                 std::string path,
                 std::string body_text,
                 std::string if_none_match);

    net::awaitable<NodeInfoFetchResult> GetNodeInfo(std::string committed_etag);
    net::awaitable<UserListFetchResult> GetUserList(std::string committed_etag);
    net::awaitable<bool> ReportNodeOnlineUsers(const std::vector<::acpp::api::OnlineUser>& online_users);
    net::awaitable<bool> ReportUserTraffic(const std::vector<::acpp::api::UserTraffic>& data);

    net::io_context& io_context_;
    ::acpp::api::Config config_;
    UrlParts url_parts_;
    ::acpp::app::dns::DNS& dns_service_;

    std::unique_ptr<net::ssl::context> https_context_;
};

APIClient::Impl::Impl(net::io_context& io_context,
                      const ::acpp::api::Config& config,
                      ::acpp::app::dns::DNS& dns_service)
    : io_context_(io_context)
    , config_(config)
    , dns_service_(dns_service) {

    if (config_.RequestTimeout <= std::chrono::seconds::zero() ||
        config_.RequestTimeout > std::chrono::seconds(defaults::kMaxPanelRequestTimeout)) {
        throw std::invalid_argument("API RequestTimeout is outside the supported range");
    }

    auto parts = ParseUrl(config.APIHost);
    if (!parts) {
        throw std::invalid_argument("Invalid panel API host");
    }
    url_parts_ = std::move(*parts);

    if (url_parts_.use_ssl) {
        // Negotiate TLS 1.3 when the panel offers it; TLS 1.2 stays the floor
        // (RFC 8996 deprecates TLS 1.0/1.1).
        https_context_ = std::make_unique<ssl::context>(ssl::context::tls_client);
        if (SSL_CTX_set_min_proto_version(https_context_->native_handle(), TLS1_2_VERSION) != 1) {
            throw std::runtime_error("V2Board: failed to set the HTTPS minimum TLS version");
        }
        https_context_->set_default_verify_paths();
        https_context_->set_verify_mode(ssl::verify_peer);
    }
}

std::string APIClient::Impl::ApiNodeType() const {
    return naming::NormalizeV2BoardApiNodeType(config_.NodeType);
}

static std::optional<UrlParts> ParseUrl(const std::string& url) {
    UrlParts parts;

    const std::string_view url_view(url);
    const size_t scheme_pos = url_view.find("://");
    if (scheme_pos == std::string_view::npos) {
        return std::nullopt;
    }

    const std::string_view scheme = url_view.substr(0, scheme_pos);
    if (scheme != constants::protocol::kHttp && scheme != constants::protocol::kHttps) {
        return std::nullopt;
    }
    parts.use_ssl = (scheme == constants::protocol::kHttps);

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

    std::string_view explicit_port;
    bool has_explicit_port = false;
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
            has_explicit_port = true;
            explicit_port = authority.substr(close_bracket + 2);
        }
    } else {
        const size_t first_colon = authority.find(':');
        const size_t last_colon = authority.rfind(':');
        if (first_colon != std::string_view::npos && first_colon == last_colon) {
            parts.host = std::string(authority.substr(0, first_colon));
            has_explicit_port = true;
            explicit_port = authority.substr(last_colon + 1);
        } else {
            parts.host = std::string(authority);
        }
    }

    if (parts.host.empty()) {
        return std::nullopt;
    }
    if (has_explicit_port) {
        const auto parsed_port = ParseHttpPort(explicit_port);
        if (!parsed_port) {
            return std::nullopt;
        }
        parts.port = *parsed_port;
    } else {
        parts.port = parts.use_ssl ? 443 : 80;
    }

    parts.literal_address = iputil::ParseLiteral(parts.host);
    if (authority.front() == '[') {
        if (!parts.literal_address || !parts.literal_address->is_v6()) return std::nullopt;
    } else if (parts.host.find(':') != std::string::npos ||
               (!parts.literal_address && !domain::IsValidDnsHostname(
                   parts.host, domain::TrailingDotPolicy::Allow))) {
        return std::nullopt;
    }

    // 移除末尾斜杠
    while (!parts.path_prefix.empty() && parts.path_prefix.back() == '/') {
        parts.path_prefix.pop_back();
    }

    return parts;
}

net::awaitable<HttpResponse>
APIClient::Impl::HttpRequest(HttpMethod method,
                             std::string path,
                             std::string body_text,
                             std::string if_none_match) {
    return http::RunRequest(
        HttpExchange(method, std::move(path), std::move(body_text),
                     std::move(if_none_match)),
        config_.RequestTimeout);
}

net::awaitable<HttpResponse>
APIClient::Impl::HttpExchange(HttpMethod method,
                              std::string path,
                              std::string body_text,
                              std::string if_none_match) {
    HttpResponse result;
    const PanelLogContext log_context{config_.Name, config_.APIHost, config_.NodeID, config_.NodeType};

    // 面板同步是冷路径；保留完整候选地址，避免双栈环境只尝试第一个解析结果。
    std::vector<tcp::endpoint> endpoints;
    const uint16_t port = url_parts_.port;

    if (url_parts_.literal_address) {
        endpoints.emplace_back(*url_parts_.literal_address, port);
    } else {
        auto dns_result = co_await dns_service_.Resolve(url_parts_.host);
        if (!dns_result.Ok() || dns_result.addresses.empty()) {
            result.status = 0;
            result.body = "DNS resolve failed for " + url_parts_.host;
            co_return result;
        }
        endpoints.reserve(dns_result.addresses.size());
        for (const auto& address : dns_result.addresses) {
            endpoints.emplace_back(address, port);
        }
    }

    // 构建完整路径（所有请求都在 URL 参数中传 token）
    std::string full_path = url_parts_.path_prefix + path;
    if (full_path.find('?') != std::string::npos) {
        full_path += "&token=" + config_.Key;
    } else {
        full_path += "?token=" + config_.Key;
    }

    std::string request;
    request.reserve(512 + body_text.size());
    request += MethodName(method);
    request += ' ';
    request += full_path.empty() ? "/" : full_path;
    request += " HTTP/1.1\r\nHost: ";
    request += iputil::FormatHttpHostHeader(url_parts_.host, port, url_parts_.use_ssl);
    request += "\r\nUser-Agent: acppnode/1.0\r\nAuthorization: Bearer ";
    request += config_.Key;
    request += "\r\nX-API-Key: ";
    request += config_.Key;
    request += "\r\nAccept: application/json\r\nConnection: close\r\n";
    if (!if_none_match.empty()) {
        request += "If-None-Match: ";
        request += if_none_match;
        request += "\r\n";
    }
    if (method == HttpMethod::Post) {
        request += "Content-Type: application/json\r\nContent-Length: ";
        request += std::to_string(body_text.size());
        request += "\r\n";
    }
    request += "\r\n";
    request += body_text;

    if (url_parts_.use_ssl) {
        std::string last_error;
        for (const auto& endpoint : endpoints) {
            ssl::stream<tcp::socket> stream(io_context_, *https_context_);
            try {
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

                co_await stream.lowest_layer().async_connect(endpoint, net::use_awaitable);
                co_await stream.async_handshake(ssl::stream_base::client, net::use_awaitable);
            } catch (const std::exception& e) {
                last_error = e.what();
                LOG_PANEL_DEBUG(log_context, "HTTPS endpoint connection failed: endpoint={} reason={}",
                          iputil::FormatEndpointForLog(iputil::AddressText(endpoint.address()).View(), endpoint.port()),
                          last_error);
                continue;
            }

            // Only connection setup may try another address. Once HTTP
            // transmission starts, a failure cannot prove the peer did not
            // apply the request (in particular, an additive traffic POST).
            co_await net::async_write(stream, net::buffer(request), net::use_awaitable);
            result = co_await http::ReadResponse(stream);

            // The HTTP response is complete. TLS close_notify is best effort
            // and must neither stall indefinitely nor invalidate that response.
            try {
                IoErrorCode ec;
                co_await stream.async_shutdown(net::cancel_after(std::chrono::seconds(1),
                    net::redirect_error(net::use_awaitable, ec)));
            } catch (const std::exception&) {
            }
            co_return result;
        }
        result.status = -1;
        result.body = last_error.empty() ? "HTTPS connect failed" : last_error;

    } else {
        // HTTP
        std::string last_error;
        for (const auto& endpoint : endpoints) {
            tcp::socket stream(io_context_);
            try {
                co_await stream.async_connect(endpoint, net::use_awaitable);
            } catch (const std::exception& e) {
                last_error = e.what();
                LOG_PANEL_DEBUG(log_context, "HTTP endpoint connection failed: endpoint={} reason={}",
                          iputil::FormatEndpointForLog(iputil::AddressText(endpoint.address()).View(), endpoint.port()),
                          last_error);
                continue;
            }

            co_await net::async_write(stream, net::buffer(request), net::use_awaitable);
            result = co_await http::ReadResponse(stream);

            IoErrorCode ec;
            stream.shutdown(tcp::socket::shutdown_both, ec);
            stream.close(ec);
            co_return result;
        }
        result.status = -1;
        result.body = last_error.empty() ? "HTTP connect failed" : last_error;
    }

    co_return result;

}

net::awaitable<NodeInfoFetchResult>
APIClient::Impl::GetNodeInfo(std::string committed_etag) {
    const int node_id = config_.NodeID;
    const PanelLogContext log_context{config_.Name, config_.APIHost, node_id, config_.NodeType};

    // GET /api/v1/server/UniProxy/config?node_id=X&node_type=Y
    std::string path = std::format("/api/v1/server/UniProxy/config?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    auto resp = co_await HttpRequest(HttpMethod::Get, std::move(path), {}, committed_etag);
    if (resp.not_modified) {
        if (committed_etag.empty()) {
            co_return NodeInfoFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                "received 304 without a committed node ETag");
        }
        co_return NodeInfoFetchResult::NotModified();
    }

    if (resp.status != 200) {
        const auto error_message = FormatHttpFailure(resp);
        LOG_PANEL_DEBUG(log_context, "Node configuration pull failed: {}", error_message);
        co_return NodeInfoFetchResult::Fail(
            ErrorCode::PANEL_API_FAILED,
            error_message);
    }

    try {
        auto jv = json::parse(resp.body);
        auto& j = jv.as_object();

        auto parsed_config = ParseNodeInfo(j, config_.NodeType);
        if (!parsed_config) {
            LOG_PANEL_ERROR(log_context, "Invalid node configuration: {}", parsed_config.error());
            co_return NodeInfoFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                std::move(parsed_config.error()));
        }
        auto config = std::move(*parsed_config);

        auto rules = ExtractBlockDetectRules(j);

        LOG_PANEL_DEBUG(log_context, "Node configuration received: protocol={} port={} network={}",
                        config.NodeType, config.Port, config.TransportProtocol);

        co_return NodeInfoFetchResult::Success(
            std::move(config), std::move(rules), std::move(resp.etag));

    } catch (const std::exception& e) {
        LOG_PANEL_ERROR(log_context, "Node configuration parsing failed: {}", e.what());
        co_return NodeInfoFetchResult::Fail(ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
}

net::awaitable<UserListFetchResult>
APIClient::Impl::GetUserList(std::string committed_etag) {
    const int node_id = config_.NodeID;
    const PanelLogContext log_context{config_.Name, config_.APIHost, node_id, config_.NodeType};

    // GET /api/v1/server/UniProxy/user?node_id=X&node_type=Y
    std::string path = std::format("/api/v1/server/UniProxy/user?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    // Only the owner of a committed user snapshot may supply its validator.
    // A successful fetch alone must not acknowledge a failed runtime update.
    auto resp = co_await HttpRequest(HttpMethod::Get, std::move(path), {}, committed_etag);

    // 304 Not Modified - 交给上层直接跳过用户重建，避免额外常驻缓存和拷贝
    if (resp.not_modified) {
        if (committed_etag.empty()) {
            co_return UserListFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                "received 304 without a committed user ETag");
        }
        LOG_PANEL_DEBUG(log_context, "Node users unchanged: HTTP status=304");
        co_return UserListFetchResult::NotModified();
    }

    if (resp.status != 200) {
        const auto error_message = FormatHttpFailure(resp);
        LOG_PANEL_DEBUG(log_context, "User list pull failed: {}", error_message);
        co_return UserListFetchResult::Fail(
            ErrorCode::PANEL_API_FAILED,
            error_message);
    }

    try {
        auto jv = json::parse(resp.body);
        auto& j = jv.as_object();

        auto users = ParseUserList(j);
        if (!users) {
            LOG_PANEL_ERROR(log_context, "User list parsing failed: {}", users.error());
            co_return UserListFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                std::move(users.error()));
        }

        LOG_PANEL_DEBUG(log_context, "User list received: users={}", users->size());
        co_return UserListFetchResult::Success(std::move(*users), std::move(resp.etag));

    } catch (const std::exception& e) {
        LOG_PANEL_ERROR(log_context, "User list parsing failed: {}", e.what());
        co_return UserListFetchResult::Fail(ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
}

net::awaitable<bool>
APIClient::Impl::ReportUserTraffic(const std::vector<::acpp::api::UserTraffic>& data) {
    const int node_id = config_.NodeID;
    const PanelLogContext log_context{config_.Name, config_.APIHost, node_id, config_.NodeType};

    // V2Board UniProxy push 格式: {user_id: [upload, download], ...}
    json::object body;
    for (const auto& t : data) {
        body[std::to_string(t.UID)] = json::array{
            static_cast<int64_t>(t.Upload), static_cast<int64_t>(t.Download)};
    }

    // 路径包含 node_id 和 node_type
    std::string path = std::format("/api/v1/server/UniProxy/push?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    auto resp = co_await HttpRequest(
        HttpMethod::Post, std::move(path), json::serialize(json::value(std::move(body))), {});

    if (resp.status != 200) {
        LOG_PANEL_WARN(log_context, "Traffic API acceptance unknown: HTTP status={}", resp.status);
        co_return false;
    }

    LOG_PANEL_DEBUG(log_context, "Traffic API accepted: users={} (not a billing commit acknowledgement)", data.size());
    co_return true;
}

net::awaitable<bool>
APIClient::Impl::ReportNodeOnlineUsers(const std::vector<::acpp::api::OnlineUser>& online_users) {
    const int node_id = config_.NodeID;
    const PanelLogContext log_context{config_.Name, config_.APIHost, node_id, config_.NodeType};
    auto report = BuildOnlineReportPayload(online_users, node_id);

    if (!report.alive_body.empty()) {
        const std::string alive_path = std::format(
            "/api/v1/server/UniProxy/alive?node_id={}&node_type={}",
            node_id, ApiNodeType());
        auto alive_resp = co_await HttpRequest(
            HttpMethod::Post, alive_path, json::serialize(json::value(std::move(report.alive_body))), {});
        if (alive_resp.status != 200) {
            LOG_PANEL_WARN(log_context, "Online device report failed: {}", FormatHttpFailure(alive_resp));
            co_return false;
        }
    }

    LOG_PANEL_DEBUG(log_context, "Online devices reported: users={} devices={}", report.user_count, report.device_count);
    co_return true;
}

APIClient::APIClient(net::io_context& io_context,
                     const ::acpp::api::Config& config,
                     ::acpp::app::dns::DNS& dns_service)
    : impl_(std::make_unique<Impl>(io_context, config, dns_service)) {}

APIClient::~APIClient() = default;


net::awaitable<NodeInfoFetchResult>
APIClient::GetNodeInfo(std::string committed_etag) {
    return impl_->GetNodeInfo(std::move(committed_etag));
}

net::awaitable<UserListFetchResult>
APIClient::GetUserList(std::string committed_etag) {
    return impl_->GetUserList(std::move(committed_etag));
}

net::awaitable<bool>
APIClient::ReportNodeOnlineUsers(const std::vector<::acpp::api::OnlineUser>& online_users) {
    return impl_->ReportNodeOnlineUsers(online_users);
}

net::awaitable<bool>
APIClient::ReportUserTraffic(const std::vector<::acpp::api::UserTraffic>& data) {
    return impl_->ReportUserTraffic(data);
}

}  // namespace acpp::api::v2board

namespace acpp::api {

std::unique_ptr<API> CreatePanelClient(
    net::io_context& io_context,
    const Config& config,
    app::dns::DNS& dns_service) {
    return std::make_unique<v2board::APIClient>(io_context, config, dns_service);
}

}  // namespace acpp::api
