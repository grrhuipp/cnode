#include "api/panel_factory.hpp"
#include "common/ip_address.hpp"
#include "common/ip_utils.hpp"
#include "core/naming.hpp"
#include "app/dns/dns.hpp"
#include "infra/json.hpp"
#include "infra/log.hpp"
#include "infra/panel_config.hpp"
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
#include <asio/redirect_error.hpp>
#include <asio/write.hpp>
#include <asio/cancel_after.hpp>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <format>
#include <map>
#include <regex>
#include <stdexcept>
#include <vector>
#include <openssl/x509_vfy.h>

namespace api::v2board {

namespace ssl = net::ssl;

class APIClient final : public ::api::API {
public:
    APIClient(net::io_context& io_context, const ::api::Config& config,
              ::app::dns::DNS& dns_service);
    ~APIClient() override;

    net::awaitable<NodeInfoFetchResult>
    GetNodeInfo(std::string committed_etag) override;

    net::awaitable<UserListFetchResult>
    GetUserList(std::string committed_etag) override;

    net::awaitable<bool>
    ReportNodeOnlineUsers(const std::vector<::api::OnlineUser>& online_users) override;

    net::awaitable<bool>
    ReportUserTraffic(const std::vector<::api::UserTraffic>& data) override;

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

template <typename Stream>
net::awaitable<HttpResponse>
WriteRequestAndReadResponse(Stream& stream, std::string_view request) {
    const auto cancellation = co_await net::this_coro::cancellation_state;
    IoErrorCode write_ec;
    co_await net::async_write(
        stream, net::buffer(request),
        net::redirect_error(net::use_awaitable, write_ec));
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(
            write_ec ? write_ec : net::error::operation_aborted,
            "HTTP write cancelled");
    }
    if (write_ec) {
        HttpResponse result;
        result.status = -1;
        result.body = write_ec.message();
        co_return result;
    }
    co_return co_await http::ReadResponse(stream);
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
        if (action && !action->is_null() && !action->is_string()) {
            throw std::invalid_argument("route action must be a string");
        }
        if (!action || !action->is_string() || action->as_string() != "block") {
            continue;
        }

        const auto* match_value = route.if_contains("match");
        if (!match_value || !match_value->is_array()) {
            throw std::invalid_argument("block route match must be an array");
        }

        const auto& matches = match_value->as_array();
        if (matches.empty()) {
            throw std::invalid_argument("block route match must not be empty");
        }
        for (size_t j = 0; j < matches.size(); ++j) {
            const auto& match = matches[j];
            if (!match.is_string()) {
                throw std::invalid_argument("block route match entries must be strings");
            }
            const std::string_view entry = match.as_string();
            if (entry.empty()) {
                throw std::invalid_argument("block route match entries must not be empty");
            }
            for (const unsigned char ch : entry) {
                if (ch < 0x20 || ch == 0x7f) {
                    throw std::invalid_argument(
                        "block route match entries must not contain control characters");
                }
            }
            try {
                rules.push_back(rule::DetectRule{
                    .Pattern = std::regex(std::string(entry)),
                });
            } catch (const std::regex_error& entry_error) {
                throw std::invalid_argument(std::format(
                    "Invalid block route detect rule {} (match {}): {}",
                    i, j, entry_error.what()));
            }
        }
    }
    return rules;
}

}  // namespace

// ============================================================================
// APIClient 实现
// ============================================================================

struct APIClient::Impl {
    Impl(net::io_context& io_context,
         const ::api::Config& config,
         ::app::dns::DNS& dns_service);

    [[nodiscard]] const std::string& ApiNodeType() const noexcept;

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
    net::awaitable<bool> ReportNodeOnlineUsers(const std::vector<::api::OnlineUser>& online_users);
    net::awaitable<bool> ReportUserTraffic(const std::vector<::api::UserTraffic>& data);

    net::io_context& io_context_;
    ::api::Config config_;
    PanelApiUrlParts url_parts_;
    std::optional<net::ip::address> literal_address_;
    std::string api_node_type_;
    std::string host_header_;
    ::app::dns::DNS& dns_service_;

    std::unique_ptr<net::ssl::context> https_context_;
};

APIClient::Impl::Impl(net::io_context& io_context,
                      const ::api::Config& config,
                      ::app::dns::DNS& dns_service)
    : io_context_(io_context)
    , config_(config)
    , dns_service_(dns_service) {

    if (config_.RequestTimeout <= std::chrono::seconds::zero() ||
        config_.RequestTimeout > std::chrono::seconds(defaults::kMaxPanelRequestTimeout)) {
        throw std::invalid_argument("API RequestTimeout is outside the supported range");
    }
    if (!IsValidPanelName(config_.Name)) {
        throw std::invalid_argument("Invalid panel name");
    }
    if (!IsValidPanelKey(config_.Key)) {
        throw std::invalid_argument("Invalid panel API key");
    }

    auto parts = ParsePanelApiUrl(config.APIHost);
    if (!parts) {
        throw std::invalid_argument("Invalid panel API host");
    }
    url_parts_ = std::move(*parts);
    literal_address_ = iputil::ParseLiteral(url_parts_.host);
    api_node_type_ = naming::NormalizeV2BoardApiNodeType(config_.NodeType);
    host_header_ = iputil::FormatHttpHostHeader(
        url_parts_.host, url_parts_.port, url_parts_.use_ssl);

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

const std::string& APIClient::Impl::ApiNodeType() const noexcept {
    return api_node_type_;
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

    if (literal_address_) {
        endpoints.emplace_back(*literal_address_, port);
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
    request += host_header_;
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

    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (url_parts_.use_ssl) {
        std::string last_error;
        for (const auto& endpoint : endpoints) {
            ssl::stream<tcp::socket> stream(io_context_, *https_context_);
            try {
                if (literal_address_) {
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
                if (cancellation.cancelled() != net::cancellation_type::none) {
                    throw;
                }
                last_error = e.what();
                LOG_PANEL_DEBUG(log_context, "HTTPS endpoint connection failed: endpoint={} reason={}",
                          iputil::FormatEndpointForLog(iputil::AddressText(endpoint.address()).View(), endpoint.port()),
                          last_error);
                continue;
            }

            // Only connection setup may try another address. Once HTTP
            // transmission starts, a failure cannot prove the peer did not
            // apply the request (in particular, an additive traffic POST).
            result = co_await WriteRequestAndReadResponse(stream, request);

            // The HTTP response is complete. TLS close_notify is best effort
            // and must neither stall indefinitely nor invalidate that response.
            if (result.status > 0 && cancellation.cancelled() == net::cancellation_type::none) {
                try {
                    IoErrorCode ec;
                    co_await stream.async_shutdown(net::cancel_after(std::chrono::seconds(1),
                        net::redirect_error(net::use_awaitable, ec)));
                } catch (const std::exception&) {
                }
            }
            IoErrorCode close_ec;
            stream.lowest_layer().close(close_ec);
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
                if (cancellation.cancelled() != net::cancellation_type::none) {
                    throw;
                }
                last_error = e.what();
                LOG_PANEL_DEBUG(log_context, "HTTP endpoint connection failed: endpoint={} reason={}",
                          iputil::FormatEndpointForLog(iputil::AddressText(endpoint.address()).View(), endpoint.port()),
                          last_error);
                continue;
            }

            result = co_await WriteRequestAndReadResponse(stream, request);

            IoErrorCode ec;
            if (result.status > 0) {
                stream.shutdown(tcp::socket::shutdown_both, ec);
            }
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
        if (!jv.is_object()) {
            LOG_PANEL_ERROR(log_context, "Invalid node configuration: root JSON value must be an object");
            co_return NodeInfoFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                "root JSON value must be an object");
        }
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
        if (!jv.is_object()) {
            LOG_PANEL_ERROR(log_context, "User list parsing failed: root JSON value must be an object");
            co_return UserListFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                "root JSON value must be an object");
        }
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
APIClient::Impl::ReportUserTraffic(const std::vector<::api::UserTraffic>& data) {
    const int node_id = config_.NodeID;
    const PanelLogContext log_context{config_.Name, config_.APIHost, node_id, config_.NodeType};

    // V2Board UniProxy push 格式: {user_id: [upload, download], ...}
    std::map<int64_t, ::api::UserTraffic> aggregated;
    for (const auto& t : data) {
        if (t.UID <= 0 || (t.Upload <= 0 && t.Download <= 0)) {
            continue;
        }
        const int64_t up = std::max<int64_t>(0, t.Upload);
        const int64_t down = std::max<int64_t>(0, t.Download);
        auto& entry = aggregated[t.UID];
        entry.UID = t.UID;
        entry.Upload = (up > INT64_MAX - entry.Upload) ? INT64_MAX : (entry.Upload + up);
        entry.Download = (down > INT64_MAX - entry.Download) ? INT64_MAX : (entry.Download + down);
    }
    json::object body;
    for (const auto& [uid, t] : aggregated) {
        body[std::to_string(uid)] = json::array{t.Upload, t.Download};
    }

    // 路径包含 node_id 和 node_type
    std::string path = std::format("/api/v1/server/UniProxy/push?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    auto resp = co_await HttpRequest(
        HttpMethod::Post, std::move(path), json::serialize(json::value(std::move(body))), {});

    if (resp.status != 200) {
        LOG_PANEL_WARN(log_context, "Traffic API acceptance unknown: {}", FormatHttpFailure(resp));
        co_return false;
    }

    LOG_PANEL_DEBUG(log_context, "Traffic API accepted: users={} (not a billing commit acknowledgement)", aggregated.size());
    co_return true;
}

net::awaitable<bool>
APIClient::Impl::ReportNodeOnlineUsers(const std::vector<::api::OnlineUser>& online_users) {
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
                     const ::api::Config& config,
                     ::app::dns::DNS& dns_service)
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
APIClient::ReportNodeOnlineUsers(const std::vector<::api::OnlineUser>& online_users) {
    return impl_->ReportNodeOnlineUsers(online_users);
}

net::awaitable<bool>
APIClient::ReportUserTraffic(const std::vector<::api::UserTraffic>& data) {
    return impl_->ReportUserTraffic(data);
}

}  // namespace api::v2board

namespace api {

std::unique_ptr<API> CreatePanelClient(
    net::io_context& io_context,
    const Config& config,
    app::dns::DNS& dns_service) {
    return std::make_unique<v2board::APIClient>(io_context, config, dns_service);
}

}  // namespace api
