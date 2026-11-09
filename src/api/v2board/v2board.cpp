#include "api/api.hpp"
#include "common/ip_utils.hpp"
#include "core/constants.hpp"
#include "infra/config.hpp"
#include "transport/internet/http_headers.hpp"
#include "app/dns/dns.hpp"
#include "infra/json.hpp"
#include "infra/log.hpp"
#include "http_response.hpp"

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
#include <stdexcept>
#include <limits>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>
#include <openssl/x509_vfy.h>

namespace api::v2board {

namespace ssl = net::ssl;

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

}  // namespace

// ============================================================================
// APIClient 实现
// ============================================================================

class APIClient final : public ::api::API {
public:
    APIClient(net::io_context& io_context,
              const ::api::Config& config,
              ::app::dns::DNS& dns_service);
    ~APIClient() override = default;

    net::awaitable<NodeInfoFetchResult>
    GetNodeInfo(std::string committed_etag) override;

    net::awaitable<UserListFetchResult>
    GetUserList(std::string committed_etag) override;

    net::awaitable<bool>
    ReportNodeOnlineUsers(const std::vector<::api::OnlineUser>& online_users) override;

    net::awaitable<bool>
    ReportUserTraffic(const std::vector<::api::UserTraffic>& data) override;

private:
    [[nodiscard]] const std::string& ApiNodeType() const noexcept {
        return api_node_type_;
    }

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

    template <typename FetchResult>
    net::awaitable<tl::expected<HttpResponse, FetchResult>>
    FetchConditionalResource(std::string_view endpoint,
                             std::string committed_etag,
                             std::string_view missing_etag_error,
                             std::string_view pull_failure_label,
                             bool log_not_modified = false);

    net::io_context& io_context_;
    ::api::Config config_;
    const PanelLogContext log_context_;
    PanelApiUrlParts url_parts_;
    std::optional<net::ip::address> literal_address_;
    std::string api_node_type_;
    std::string host_header_;
    ::app::dns::DNS& dns_service_;

    std::unique_ptr<net::ssl::context> https_context_;
};

APIClient::APIClient(net::io_context& io_context,
                     const ::api::Config& config,
                     ::app::dns::DNS& dns_service)
    : io_context_(io_context)
    , config_(config)
    , log_context_{config_.Name, config_.APIHost, config_.NodeID, config_.NodeType}
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
    iputil::FormatHttpHostHeaderInto(
        host_header_, url_parts_.host, url_parts_.port, url_parts_.use_ssl);

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

net::awaitable<HttpResponse>
APIClient::HttpRequest(HttpMethod method,
                       std::string path,
                       std::string body_text,
                       std::string if_none_match) {
    return http::RunRequest(
        HttpExchange(method, std::move(path), std::move(body_text),
                     std::move(if_none_match)),
        config_.RequestTimeout);
}

net::awaitable<HttpResponse>
APIClient::HttpExchange(HttpMethod method,
                        std::string path,
                        std::string body_text,
                        std::string if_none_match) {
    HttpResponse result;

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
                LOG_PANEL_DEBUG(log_context_, "HTTPS endpoint connection failed: endpoint={} reason={}",
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
                LOG_PANEL_DEBUG(log_context_, "HTTP endpoint connection failed: endpoint={} reason={}",
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

template <typename FetchResult>
net::awaitable<tl::expected<HttpResponse, FetchResult>>
APIClient::FetchConditionalResource(std::string_view endpoint,
                                    std::string committed_etag,
                                    std::string_view missing_etag_error,
                                    std::string_view pull_failure_label,
                                    bool log_not_modified) {
    std::string path = std::format("/api/v1/server/UniProxy/{}?node_id={}&node_type={}",
                                   endpoint, config_.NodeID, ApiNodeType());
    auto resp = co_await HttpRequest(HttpMethod::Get, std::move(path), {}, committed_etag);
    if (resp.not_modified) {
        if (committed_etag.empty()) {
            co_return tl::unexpected(FetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                std::string(missing_etag_error)));
        }
        if (log_not_modified) {
            LOG_PANEL_DEBUG(log_context_, "Node users unchanged: HTTP status=304");
        }
        co_return tl::unexpected(FetchResult::NotModified());
    }
    if (resp.status != 200) {
        const auto error_message = FormatHttpFailure(resp);
        LOG_PANEL_DEBUG(log_context_, "{}: {}", pull_failure_label, error_message);
        co_return tl::unexpected(FetchResult::Fail(
            ErrorCode::PANEL_API_FAILED,
            error_message));
    }
    co_return resp;
}

net::awaitable<NodeInfoFetchResult>
APIClient::GetNodeInfo(std::string committed_etag) {
    auto fetched = co_await FetchConditionalResource<NodeInfoFetchResult>(
        "config",
        std::move(committed_etag),
        "received 304 without a committed node ETag",
        "Node configuration pull failed");
    if (!fetched) {
        co_return std::move(fetched.error());
    }
    auto& resp = *fetched;
    try {
        auto jv = json::parse(resp.body);
        if (!jv.is_object()) {
            LOG_PANEL_ERROR(log_context_, "Invalid node configuration: root JSON value must be an object");
            co_return NodeInfoFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                "root JSON value must be an object");
        }
        auto& j = jv.as_object();

        auto parsed_config = ParseNodeInfo(j, config_.NodeType);
        if (!parsed_config) {
            LOG_PANEL_ERROR(log_context_, "Invalid node configuration: {}", parsed_config.error());
            co_return NodeInfoFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                std::move(parsed_config.error()));
        }
        auto config = std::move(*parsed_config);

        auto rules = ExtractBlockDetectRules(j);

        LOG_PANEL_DEBUG(log_context_, "Node configuration received: protocol={} port={} network={}",
                        config.NodeType, config.Port, config.TransportProtocol);

        co_return NodeInfoFetchResult::Success(
            std::move(config), std::move(rules), std::move(resp.etag));

    } catch (const std::exception& e) {
        LOG_PANEL_ERROR(log_context_, "Node configuration parsing failed: {}", e.what());
        co_return NodeInfoFetchResult::Fail(ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
}

net::awaitable<UserListFetchResult>
APIClient::GetUserList(std::string committed_etag) {
    // Only the owner of a committed user snapshot may supply its validator.
    // A successful fetch alone must not acknowledge a failed runtime update.
    auto fetched = co_await FetchConditionalResource<UserListFetchResult>(
        "user",
        std::move(committed_etag),
        "received 304 without a committed user ETag",
        "User list pull failed",
        true);
    if (!fetched) {
        co_return std::move(fetched.error());
    }
    auto& resp = *fetched;
    try {
        auto jv = json::parse(resp.body);
        if (!jv.is_object()) {
            LOG_PANEL_ERROR(log_context_, "User list parsing failed: root JSON value must be an object");
            co_return UserListFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                "root JSON value must be an object");
        }
        auto& j = jv.as_object();

        auto users = ParseUserList(j);
        if (!users) {
            LOG_PANEL_ERROR(log_context_, "User list parsing failed: {}", users.error());
            co_return UserListFetchResult::Fail(
                ErrorCode::PANEL_INVALID_RESPONSE,
                std::move(users.error()));
        }

        LOG_PANEL_DEBUG(log_context_, "User list received: users={}", users->size());
        co_return UserListFetchResult::Success(std::move(*users), std::move(resp.etag));

    } catch (const std::exception& e) {
        LOG_PANEL_ERROR(log_context_, "User list parsing failed: {}", e.what());
        co_return UserListFetchResult::Fail(ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
}

net::awaitable<bool>
APIClient::ReportUserTraffic(const std::vector<::api::UserTraffic>& data) {
    const int node_id = config_.NodeID;

    // V2Board UniProxy push 格式: {user_id: [upload, download], ...}
    json::object body;
    for (const auto& t : data) {
        if (t.UID <= 0 || (t.Upload <= 0 && t.Download <= 0)) {
            continue;
        }
        const int64_t up = std::max<int64_t>(0, t.Upload);
        const int64_t down = std::max<int64_t>(0, t.Download);
        auto& entry = body[std::to_string(t.UID)];
        if (!entry.is_array()) {
            entry = json::array{up, down};
            continue;
        }
        auto& pair = entry.as_array();
        const int64_t prev_up = pair[0].as_int64();
        const int64_t prev_down = pair[1].as_int64();
        pair[0] = (up > INT64_MAX - prev_up) ? INT64_MAX : (prev_up + up);
        pair[1] = (down > INT64_MAX - prev_down) ? INT64_MAX : (prev_down + down);
    }
    const size_t reported_users = body.size();

    // 路径包含 node_id 和 node_type
    std::string path = std::format("/api/v1/server/UniProxy/push?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    auto resp = co_await HttpRequest(
        HttpMethod::Post, std::move(path), json::serialize(json::value(std::move(body))), {});

    if (resp.status != 200) {
        LOG_PANEL_WARN(log_context_, "Traffic API acceptance unknown: {}", FormatHttpFailure(resp));
        co_return false;
    }

    LOG_PANEL_DEBUG(log_context_, "Traffic API accepted: users={} (not a billing commit acknowledgement)", reported_users);
    co_return true;
}

net::awaitable<bool>
APIClient::ReportNodeOnlineUsers(const std::vector<::api::OnlineUser>& online_users) {
    const int node_id = config_.NodeID;
    auto report = BuildOnlineReportPayload(online_users, node_id);

    if (!report.alive_body.empty()) {
        const std::string alive_path = std::format(
            "/api/v1/server/UniProxy/alive?node_id={}&node_type={}",
            node_id, ApiNodeType());
        auto alive_resp = co_await HttpRequest(
            HttpMethod::Post, alive_path, json::serialize(json::value(std::move(report.alive_body))), {});
        if (alive_resp.status != 200) {
            LOG_PANEL_WARN(log_context_, "Online device report failed: {}", FormatHttpFailure(alive_resp));
            co_return false;
        }
    }

    LOG_PANEL_DEBUG(log_context_, "Online devices reported: users={} devices={}", report.user_count, report.device_count);
    co_return true;
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

namespace api::v2board {

namespace {

tl::expected<uint16_t, std::string> ParseServerPort(const json::object& source) {
    const auto* raw = source.if_contains("server_port");
    if (!raw || raw->is_null()) {
        return tl::unexpected("server_port is required");
    }
    const auto result = PanelUnsignedInteger(*raw);
    if (!result) {
        return tl::unexpected(
            "server_port must be an integer or decimal integer string");
    }
    if (*result == 0 || *result > std::numeric_limits<uint16_t>::max()) {
        return tl::unexpected("server_port must be between 1 and 65535");
    }
    return static_cast<uint16_t>(*result);
}

// 0 keeps the local default cadence; the bound keeps the value representable
// in NodeInfo and in steady_clock deadline arithmetic.
tl::expected<int, std::string> ParseReportInterval(
    const json::object& base, std::string_view field, int current) {
    const auto* raw = base.if_contains(field);
    if (!raw || raw->is_null()) {
        return current;
    }
    const auto seconds = PanelUnsignedInteger(*raw);
    if (!seconds || *seconds > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
        return tl::unexpected(std::format(
            "base_config.{} must be a non-negative integer number of seconds", field));
    }
    return static_cast<int>(*seconds);
}

tl::expected<const json::value*, std::string> ResolveAlias(
    const json::object& obj,
    std::string_view primary,
    std::string_view secondary,
    std::string_view context) {
    const auto* primary_val = obj.if_contains(primary);
    if (primary_val && primary_val->is_null()) {
        primary_val = nullptr;
    }
    const auto* secondary_val = obj.if_contains(secondary);
    if (secondary_val && secondary_val->is_null()) {
        secondary_val = nullptr;
    }
    if (primary_val && secondary_val && *primary_val != *secondary_val) {
        return tl::unexpected(std::format(
            "{} aliases '{}' and '{}' must match", context, primary, secondary));
    }
    return primary_val ? primary_val : secondary_val;
}

tl::expected<uint32_t, std::string> ParseRequiredPanelUint32(
    const json::object& source,
    std::string_view field) {
    const auto* raw = source.if_contains(field);
    if (!raw || raw->is_null()) {
        return tl::unexpected(std::format("{} is required", field));
    }
    const auto value = PanelUnsignedInteger(*raw);
    if (!value || *value > std::numeric_limits<uint32_t>::max()) {
        return tl::unexpected(std::format(
            "{} must be a non-negative 32-bit integer or decimal integer string",
            field));
    }
    return static_cast<uint32_t>(*value);
}

// Reads one alias pair; null and absent are both "not declared".
#define ACPP_RESOLVE_OR_RETURN(var, obj, primary, secondary)                   \
    const auto var##_res =                                                     \
        ResolveAlias(obj, primary, secondary, "REALITY tls_settings");         \
    if (!var##_res) {                                                          \
        return tl::unexpected(std::move(var##_res.error()));                   \
    }                                                                          \
    const json::value* const var = *var##_res

tl::expected<std::vector<std::string>, std::string> ReadPanelStringList(
    const json::value& value, std::string_view field, bool allow_scalar) {
    std::vector<std::string> out;
    if (allow_scalar && value.is_string()) {
        out.push_back(naming::LowerAscii(std::string(value.as_string())));
        return out;
    }
    if (!value.is_array()) {
        return tl::unexpected(allow_scalar
            ? std::format("REALITY {} must be a string or array", field)
            : std::format("REALITY {} must be an array", field));
    }
    for (const auto& item : value.as_array()) {
        if (!item.is_string()) {
            return tl::unexpected(std::format(
                "REALITY {} must contain only strings", field));
        }
        out.push_back(naming::LowerAscii(std::string(item.as_string())));
    }
    return out;
}

// Maps v2board tls_settings onto the shared REALITY server input; semantic
// validation belongs to infra::ApplyRealityServerInput.
tl::expected<void, std::string> MapRealitySettings(
    const json::object& rs,
    std::string_view tls_server_name,
    RealityConfig& out) {
    infra::RealityServerInput input;

    ACPP_RESOLVE_OR_RETURN(private_key, rs, "private_key", "privateKey");
    if (private_key) {
        if (!private_key->is_string()) {
            return tl::unexpected("REALITY private_key must be a string");
        }
        input.private_key = std::string(private_key->as_string());
    }

    ACPP_RESOLVE_OR_RETURN(server_names, rs, "server_names", "serverNames");
    ACPP_RESOLVE_OR_RETURN(server_name, rs, "server_name", "serverName");
    if (server_names) {
        auto names = ReadPanelStringList(*server_names, "server_names", false);
        if (!names) {
            return tl::unexpected(std::move(names.error()));
        }
        input.server_names = std::move(*names);
    }
    if (server_name) {
        if (!server_name->is_string()) {
            return tl::unexpected("REALITY server_name must be a string");
        }
        std::vector<std::string> single{
            naming::LowerAscii(std::string(server_name->as_string()))};
        if (server_names && input.server_names != single) {
            return tl::unexpected(
                "REALITY server_names and server_name must match");
        }
        input.server_names = std::move(single);
    } else if (!server_names && !tls_server_name.empty()) {
        input.server_names.emplace_back(tls_server_name);
    }

    ACPP_RESOLVE_OR_RETURN(short_ids, rs, "short_ids", "shortIds");
    ACPP_RESOLVE_OR_RETURN(short_id, rs, "short_id", "shortId");
    if (short_ids) {
        auto ids = ReadPanelStringList(*short_ids, "short_ids", false);
        if (!ids) {
            return tl::unexpected(std::move(ids.error()));
        }
        input.short_ids = std::move(*ids);
    }
    if (short_id) {
        auto ids = ReadPanelStringList(*short_id, "short_id", true);
        if (!ids) {
            return tl::unexpected(std::move(ids.error()));
        }
        if (short_ids && input.short_ids != *ids) {
            return tl::unexpected("REALITY short_ids and short_id must match");
        }
        input.short_ids = std::move(*ids);
    } else if (!short_ids) {
        // Panel mapping default: a node without short ids admits the empty id.
        input.short_ids.emplace_back();
    }

    ACPP_RESOLVE_OR_RETURN(server_port, rs, "server_port", "serverPort");
    std::optional<uint16_t> sp_port;
    if (server_port) {
        const auto port = PanelUnsignedInteger(*server_port);
        if (!port || *port == 0 ||
            *port > std::numeric_limits<uint16_t>::max()) {
            return tl::unexpected("REALITY tls_settings.server_port is invalid");
        }
        sp_port = static_cast<uint16_t>(*port);
    }
    if (const auto* dest = rs.if_contains("dest"); dest && !dest->is_null()) {
        if (!dest->is_string()) {
            return tl::unexpected("REALITY dest must be a string");
        }
        input.dest = std::string(dest->as_string());
    } else if (sp_port && !input.server_names.empty() &&
               !input.server_names.front().empty()) {
        // v2board sends the fallback port separately from the SNI host.
        input.dest = std::format("{}:{}", input.server_names.front(), *sp_port);
    }

    if (const auto* xver = rs.if_contains("xver"); xver && !xver->is_null()) {
        const auto value = PanelUnsignedInteger(*xver);
        if (!value) {
            return tl::unexpected(
                "REALITY xver must be an integer between 0 and 2");
        }
        input.xver = *value;
    }

    ACPP_RESOLVE_OR_RETURN(mldsa65_seed, rs, "mldsa65_seed", "mldsa65Seed");
    if (mldsa65_seed) {
        if (!mldsa65_seed->is_string()) {
            return tl::unexpected("REALITY mldsa65_seed must be a string");
        }
        input.mldsa65_seed = std::string(mldsa65_seed->as_string());
    }

    ACPP_RESOLVE_OR_RETURN(min_ver, rs, "min_client_ver", "minClientVer");
    if (min_ver) {
        if (!min_ver->is_string()) {
            return tl::unexpected("REALITY min_client_ver must be a string");
        }
        input.min_client_ver = std::string(min_ver->as_string());
    }
    ACPP_RESOLVE_OR_RETURN(max_ver, rs, "max_client_ver", "maxClientVer");
    if (max_ver) {
        if (!max_ver->is_string()) {
            return tl::unexpected("REALITY max_client_ver must be a string");
        }
        input.max_client_ver = std::string(max_ver->as_string());
    }

    ACPP_RESOLVE_OR_RETURN(max_time, rs, "max_time_diff", "maxTimeDiff");
    if (max_time) {
        const auto value = PanelUnsignedInteger(*max_time);
        if (!value) {
            return tl::unexpected(
                "REALITY max_time_diff must be a non-negative integer");
        }
        input.max_time_diff = *value;
    }

    if (auto applied = infra::ApplyRealityServerInput(input, out); !applied) {
        return applied;
    }
    // A synthesized dest always carries server_port; a declared one must agree.
    if (sp_port && out.HasDest() && out.dest_port != *sp_port) {
        return tl::unexpected("REALITY dest and server_port must not conflict");
    }
    return infra::ValidateInboundReality(out);
}

#undef ACPP_RESOLVE_OR_RETURN

constexpr uint64_t kBytesPerSecondPerMbps = 1024ULL * 1024ULL / 8ULL;
constexpr uint64_t kMaxSpeedLimitMbps =
    std::numeric_limits<uint64_t>::max() / kBytesPerSecondPerMbps;

tl::expected<uint64_t, std::string> ParseOptionalLimit(
    const json::object& source,
    std::string_view field,
    size_t user_index) {
    const auto* value = source.if_contains(field);
    if (!value || value->is_null()) return 0;

    const auto limit = PanelUnsignedInteger(*value);
    if (!limit) {
        return tl::unexpected(std::format(
            "users[{}].{} must be a non-negative integer or null", user_index, field));
    }
    return *limit;
}

tl::expected<std::string, std::string> ParseOptionalString(
    const json::object& source,
    std::string_view field,
    size_t user_index) {
    const auto* value = source.if_contains(field);
    if (!value || value->is_null()) return std::string{};
    if (!value->is_string()) {
        return tl::unexpected(std::format(
            "users[{}].{} must be a string or null", user_index, field));
    }
    if (ContainsControlCharacter(value->as_string())) {
        return tl::unexpected(std::format(
            "users[{}].{} contains control characters", user_index, field));
    }
    return std::string(value->as_string());
}

bool IsValidDevice(const ::api::OnlineUser& device) noexcept {
    return device.UID > 0 && !device.IP.empty();
}

bool DeviceLess(const ::api::OnlineUser& lhs, const ::api::OnlineUser& rhs) noexcept {
    if (lhs.UID != rhs.UID) return lhs.UID < rhs.UID;
    return lhs.IP < rhs.IP;
}

bool IsCanonicalDeviceList(std::span<const ::api::OnlineUser> devices) noexcept {
    for (size_t i = 0; i < devices.size(); ++i) {
        if (!IsValidDevice(devices[i])) {
            return false;
        }
        if (i > 0 && !DeviceLess(devices[i - 1], devices[i])) {
            return false;
        }
    }
    return true;
}

OnlineReportPayload BuildFromCanonicalDevices(
    std::span<const ::api::OnlineUser> devices,
    int node_id) {
    OnlineReportPayload result;
    if (devices.empty()) {
        return result;
    }
    const std::string suffix = "_" + std::to_string(node_id);
    result.device_count = devices.size();

    for (size_t i = 0; i < devices.size();) {
        const int64_t uid = devices[i].UID;
        size_t j = i;
        json::array alive_devices;
        while (j < devices.size() && devices[j].UID == uid) {
            alive_devices.push_back(devices[j].IP + suffix);
            ++j;
        }
        result.alive_body[std::to_string(uid)] = std::move(alive_devices);
        ++result.user_count;
        i = j;
    }
    return result;
}

}  // namespace

tl::expected<::api::NodeInfo, std::string> ParseNodeInfo(
    const json::object& source,
    std::string_view node_type) {
    auto port = ParseServerPort(source);
    if (!port) {
        return tl::unexpected(std::move(port.error()));
    }

    ::api::NodeInfo config;
    config.NodeType = naming::LowerAscii(std::string(node_type));
    config.Port = *port;

    if (const auto* network = source.if_contains("network");
        network && !network->is_null()) {
        if (!network->is_string()) {
            return tl::unexpected("network must be a string");
        }
        config.TransportProtocol =
            naming::LowerAscii(std::string(network->as_string()));
    }

    if (const auto* network_settings = source.if_contains("networkSettings");
        network_settings && !network_settings->is_null() &&
        !IsPanelEmptyObject(*network_settings)) {
        if (!network_settings->is_object()) {
            return tl::unexpected("networkSettings must be an object");
        }
        const auto& settings = network_settings->as_object();
        if (const auto* path = settings.if_contains("path");
            path && !path->is_null()) {
            if (!path->is_string()) {
                return tl::unexpected(
                    "networkSettings path must be a string");
            }
            config.Path = std::string(path->as_string());
        }
        if (const auto* service_name = settings.if_contains("serviceName");
            service_name && !service_name->is_null()) {
            if (!service_name->is_string()) {
                return tl::unexpected(
                    "networkSettings serviceName must be a string");
            }
            config.ServiceName = std::string(service_name->as_string());
        }
        if (const auto* headers = settings.if_contains("headers");
            headers && !headers->is_null() && !IsPanelEmptyObject(*headers)) {
            if (!headers->is_object()) {
                return tl::unexpected(
                    "networkSettings headers must be an object");
            }
            std::optional<std::string> host;
            for (const auto& [name, raw_value] : headers->as_object()) {
                if (transport::internet::NormalizeHttpHeaderName(name) != "host") {
                    continue;
                }
                if (!raw_value.is_string()) {
                    return tl::unexpected(
                        "networkSettings Host must be a string");
                }
                auto value = infra::NormalizeHttpAuthority(
                    raw_value.as_string(), "networkSettings Host");
                if (!value) {
                    return tl::unexpected(std::move(value.error()));
                }
                if (host && *host != *value) {
                    return tl::unexpected(
                        "networkSettings Host aliases must match");
                }
                host = std::move(*value);
            }
            config.Host = std::move(host).value_or("");
        }
    }

    // gRPC carries its service in serviceName, falling back to path; every
    // other transport uses path with the shared "/" default.
    if (config.TransportProtocol == constants::protocol::kGrpc) {
        if (config.ServiceName.empty()) {
            config.ServiceName = std::exchange(config.Path, {});
        }
        config.Path.clear();
        if (auto valid = infra::ValidateGrpcServiceName(
                config.ServiceName, "networkSettings serviceName");
            !valid) {
            return tl::unexpected(std::move(valid.error()));
        }
    } else {
        auto path = infra::NormalizeTransportPath(
            config.Path, "networkSettings path");
        if (!path) {
            return tl::unexpected(std::move(path.error()));
        }
        config.Path = std::move(*path);
    }

    if (const auto* tls = source.if_contains(constants::protocol::kTls);
        tls && !tls->is_null()) {
        // V2Board encodes 0 = none, 1 = TLS, 2 = REALITY; older panels send a
        // boolean. Any other value is ambiguous and rejects the node.
        if (const auto mode = PanelBoolean(*tls)) {
            config.EnableTLS = *mode;
        } else if (const auto mode = PanelUnsignedInteger(*tls); mode && *mode <= 2) {
            config.EnableTLS = (*mode == 1);
            config.EnableReality = (*mode == 2);
        } else {
            return tl::unexpected(
                "tls must be a boolean or integer 0, 1, or 2");
        }
    }

    if (const auto* flow = source.if_contains("flow");
        flow && !flow->is_null()) {
        if (!flow->is_string()) {
            return tl::unexpected("flow must be a string");
        }
        config.Flow = naming::LowerAscii(std::string(flow->as_string()));
    }

    if (const auto* server_name = source.if_contains("server_name");
        server_name && !server_name->is_null()) {
        if (!server_name->is_string()) {
            return tl::unexpected("server_name must be a string");
        }
        auto normalized = infra::NormalizeTlsServerName(
            server_name->as_string(), "server_name");
        if (!normalized) {
            return tl::unexpected(std::move(normalized.error()));
        }
        config.TLSServerName = std::move(*normalized);
    }
    if (const auto* cipher = source.if_contains("cipher");
        cipher && !cipher->is_null()) {
        if (!cipher->is_string()) {
            return tl::unexpected("cipher must be a string");
        }
        config.CypherMethod =
            naming::LowerAscii(std::string(cipher->as_string()));
    }
    if (const auto* server_key = source.if_contains("server_key");
        server_key && !server_key->is_null()) {
        if (!server_key->is_string()) {
            return tl::unexpected("server_key must be a string");
        }
        config.ShadowsocksServerKey = std::string(server_key->as_string());
    }
    if (const auto* host = source.if_contains("host");
        host && !host->is_null() && !host->is_string()) {
        return tl::unexpected("host must be a string");
    }

    if (config.NodeType == constants::protocol::kShadowsocks) {
        if (const auto* obfs = source.if_contains("obfs");
            obfs && !obfs->is_null()) {
            if (!obfs->is_string()) {
                return tl::unexpected("obfs must be a string or null");
            }
            const std::string mode =
                naming::LowerAscii(std::string(obfs->as_string()));
            if (!mode.empty() && mode != constants::protocol::kNone) {
                return tl::unexpected(
                    "Shadowsocks obfs is not supported by this runtime");
            }
        }
        if (const auto* settings = source.if_contains("obfs_settings");
            settings && !settings->is_null() && !settings->is_object() &&
            !IsPanelEmptyObject(*settings)) {
            return tl::unexpected("obfs_settings must be an object or null");
        }
    }

    if (config.NodeType == constants::protocol::kVless) {
        if (const auto* encryption = source.if_contains("encryption");
            encryption && !encryption->is_null()) {
            if (!encryption->is_string()) {
                return tl::unexpected("encryption must be a string or null");
            }
            const std::string mode =
                naming::LowerAscii(std::string(encryption->as_string()));
            if (!mode.empty() && mode != constants::protocol::kNone) {
                return tl::unexpected(
                    "panel VLESS encryption is not supported by this runtime");
            }
        }
        if (const auto* settings = source.if_contains("encryption_settings");
            settings && !settings->is_null() && !settings->is_object() &&
            !IsPanelEmptyObject(*settings)) {
            return tl::unexpected(
                "encryption_settings must be an object or null");
        }
        if (const auto* settings = source.if_contains("tls_settings");
            settings && !settings->is_null() && !settings->is_object() &&
            !IsPanelEmptyObject(*settings)) {
            return tl::unexpected("tls_settings must be an object or null");
        }
    }

    if (config.NodeType == constants::protocol::kAnyTLS) {
        if (const auto* padding = source.if_contains("padding_scheme")) {
            auto scheme = infra::ParseAnyTlsPaddingScheme(*padding, "padding_scheme");
            if (!scheme) {
                return tl::unexpected(std::move(scheme.error()));
            }
            config.PaddingScheme = std::move(*scheme);
        }
    }

    if (config.NodeType == constants::protocol::kHysteria ||
        config.NodeType == constants::protocol::kHysteria2) {
        auto version = ParseRequiredPanelUint32(source, "version");
        if (!version || (*version != 1 && *version != 2)) {
            return tl::unexpected(
                version ? "version must be 1 or 2" : std::move(version.error()));
        }
        config.NodeType = *version == 1
            ? std::string(constants::protocol::kHysteria)
            : std::string(constants::protocol::kHysteria2);

        auto up_mbps = ParseRequiredPanelUint32(source, "up_mbps");
        if (!up_mbps) {
            return tl::unexpected(std::move(up_mbps.error()));
        }
        auto down_mbps = ParseRequiredPanelUint32(source, "down_mbps");
        if (!down_mbps) {
            return tl::unexpected(std::move(down_mbps.error()));
        }
        config.HysteriaUpMbps = *up_mbps;
        config.HysteriaDownMbps = *down_mbps;

        if (const auto* ignored = source.if_contains("ignore_client_bandwidth");
            ignored && !ignored->is_null() && !PanelBoolean(*ignored)) {
            return tl::unexpected(
                "ignore_client_bandwidth must be a boolean or 0/1");
        }

        for (const std::string_view field : {"obfs", "obfs-password"}) {
            const auto* value = source.if_contains(field);
            if (!value || value->is_null()) {
                continue;
            }
            if (!value->is_string()) {
                return tl::unexpected(std::format(
                    "{} must be a string or null", field));
            }
            if (!value->as_string().empty()) {
                return tl::unexpected(
                    "Hysteria obfs is not supported by this runtime");
            }
        }
    }


    if (config.EnableReality) {
        const auto tls_settings_res =
            ResolveAlias(source, "tls_settings", "tlsSettings", "REALITY");
        if (!tls_settings_res) {
            return tl::unexpected(std::move(tls_settings_res.error()));
        }
        const auto* tls_settings_val = *tls_settings_res;
        if (!tls_settings_val || !tls_settings_val->is_object()) {
            return tl::unexpected(
                "REALITY node requires tls_settings object");
        }
        auto mapped = MapRealitySettings(
            tls_settings_val->as_object(), config.TLSServerName, config.Reality);
        if (!mapped) {
            return tl::unexpected(std::move(mapped.error()));
        }
    }
    if (const auto* base_config = source.if_contains("base_config");
        base_config && !base_config->is_null()) {
        if (!base_config->is_object()) {
            return tl::unexpected("base_config must be an object");
        }
        const auto& base = base_config->as_object();
        auto pull = ParseReportInterval(base, "pull_interval", config.PullInterval);
        if (!pull) {
            return tl::unexpected(std::move(pull.error()));
        }
        auto push = ParseReportInterval(base, "push_interval", config.PushInterval);
        if (!push) {
            return tl::unexpected(std::move(push.error()));
        }
        config.PullInterval = *pull;
        config.PushInterval = *push;
    }

    return config;
}

std::vector<rule::DetectRule> ExtractBlockDetectRules(
    const json::object& config) {
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
                throw std::invalid_argument(
                    "block route match entries must be strings");
            }
            const std::string_view entry = match.as_string();
            if (entry.empty()) {
                throw std::invalid_argument(
                    "block route match entries must not be empty");
            }
            if (ContainsControlCharacter(entry)) {
                throw std::invalid_argument(
                    "block route match entries must not contain control characters");
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

tl::expected<std::vector<::api::UserInfo>, std::string>
ParseUserList(const json::object& source) {
    const auto* users_value = source.if_contains("users");
    if (!users_value) {
        return tl::unexpected("users is required");
    }
    if (!users_value->is_array()) {
        return tl::unexpected("users must be an array");
    }

    const auto& users_array = users_value->as_array();
    std::vector<::api::UserInfo> users;
    users.reserve(users_array.size());
    // A repeated id would merge accounting for two users. Credentials are
    // compared after protocol derivation, when the UserStore snapshot is built.
    std::unordered_set<int64_t> seen_ids;
    seen_ids.reserve(users_array.size());
    for (size_t i = 0; i < users_array.size(); ++i) {
        const auto& user_value = users_array[i];
        if (!user_value.is_object()) {
            return tl::unexpected(std::format("users[{}] must be an object", i));
        }
        const auto& source_user = user_value.as_object();
        ::api::UserInfo user;

        const auto* id = source_user.if_contains("id");
        const auto parsed_id = id ? PanelUnsignedInteger(*id) : std::nullopt;
        if (!parsed_id || *parsed_id == 0 ||
            *parsed_id > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            return tl::unexpected(std::format(
                "users[{}].id must be a positive int64", i));
        }
        user.UID = static_cast<int64_t>(*parsed_id);
        if (!seen_ids.insert(user.UID).second) {
            return tl::unexpected(std::format("users[{}].id duplicates another user", i));
        }

        const auto* uuid = source_user.if_contains("uuid");
        if (!uuid || !uuid->is_string() || uuid->as_string().empty()) {
            return tl::unexpected(std::format(
                "users[{}].uuid must be a non-empty string", i));
        }
        if (ContainsControlCharacter(uuid->as_string())) {
            return tl::unexpected(std::format(
                "users[{}].uuid contains control characters", i));
        }
        user.UUID = std::string(uuid->as_string());

        auto flow = ParseOptionalString(source_user, "flow", i);
        if (!flow) return tl::unexpected(std::move(flow.error()));
        user.Flow = naming::LowerAscii(std::move(*flow));

        auto speed_limit = ParseOptionalLimit(source_user, "speed_limit", i);
        if (!speed_limit) {
            return tl::unexpected(std::move(speed_limit.error()));
        }
        if (*speed_limit > kMaxSpeedLimitMbps) {
            return tl::unexpected(std::format(
                "users[{}].speed_limit exceeds {} Mbps",
                i, kMaxSpeedLimitMbps));
        }
        user.SpeedLimit = *speed_limit * kBytesPerSecondPerMbps;

        auto device_limit = ParseOptionalLimit(source_user, "device_limit", i);
        if (!device_limit) {
            return tl::unexpected(std::move(device_limit.error()));
        }
        if (*device_limit > std::numeric_limits<uint32_t>::max()) {
            return tl::unexpected(std::format(
                "users[{}].device_limit exceeds {}",
                i, std::numeric_limits<uint32_t>::max()));
        }
        user.DeviceLimit = static_cast<uint32_t>(*device_limit);

        auto email = ParseOptionalString(source_user, "email", i);
        if (!email) return tl::unexpected(std::move(email.error()));
        user.Email = std::move(*email);
        users.push_back(std::move(user));
    }
    return users;
}

OnlineReportPayload BuildOnlineReportPayload(
    std::span<const ::api::OnlineUser> online_devices,
    int node_id) {
    if (IsCanonicalDeviceList(online_devices)) {
        return BuildFromCanonicalDevices(online_devices, node_id);
    }

    std::vector<::api::OnlineUser> valid;
    valid.reserve(online_devices.size());
    for (const auto& device : online_devices) {
        if (IsValidDevice(device)) {
            valid.push_back(device);
        }
    }

    std::ranges::sort(valid, DeviceLess);
    const auto duplicate_tail = std::ranges::unique(
        valid, [](const ::api::OnlineUser& lhs, const ::api::OnlineUser& rhs) {
            return lhs.UID == rhs.UID && lhs.IP == rhs.IP;
        });
    valid.erase(duplicate_tail.begin(), duplicate_tail.end());

    return BuildFromCanonicalDevices(valid, node_id);
}

}  // namespace api::v2board
