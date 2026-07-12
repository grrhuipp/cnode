#include "acppnode/api/panel_factory.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/infra/json.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"

#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>
#include <asio/connect.hpp>
#include <asio/read.hpp>
#include <asio/read_until.hpp>
#include <asio/write.hpp>
#include <asio/steady_timer.hpp>
#include <cctype>
#include <format>
#include <istream>
#include <limits>
#include <map>
#include <regex>
#include <sstream>
#include <vector>
#include <openssl/x509_vfy.h>

#ifdef _WIN32
#include <openssl/x509.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
// 将 Windows 系统根证书库导入 OpenSSL SSL_CTX
static void LoadWindowsCACerts(asio::ssl::context& ctx) {
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

namespace acpp::api::v2board {

namespace ssl = net::ssl;

class APIClient final : public ::acpp::api::API {
public:
    APIClient(net::io_context& io_context, const ::acpp::api::Config& config,
              ::acpp::app::dns::DNS& dns_service);
    ~APIClient() override;

    ::acpp::api::ClientInfo Describe() const override;

    net::awaitable<NodeInfoFetchResult>
    GetNodeInfo() override;

    net::awaitable<UserListFetchResult>
    GetUserList() override;

    net::awaitable<bool>
    ReportNodeStatus(const ::acpp::api::NodeStatus& node_status) override;

    net::awaitable<bool>
    ReportNodeOnlineUsers(const std::vector<::acpp::api::OnlineUser>& online_users) override;

    net::awaitable<bool>
    ReportUserTraffic(const std::vector<::acpp::api::UserTraffic>& data) override;

    net::awaitable<RuleListFetchResult>
    GetNodeRule() override;

    net::awaitable<bool>
    ReportIllegal(const std::vector<::acpp::api::DetectResult>& detect_results) override;

    void Debug() override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

namespace {

constexpr size_t kHttpErrorDetailLimit = 256;

struct HttpResponse {
    int status = 0;
    std::string body;
    std::string etag;
    bool not_modified = false;
};

enum class HttpMethod : uint8_t {
    Get,
    Post,
};

struct UrlParts {
    bool use_ssl = false;
    std::string host;
    std::string port;
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
    const std::string detail = CompactLogText(resp.body);

    if (resp.status <= 0) {
        if (!detail.empty()) {
            return std::format(
                "request failed before HTTP response (status {}): {}",
                resp.status, detail);
        }
        return std::format("request failed before HTTP response (status {})",
                           resp.status);
    }

    if (!detail.empty()) {
        return std::format("HTTP status {}: {}", resp.status, detail);
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

std::string JoinRouteMatches(const json::array& matches) {
    std::string pattern;
    for (const auto& match : matches) {
        if (!match.is_string()) {
            continue;
        }
        if (!pattern.empty()) {
            pattern.push_back('|');
        }
        pattern += match.as_string();
    }
    return pattern;
}

std::vector<::acpp::api::DetectRule>
ExtractBlockDetectRules(const json::object& config, std::string_view panel_name) {
    std::vector<::acpp::api::DetectRule> rules;
    const auto* routes_value = config.if_contains("routes");
    if (!routes_value || !routes_value->is_array()) {
        return rules;
    }

    const auto& routes = routes_value->as_array();
    rules.reserve(routes.size());
    for (size_t i = 0; i < routes.size(); ++i) {
        const auto& route_value = routes[i];
        if (!route_value.is_object()) {
            continue;
        }

        const auto& route = route_value.as_object();
        const auto* action = route.if_contains("action");
        if (!action || !action->is_string() || action->as_string() != "block") {
            continue;
        }

        const auto* match_value = route.if_contains("match");
        if (!match_value || !match_value->is_array()) {
            continue;
        }

        const std::string pattern = JoinRouteMatches(match_value->as_array());
        if (pattern.empty()) {
            continue;
        }

        try {
            ::acpp::api::DetectRule rule;
            rule.ID = static_cast<int>(i);
            rule.Pattern = std::regex(pattern);
            rules.push_back(std::move(rule));
        } catch (const std::regex_error& e) {
            LOG_WARN("V2Board[{}]: invalid block route detect rule {}: {}",
                     panel_name, i, e.what());
        }
    }
    return rules;
}

std::string HeaderNameLower(std::string_view name) {
    std::string out;
    out.reserve(name.size());
    for (unsigned char ch : name) {
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

std::string TrimHeaderValue(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
        value.remove_suffix(1);
    }
    return std::string(value);
}

int HexValue(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

std::optional<size_t> ParseChunkSize(std::string_view line) {
    size_t size = 0;
    bool has_digit = false;
    for (char ch : line) {
        if (ch == ';') break;
        if (ch == ' ' || ch == '\t' || ch == '\r') continue;
        const int value = HexValue(ch);
        if (value < 0) {
            return std::nullopt;
        }
        has_digit = true;
        if (size > (std::numeric_limits<size_t>::max() - static_cast<size_t>(value)) / 16) {
            return std::nullopt;
        }
        size = size * 16 + static_cast<size_t>(value);
    }
    if (!has_digit) {
        return std::nullopt;
    }
    return size;
}

std::optional<std::string> DecodeChunkedBody(std::string_view raw_body) {
    std::string decoded;
    size_t pos = 0;

    while (true) {
        const size_t line_end = raw_body.find("\r\n", pos);
        if (line_end == std::string_view::npos) {
            return std::nullopt;
        }

        auto chunk_size = ParseChunkSize(raw_body.substr(pos, line_end - pos));
        if (!chunk_size) {
            return std::nullopt;
        }

        pos = line_end + 2;
        if (*chunk_size == 0) {
            return decoded;
        }

        if (raw_body.size() - pos < *chunk_size + 2) {
            return std::nullopt;
        }
        decoded.append(raw_body.substr(pos, *chunk_size));
        pos += *chunk_size;

        if (raw_body.substr(pos, 2) != "\r\n") {
            return std::nullopt;
        }
        pos += 2;
    }
}

void AppendStreambuf(net::streambuf& buffer, std::string& out) {
    std::istream is(&buffer);
    out.append(std::istreambuf_iterator<char>(is), std::istreambuf_iterator<char>());
}

template <typename Stream>
net::awaitable<void> WriteHttpRequest(Stream& stream, const std::string& request) {
    co_await net::async_write(stream, net::buffer(request), net::use_awaitable);
}

template <typename Stream>
net::awaitable<HttpResponse> ReadHttpResponse(Stream& stream) {
    HttpResponse result;
    net::streambuf buffer;

    co_await net::async_read_until(stream, buffer, "\r\n\r\n", net::use_awaitable);

    std::istream header_stream(&buffer);
    std::string status_line;
    std::getline(header_stream, status_line);
    if (!status_line.empty() && status_line.back() == '\r') {
        status_line.pop_back();
    }

    std::istringstream status_parser(status_line);
    std::string http_version;
    status_parser >> http_version >> result.status;
    if (result.status <= 0) {
        result.status = -1;
        result.body = "invalid HTTP status line: " + status_line;
        co_return result;
    }
    result.not_modified = (result.status == 304);

    size_t content_length = 0;
    bool has_content_length = false;
    bool is_chunked = false;

    std::string line;
    while (std::getline(header_stream, line)) {
        if (line == "\r" || line.empty()) break;
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        const auto name = HeaderNameLower(std::string_view(line).substr(0, colon));
        const auto value = TrimHeaderValue(std::string_view(line).substr(colon + 1));

        if (name == "etag") {
            result.etag = value;
            if (result.etag.size() >= 2 && result.etag.front() == '"' && result.etag.back() == '"') {
                result.etag = result.etag.substr(1, result.etag.size() - 2);
            }
        } else if (name == "transfer-encoding") {
            std::string lowered = value;
            for (char& ch : lowered) {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }
            is_chunked = lowered.find("chunked") != std::string::npos;
        } else if (name == "content-length") {
            try {
                content_length = static_cast<size_t>(std::stoull(value));
                has_content_length = true;
            } catch (...) {
                result.status = -1;
                result.body = "invalid Content-Length";
                co_return result;
            }
        }
    }

    if (is_chunked) {
        IoErrorCode ec;
        while (true) {
            auto [read_ec, bytes] = co_await stream.async_read_some(
                buffer.prepare(8192), net::as_tuple(net::use_awaitable));
            if (bytes > 0) {
                buffer.commit(bytes);
                AppendStreambuf(buffer, result.body);
            }
            if (read_ec == io_error::eof) break;
            if (read_ec) {
                result.status = -1;
                result.body = read_ec.message();
                co_return result;
            }
        }

        auto decoded = DecodeChunkedBody(result.body);
        if (!decoded) {
            result.status = -1;
            result.body = "invalid chunked HTTP response";
            co_return result;
        }
        result.body = std::move(*decoded);
        co_return result;
    }

    AppendStreambuf(buffer, result.body);

    if (has_content_length) {
        if (result.body.size() < content_length) {
            co_await net::async_read(
                stream, buffer,
                net::transfer_exactly(content_length - result.body.size()),
                net::use_awaitable);
            AppendStreambuf(buffer, result.body);
        } else if (result.body.size() > content_length) {
            result.body.resize(content_length);
        }
    } else {
        IoErrorCode ec;
        while (true) {
            auto [read_ec, bytes] = co_await stream.async_read_some(
                buffer.prepare(8192), net::as_tuple(net::use_awaitable));
            if (bytes > 0) {
                buffer.commit(bytes);
                AppendStreambuf(buffer, result.body);
            }
            if (read_ec == io_error::eof) break;
            if (read_ec) {
                result.status = -1;
                result.body = read_ec.message();
                co_return result;
            }
        }
    }

    co_return result;
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

    [[nodiscard]] ::acpp::api::ClientInfo Describe() const;
    [[nodiscard]] std::string ApiNodeType() const;

    net::ssl::context* GetOrCreateHttpsContext();

    net::awaitable<HttpResponse>
    HttpGet(const std::string& path, const std::string& etag = "");

    net::awaitable<HttpResponse>
    HttpPost(const std::string& path, const json::value& body);

    net::awaitable<HttpResponse>
    HttpRequest(HttpMethod method,
                const std::string& path,
                const std::optional<json::value>& body,
                const std::string& if_none_match = "");

    net::awaitable<NodeInfoFetchResult> GetNodeInfo();
    net::awaitable<UserListFetchResult> GetUserList();
    net::awaitable<bool> ReportNodeStatus(const ::acpp::api::NodeStatus& node_status);
    net::awaitable<bool> ReportNodeOnlineUsers(const std::vector<::acpp::api::OnlineUser>& online_users);
    net::awaitable<bool> ReportUserTraffic(const std::vector<::acpp::api::UserTraffic>& data);
    net::awaitable<RuleListFetchResult> GetNodeRule();
    net::awaitable<bool> ReportIllegal(const std::vector<::acpp::api::DetectResult>& detect_results);
    void Debug();

    net::io_context& io_context_;
    ::acpp::api::Config config_;
    UrlParts url_parts_;
    ::acpp::app::dns::DNS& dns_service_;

    std::string config_etag_;
    std::string users_etag_;

    std::optional<::acpp::api::NodeInfo> cached_config_;
    std::vector<::acpp::api::DetectRule> cached_route_rules_;
    std::unique_ptr<net::ssl::context> https_context_;
    bool debug_enabled_ = false;
};

APIClient::Impl::Impl(net::io_context& io_context,
                      const ::acpp::api::Config& config,
                      ::acpp::app::dns::DNS& dns_service)
    : io_context_(io_context)
    , config_(config)
    , dns_service_(dns_service) {

    auto parts = ParseUrl(config.APIHost);
    if (parts) {
        url_parts_ = *parts;
    } else {
        LOG_ERROR("V2Board[{}]: invalid API host: {}", config.Name, config.APIHost);
    }
}

::acpp::api::ClientInfo APIClient::Impl::Describe() const {
    return ::acpp::api::ClientInfo{
        .APIHost = config_.APIHost,
        .NodeID = config_.NodeID,
        .Key = config_.Key,
        .NodeType = config_.NodeType,
    };
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

    IoErrorCode ec;
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

net::awaitable<HttpResponse>
APIClient::Impl::HttpPost(const std::string& path, const json::value& body) {
    co_return co_await HttpRequest(HttpMethod::Post, path, body, "");
}

net::awaitable<HttpResponse>
APIClient::Impl::HttpGet(const std::string& path, const std::string& etag) {
    co_return co_await HttpRequest(HttpMethod::Get, path, std::nullopt, etag);
}

net::ssl::context* APIClient::Impl::GetOrCreateHttpsContext() {
    if (!url_parts_.use_ssl) {
        return nullptr;
    }
    if (https_context_) {
        return https_context_.get();
    }

    auto ctx = std::make_unique<ssl::context>(ssl::context::tlsv12_client);
#ifdef _WIN32
    LoadWindowsCACerts(*ctx);
#else
    ctx->set_default_verify_paths();
#endif
    ctx->set_verify_mode(ssl::verify_peer);
    https_context_ = std::move(ctx);
    return https_context_.get();
}

net::awaitable<HttpResponse>
APIClient::Impl::HttpRequest(HttpMethod method, const std::string& path,
                          const std::optional<json::value>& body,
                          const std::string& if_none_match) {

    HttpResponse result;

    try {
        if (url_parts_.host.empty() || url_parts_.port.empty()) {
            result.status = -1;
            result.body = "invalid API host";
            co_return result;
        }

        // 面板同步是冷路径；保留完整候选地址，避免双栈环境只尝试第一个解析结果。
        std::vector<tcp::endpoint> endpoints;
        uint16_t port = static_cast<uint16_t>(std::stoi(url_parts_.port));

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

        if (endpoints.empty()) {
            result.status = 0;
            result.body = "DNS resolve failed";
            co_return result;
        }

        // 构建完整路径（所有请求都在 URL 参数中传 token）
        std::string full_path = url_parts_.path_prefix + path;
        if (full_path.find('?') != std::string::npos) {
            full_path += "&token=" + config_.Key;
        } else {
            full_path += "?token=" + config_.Key;
        }

        std::string body_text;
        if (body.has_value()) {
            body_text = json::serialize(*body);
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
        if (body.has_value()) {
            request += "Content-Type: application/json\r\nContent-Length: ";
            request += std::to_string(body_text.size());
            request += "\r\n";
        }
        request += "\r\n";
        request += body_text;

        if (debug_enabled_) {
            LOG_DEBUG("V2Board[{}]: {} {}", config_.Name, MethodName(method), path);
        }

        if (url_parts_.use_ssl) {
            // HTTPS
            auto ssl_ctx = GetOrCreateHttpsContext();
            if (!ssl_ctx) {
                result.status = -1;
                result.body = "SSL context init failed";
                co_return result;
            }

            std::string last_error;
            for (const auto& endpoint : endpoints) {
                try {
                    ssl::stream<tcp::socket> stream(io_context_, *ssl_ctx);
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

                    co_await WriteHttpRequest(stream, request);
                    result = co_await ReadHttpResponse(stream);
                    if (debug_enabled_) {
                        LOG_DEBUG("V2Board[{}]: {} {} -> HTTP {}",
                                  config_.Name, MethodName(method), path, result.status);
                    }

                    IoErrorCode ec;
                    co_await stream.async_shutdown(net::redirect_error(net::use_awaitable, ec));
                    co_return result;
                } catch (const std::exception& e) {
                    last_error = e.what();
                    LOG_DEBUG("V2Board[{}]: HTTPS endpoint {} failed: {}",
                              config_.Name,
                              iputil::FormatEndpointForLog(endpoint.address().to_string(), endpoint.port()),
                              last_error);
                }
            }
            result.status = -1;
            result.body = last_error.empty() ? "HTTPS connect failed" : last_error;

        } else {
            // HTTP
            std::string last_error;
            for (const auto& endpoint : endpoints) {
                try {
                    tcp::socket stream(io_context_);

                    co_await stream.async_connect(endpoint, net::use_awaitable);

                    co_await WriteHttpRequest(stream, request);
                    result = co_await ReadHttpResponse(stream);
                    if (debug_enabled_) {
                        LOG_DEBUG("V2Board[{}]: {} {} -> HTTP {}",
                                  config_.Name, MethodName(method), path, result.status);
                    }

                    IoErrorCode ec;
                    stream.shutdown(tcp::socket::shutdown_both, ec);
                    stream.close(ec);
                    co_return result;
                } catch (const std::exception& e) {
                    last_error = e.what();
                    LOG_DEBUG("V2Board[{}]: HTTP endpoint {} failed: {}",
                              config_.Name,
                              iputil::FormatEndpointForLog(endpoint.address().to_string(), endpoint.port()),
                              last_error);
                }
            }
            result.status = -1;
            result.body = last_error.empty() ? "HTTP connect failed" : last_error;
        }

        co_return result;

    } catch (const std::exception& e) {
        LOG_DEBUG("V2Board[{}]: HTTP error: {}", config_.Name, e.what());
        result.status = -1;
        result.body = e.what();
        co_return result;
    }
}

net::awaitable<NodeInfoFetchResult>
APIClient::Impl::GetNodeInfo() {
    const int node_id = config_.NodeID;

    // GET /api/v1/server/UniProxy/config?node_id=X&node_type=Y
    std::string path = std::format("/api/v1/server/UniProxy/config?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    // 使用存储的 ETag
    auto resp = co_await HttpGet(path, config_etag_);

    // 304 Not Modified - 返回缓存
    if (resp.not_modified) {
        if (cached_config_) {
            LOG_DEBUG("V2Board[{}]: node {} config not modified (304)", config_.Name, node_id);
            co_return NodeInfoFetchResult::Success(*cached_config_);
        }
        co_return NodeInfoFetchResult::Fail(
            ErrorCode::PANEL_INVALID_RESPONSE,
            "received 304 without cached node config");
    }

    if (resp.status == 404) {
        LOG_DEBUG("V2Board[{}]: node {} config not found", config_.Name, node_id);
        config_etag_.clear();
        cached_config_.reset();
        cached_route_rules_.clear();
        co_return NodeInfoFetchResult::Missing();
    }

    if (resp.status != 200) {
        const auto error_message = FormatHttpFailure(resp);
        LOG_DEBUG("V2Board[{}]: GetNodeInfo failed: {}", config_.Name,
                  error_message);
        co_return NodeInfoFetchResult::Fail(
            ErrorCode::PANEL_API_FAILED,
            error_message);
    }

    try {
        auto jv = json::parse(resp.body);
        auto& j = jv.as_object();

        ::acpp::api::NodeInfo config;
        config.NodeID = node_id;
        config.NodeType = config_.NodeType;  // 使用面板配置中的节点类型

        auto* sp = j.if_contains("server_port");
        config.Port = (sp && sp->is_int64()) ? static_cast<uint16_t>(sp->as_int64()) : 0;
        auto* np = j.if_contains("network");
        config.TransportProtocol = (np && np->is_string())
            ? std::string(np->as_string())
            : std::string(constants::protocol::kTcp);

        // networkSettings 可能是 null
        auto* nsp = j.if_contains("networkSettings");
        if (nsp && nsp->is_object()) {
            auto& ns = nsp->as_object();
            auto* pp = ns.if_contains("path");
            config.Path = (pp && pp->is_string()) ? std::string(pp->as_string()) : "";
            auto* hp = ns.if_contains("headers");
            if (hp && hp->is_object()) {
                auto* hostp = hp->as_object().if_contains("Host");
                config.Host = (hostp && hostp->is_string()) ? std::string(hostp->as_string()) : "";
            }
        }

        // tls 可能是 null 或 0/1
        auto* tlsp = j.if_contains(constants::protocol::kTls);
        if (tlsp && !tlsp->is_null()) {
            if (tlsp->is_int64()) config.EnableTLS = tlsp->as_int64() != 0;
            else if (tlsp->is_bool()) config.EnableTLS = tlsp->as_bool();
        }

        // server_name / sni
        auto* snip = j.if_contains("server_name");
        if (snip && snip->is_string()) {
            config.TLSServerName = std::string(snip->as_string());
        }

        // cipher（Shadowsocks 加密方法）
        auto* ciphp = j.if_contains("cipher");
        if (ciphp && ciphp->is_string()) {
            config.CypherMethod = std::string(ciphp->as_string());
        }
        auto* ss_server_key = j.if_contains("server_key");
        if (ss_server_key && ss_server_key->is_string()) {
            config.ShadowsocksServerKey = std::string(ss_server_key->as_string());
        }

        auto* bcp = j.if_contains("base_config");
        if (bcp && bcp->is_object()) {
            auto& bc = bcp->as_object();
            auto* pi = bc.if_contains("pull_interval");
            config.PullInterval = (pi && pi->is_int64()) ? static_cast<int>(pi->as_int64()) : 60;
            auto* pu = bc.if_contains("push_interval");
            config.PushInterval = (pu && pu->is_int64()) ? static_cast<int>(pu->as_int64()) : 60;
        }

        cached_route_rules_ = ExtractBlockDetectRules(j, config_.Name);

        // 保存 ETag 和缓存
        if (!resp.etag.empty()) {
            config_etag_ = resp.etag;
        }
        cached_config_ = config;

        LOG_DEBUG("V2Board[{}]: node {} config: protocol={}, port={}, network={}",
                 config_.Name, node_id, config.NodeType, config.Port, config.TransportProtocol);

        co_return NodeInfoFetchResult::Success(std::move(config));

    } catch (const std::exception& e) {
        LOG_ERROR("V2Board[{}]: parse config error: {}", config_.Name, e.what());
        co_return NodeInfoFetchResult::Fail(ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
}

net::awaitable<UserListFetchResult>
APIClient::Impl::GetUserList() {
    const int node_id = config_.NodeID;

    // GET /api/v1/server/UniProxy/user?node_id=X&node_type=Y
    std::string path = std::format("/api/v1/server/UniProxy/user?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    // 使用存储的 ETag
    auto resp = co_await HttpGet(path, users_etag_);

    // 304 Not Modified - 交给上层直接跳过用户重建，避免额外常驻缓存和拷贝
    if (resp.not_modified) {
        LOG_DEBUG("V2Board[{}]: node {} users not modified (304)",
                 config_.Name, node_id);
        co_return UserListFetchResult::NotModified();
    }

    if (resp.status != 200) {
        const auto error_message = FormatHttpFailure(resp);
        LOG_DEBUG("V2Board[{}]: GetUserList failed: {}", config_.Name,
                  error_message);
        co_return UserListFetchResult::Fail(
            ErrorCode::PANEL_API_FAILED,
            error_message);
    }

    try {
        auto jv = json::parse(resp.body);
        auto& j = jv.as_object();

        std::vector<::acpp::api::UserInfo> users;

        auto* users_p = j.if_contains("users");
        if (users_p && users_p->is_array()) {
            const auto& users_array = users_p->as_array();
            users.reserve(users_array.size());  // 预分配，避免多次重新分配

            for (const auto& uv : users_array) {
                auto& u = uv.as_object();
                ::acpp::api::UserInfo user;

                auto* id_p = u.if_contains("id");
                user.UID = (id_p && id_p->is_int64()) ? id_p->as_int64() : 0;
                auto* uuid_p = u.if_contains("uuid");
                user.UUID = (uuid_p && uuid_p->is_string()) ? std::string(uuid_p->as_string()) : "";
                user.Passwd = user.UUID;
                auto* flow_p = u.if_contains("flow");
                user.Flow = (flow_p && flow_p->is_string()) ? std::string(flow_p->as_string()) : "";

                // speed_limit 和 device_limit 可能是 null
                auto* sl_p = u.if_contains("speed_limit");
                const int64_t speed_limit_mbps =
                    (sl_p && sl_p->is_int64()) ? sl_p->as_int64() : 0;
                user.SpeedLimit = speed_limit_mbps > 0
                    ? static_cast<uint64_t>(speed_limit_mbps) * 1024ULL * 1024ULL / 8ULL
                    : 0;

                auto* dl_p = u.if_contains("device_limit");
                user.DeviceLimit = (dl_p && dl_p->is_int64()) ? static_cast<int>(dl_p->as_int64()) : 0;

                auto* email_p = u.if_contains("email");
                user.Email = (email_p && email_p->is_string()) ? std::string(email_p->as_string()) : "";
                // 如果没有 email，使用 user_id 作为标识
                if (user.Email.empty() && user.UID > 0) {
                    user.Email = std::to_string(user.UID);
                }
                user.Enabled = true;

                if (!user.UUID.empty()) {
                    users.push_back(std::move(user));  // 使用 move 避免拷贝
                }
            }
        }

        // 保存 ETag
        if (!resp.etag.empty()) {
            users_etag_ = resp.etag;
        }

        LOG_DEBUG("V2Board[{}]: fetched {} users for node {}",
                 config_.Name, users.size(), node_id);
        co_return UserListFetchResult::Success(std::move(users));

    } catch (const std::exception& e) {
        LOG_ERROR("V2Board[{}]: parse users error: {}", config_.Name, e.what());
        co_return UserListFetchResult::Fail(ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
}

net::awaitable<bool>
APIClient::Impl::ReportUserTraffic(const std::vector<::acpp::api::UserTraffic>& data) {
    const int node_id = config_.NodeID;

    if (data.empty()) {
        co_return true;
    }

    // V2Board UniProxy push 格式: {user_id: [upload, download], ...}
    json::object body;
    for (const auto& t : data) {
        body[std::to_string(t.UID)] = json::array{
            static_cast<int64_t>(t.Upload), static_cast<int64_t>(t.Download)};
    }

    // 路径包含 node_id 和 node_type
    std::string path = std::format("/api/v1/server/UniProxy/push?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    auto resp = co_await HttpPost(path, body);

    if (resp.status != 200) {
        LOG_WARN("V2Board[{}]: ReportUserTraffic failed for node {}: {}",
                 config_.Name, node_id, FormatHttpFailure(resp));
        co_return false;
    }

    LOG_DEBUG("V2Board[{}]: reported traffic for {} users", config_.Name, data.size());
    co_return true;
}

net::awaitable<bool>
APIClient::Impl::ReportNodeStatus(const ::acpp::api::NodeStatus& node_status) {
    (void)node_status;
    co_return true;
}

net::awaitable<bool>
APIClient::Impl::ReportNodeOnlineUsers(const std::vector<::acpp::api::OnlineUser>& online_users) {
    const int node_id = config_.NodeID;

    if (online_users.empty()) {
        co_return true;
    }

    // 格式: {uid: [ip_nodeid, ...], ...}
    // XrayR V2Board 使用 OnlineUser{UID, IP}，V2Board alive 接口值为 IP_nodeID。
    std::map<int64_t, json::array> grouped;
    for (const auto& user : online_users) {
        if (user.UID <= 0) {
            continue;
        }
        const std::string ip = user.IP.empty() ? "0.0.0.0" : user.IP;
        grouped[user.UID].push_back(ip + "_" + std::to_string(node_id));
    }
    if (grouped.empty()) {
        co_return true;
    }

    json::object body;
    for (auto& [uid, values] : grouped) {
        body[std::to_string(uid)] = std::move(values);
    }

    // 路径包含 node_id 和 node_type
    std::string path = std::format("/api/v1/server/UniProxy/alive?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    auto resp = co_await HttpPost(path, body);

    if (resp.status != 200) {
        LOG_WARN("V2Board[{}]: ReportNodeOnlineUsers failed for node {}: {}",
                 config_.Name, node_id, FormatHttpFailure(resp));
        co_return false;
    }

    LOG_DEBUG("V2Board[{}]: reported {} online users", config_.Name, online_users.size());
    co_return true;
}

net::awaitable<RuleListFetchResult>
APIClient::Impl::GetNodeRule() {
    co_return RuleListFetchResult::Success(cached_route_rules_);
}

net::awaitable<bool>
APIClient::Impl::ReportIllegal(const std::vector<::acpp::api::DetectResult>& detect_results) {
    (void)detect_results;
    co_return true;
}

void APIClient::Impl::Debug() {
    debug_enabled_ = true;
}

APIClient::APIClient(net::io_context& io_context,
                     const ::acpp::api::Config& config,
                     ::acpp::app::dns::DNS& dns_service)
    : impl_(std::make_unique<Impl>(io_context, config, dns_service)) {}

APIClient::~APIClient() = default;

::acpp::api::ClientInfo APIClient::Describe() const {
    return impl_->Describe();
}

net::awaitable<NodeInfoFetchResult>
APIClient::GetNodeInfo() {
    co_return co_await impl_->GetNodeInfo();
}

net::awaitable<UserListFetchResult>
APIClient::GetUserList() {
    co_return co_await impl_->GetUserList();
}

net::awaitable<bool>
APIClient::ReportNodeStatus(const ::acpp::api::NodeStatus& node_status) {
    co_return co_await impl_->ReportNodeStatus(node_status);
}

net::awaitable<bool>
APIClient::ReportNodeOnlineUsers(const std::vector<::acpp::api::OnlineUser>& online_users) {
    co_return co_await impl_->ReportNodeOnlineUsers(online_users);
}

net::awaitable<bool>
APIClient::ReportUserTraffic(const std::vector<::acpp::api::UserTraffic>& data) {
    co_return co_await impl_->ReportUserTraffic(data);
}

net::awaitable<RuleListFetchResult>
APIClient::GetNodeRule() {
    co_return co_await impl_->GetNodeRule();
}

net::awaitable<bool>
APIClient::ReportIllegal(const std::vector<::acpp::api::DetectResult>& detect_results) {
    co_return co_await impl_->ReportIllegal(detect_results);
}

void APIClient::Debug() {
    impl_->Debug();
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
