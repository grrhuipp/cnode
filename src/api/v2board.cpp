#include "api/api.hpp"
#include "common/ip_address.hpp"
#include "common/constants.hpp"
#include "infra/config.hpp"
#include "transport/http_headers.hpp"
#include "app/dns.hpp"
#include "infra/json.hpp"
#include "infra/log.hpp"
#include "api/panel_wire.hpp"
#include "api/request_task.hpp"
#include "transport/http1_handshake.hpp"

#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>
#include <asio/redirect_error.hpp>
#include <asio/cancel_after.hpp>
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <format>
#include <stdexcept>
#include <limits>
#include <optional>
#include <regex>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>
#include <openssl/x509_vfy.h>

namespace api {

namespace ssl = net::ssl;

namespace {

constexpr size_t kHttpErrorDetailLimit = 256;

enum class HttpMethod : uint8_t {
    Get,
    Post,
};


std::string CompactLogText(std::string_view text, std::string_view api_key) {
    std::string result;
    result.reserve(text.size() < kHttpErrorDetailLimit ? text.size()
                                                       : kHttpErrorDetailLimit);

    bool truncated = false;
    bool last_space = false;
    for (size_t offset = 0; offset < text.size();) {
        if (result.size() >= kHttpErrorDetailLimit) {
            truncated = true;
            break;
        }
        // Mask before truncating so a key crossing the preview boundary cannot leak.
        if (!api_key.empty() && text.substr(offset).starts_with(api_key)) {
            constexpr std::string_view redacted = "[redacted]";
            if (redacted.size() > kHttpErrorDetailLimit - result.size()) {
                truncated = true;
                break;
            }
            result += redacted;
            offset += api_key.size();
            last_space = false;
            continue;
        }
        char ch = text[offset++];
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
    while (!result.empty() && result.back() == ' ') result.pop_back();
    if (truncated) result += "...";
    return result;
}

std::string FormatHttpFailure(const PanelHttpResponse& resp) {
    // Server response bodies can echo request queries, API keys or credentials.
    // Only locally generated transport/parser diagnostics are safe to include.
    const std::string detail = resp.status <= 0 ? CompactLogText(resp.body, {}) : std::string{};

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

std::string FormatReportFailure(const PanelHttpResponse& response, std::string_view api_key) {
    auto summary = FormatHttpFailure(response);
    if (response.status > 0) {
        const auto detail = CompactLogText(response.body, api_key);
        if (!detail.empty()) {
            summary.reserve(summary.size() + 2 + detail.size());
            summary.append(": ").append(detail);
        }
    }
    return summary;
}

std::string_view MethodName(HttpMethod method) noexcept {
    switch (method) {
        case HttpMethod::Get: return "GET";
        case HttpMethod::Post: return "POST";
    }
    return "GET";
}

// Adapts the existing Asio owner to byte I/O; HTTP parsing stays in transport.
template <typename Stream>
class PanelStream final : public transport::AsyncStream {
public:
    template <typename... Args>
    explicit PanelStream(Args&&... args) : stream(std::forward<Args>(args)...) {}
    ~PanelStream() override { Close(); }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        IoErrorCode ec;
        const auto n = co_await stream.async_read_some(
            buffer, net::redirect_error(net::use_awaitable, ec));
        if (ec && ec != net::error::eof) throw IoSystemError(ec);
        co_return n;
    }
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        common::BufferGuard buffer{common::Buffer::New()};
        if (!buffer) throw std::bad_alloc();
        const auto n = co_await AsyncRead(
            net::buffer(buffer->Tail().data(), buffer->Available()));
        if (n == 0) co_return common::MultiBuffer{};
        buffer->Produce(static_cast<uint32_t>(n));
        co_return common::MultiBuffer{std::move(buffer)};
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        return stream.async_write_some(buffer, net::use_awaitable);
    }
    void ShutdownRead() override {
        IoErrorCode ec;
        Socket().shutdown(tcp::socket::shutdown_receive, ec);
    }
    void ShutdownWrite() override {
        IoErrorCode ec;
        Socket().shutdown(tcp::socket::shutdown_send, ec);
    }
    net::awaitable<void> AsyncShutdownWrite() override {
        if constexpr (!std::is_same_v<Stream, tcp::socket>) {
            IoErrorCode ec;
            co_await stream.async_shutdown(net::cancel_after(std::chrono::seconds(1),
                net::redirect_error(net::use_awaitable, ec)));
        } else {
            ShutdownWrite();
        }
    }
    void Close() override {
        NotifyClosed();
        IoErrorCode ec;
        stream.lowest_layer().close(ec);
    }
    void Cancel() noexcept override {
        NotifyCancellation();
        IoErrorCode ec;
        stream.lowest_layer().cancel(ec);
    }
    int NativeHandle() const override {
        return const_cast<Stream&>(stream).lowest_layer().native_handle();
    }
    bool IsOpen() const override { return stream.lowest_layer().is_open(); }

    Stream stream;
private:
    tcp::socket& Socket() noexcept {
        if constexpr (std::is_same_v<Stream, tcp::socket>) return stream;
        else return stream.next_layer();
    }
};

net::awaitable<PanelHttpResponse> WriteRequestAndReadResponse(
    std::unique_ptr<transport::AsyncStream> stream, std::string request) {
    constexpr size_t kMaxBodySize = 64 * 1024 * 1024;
    constexpr size_t kMaxLineSize = 64 * 1024;
    constexpr size_t kMaxHeaderSize = 256 * 1024;
    if (!request.empty()) {
        const net::const_buffer request_buf(request.data(), request.size());
        try {
            co_await stream->WriteBuffers(
                std::span<const net::const_buffer>{&request_buf, 1});
        } catch (...) {
            std::string{}.swap(request);
            co_return PanelHttpResponse{.status = -1, .body = "HTTP request write failed"};
        }
    }
    std::string{}.swap(request);
    auto response = co_await transport::ReadHttp1ResponseHead(*stream,
        {.max_head_bytes = kMaxHeaderSize, .max_line_bytes = kMaxLineSize});
    if (!response)
        co_return PanelHttpResponse{.status = -1, .body = "invalid HTTP response headers"};

    PanelHttpResponse result{.status = response->status};
    result.not_modified = result.status == 304;
    const auto head = response->head.Text();
    if (transport::CountHeadersCI(head, "ETag") > 1)
        co_return PanelHttpResponse{.status = -1, .body = "duplicate ETag"};
    auto etag = transport::ExtractHeaderValueCI(head, "ETag");
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"')
        etag = etag.substr(1, etag.size() - 2);
    if (!std::ranges::all_of(etag, [](unsigned char ch) {
            return ch > 0x20 && ch != 0x7f;
        }))
        co_return PanelHttpResponse{.status = -1, .body = "invalid ETag"};
    result.etag.assign(etag);
    if (const auto* length = std::get_if<transport::Http1BodyContentLength>(&response->framing);
        length && length->bytes > kMaxBodySize)
        co_return PanelHttpResponse{.status = -1, .body = "HTTP body too large"};

    auto body = transport::MakeHttp1BodyStream(std::move(stream), response->framing, false,
        response->head.TakeReadAheadMultiBuffer(),
        {.max_body_bytes = kMaxBodySize,
         .max_line_bytes = kMaxLineSize,
         .max_trailer_lines = std::numeric_limits<size_t>::max(),
         .max_trailer_bytes = kMaxHeaderSize - response->header_bytes,
         .count_trailer_terminator = true,
         .reject_trailing_read_ahead = result.status != 204 && result.status != 304});
    for (;;) {
        auto chunk = co_await body->ReadMultiBuffer();
        const auto bytes = chunk.FrontSpan();
        if (bytes.empty()) break;
        if (bytes.size() > kMaxBodySize - result.body.size())
            co_return PanelHttpResponse{.status = -1, .body = "HTTP body too large"};
        // Grow for bytes actually received, never for a declared length.
        result.body.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
    // A completed response survives cancellation of best-effort TLS cleanup.
    try { co_await body->AsyncShutdownWrite(); } catch (const std::exception&) {}
    co_return result;
}

// 同进程的 HTTPS 面板客户端共享一份只读客户端 SSL_CTX（一份系统 CA store）。
// SNI、主机名/IP 校验都设置在逐连接的 SSL 对象上；客户端会话不缓存在 ctx 中。
// 仅在控制线程构造 APIClient 时调用；全部客户端释放后由下一次构造重建。
std::shared_ptr<ssl::context> AcquireHttpsClientContext() {
    static std::weak_ptr<ssl::context> shared;
    if (auto context = shared.lock()) return context;
    // Negotiate TLS 1.3 when the panel offers it; TLS 1.2 stays the floor
    // (RFC 8996 deprecates TLS 1.0/1.1).
    auto context = std::make_shared<ssl::context>(ssl::context::tls_client);
    if (SSL_CTX_set_min_proto_version(context->native_handle(), TLS1_2_VERSION) != 1) {
        throw std::runtime_error("V2Board: failed to set the HTTPS minimum TLS version");
    }
    context->set_default_verify_paths();
    context->set_verify_mode(ssl::verify_peer);
    shared = context;
    return context;
}

}  // namespace

// ============================================================================
// APIClient 实现
// ============================================================================

class APIClient final : public API {
public:
    APIClient(net::io_context& io_context,
              Config config,
              app::DNS& dns_service);
    ~APIClient() override = default;

    net::awaitable<NodeInfoFetchResult>
    GetNodeInfo(std::string committed_etag) override;

    net::awaitable<UserListFetchResult>
    GetUserList(std::string committed_etag) override;

    net::awaitable<bool>
    ReportNodeOnlineUsers(const std::vector<OnlineUser>& online_users) override;

    net::awaitable<bool>
    ReportUserTraffic(const std::vector<UserTraffic>& data) override;

private:
    [[nodiscard]] const std::string& ApiNodeType() const noexcept {
        return api_node_type_;
    }

    // Parameters are owned by the coroutine frame: ExecutePanelHttpRequest starts the
    // exchange lazily and may cancel it after the caller's arguments are gone.
    net::awaitable<PanelHttpResponse>
    HttpRequest(HttpMethod method,
                std::string path,
                std::string body_text,
                std::string if_none_match);

    net::awaitable<PanelHttpResponse>
    HttpExchange(HttpMethod method,
                 std::string path,
                 std::string body_text,
                 std::string if_none_match);

    // 依次尝试候选地址。回退只发生在连接与 TLS 握手阶段：一旦开始发送，
    // 失败也无法证明面板未处理请求（流量上报是累加的），因此不换地址重发。
    template <typename Stream>
    net::awaitable<PanelHttpResponse>
    ConnectAndExchange(std::vector<tcp::endpoint> endpoints,
                       std::string request);

    template <typename FetchResult>
    net::awaitable<tl::expected<PanelHttpResponse, FetchResult>>
    FetchConditionalResource(std::string_view endpoint,
                             std::string committed_etag,
                             std::string_view missing_etag_error,
                             std::string_view pull_failure_label,
                             bool log_not_modified = false);

    net::io_context& io_context_;
    Config config_;
    const infra::PanelLogContext log_context_;
    infra::PanelApiUrlParts url_parts_;
    std::optional<net::ip::address> literal_address_;
    std::string api_node_type_;
    std::string host_header_;
    app::DNS& dns_service_;

    std::shared_ptr<ssl::context> https_context_;
};

APIClient::APIClient(net::io_context& io_context,
                     Config config,
                     app::DNS& dns_service)
    : io_context_(io_context)
    , config_(std::move(config))
    , log_context_{config_.Name, config_.APIHost, config_.NodeID, config_.NodeType}
    , dns_service_(dns_service) {
    if (config_.RequestTimeout <= std::chrono::seconds::zero() ||
        config_.RequestTimeout > std::chrono::seconds(common::kMaxPanelRequestTimeout)) {
        throw std::invalid_argument("API RequestTimeout is outside the supported range");
    }
    if (!infra::IsValidPanelName(config_.Name)) {
        throw std::invalid_argument("Invalid panel name");
    }
    if (!infra::IsValidPanelKey(config_.Key)) {
        throw std::invalid_argument("Invalid panel API key");
    }

    auto parts = infra::ParsePanelApiUrl(config_.APIHost);
    if (!parts) {
        throw std::invalid_argument("Invalid panel API host");
    }
    url_parts_ = std::move(*parts);
    literal_address_ = common::ParseLiteral(url_parts_.host);
    api_node_type_ = common::NormalizeV2BoardApiNodeType(config_.NodeType);
    common::FormatHttpHostHeaderInto(
        host_header_, url_parts_.host, url_parts_.port, url_parts_.use_ssl);

    if (url_parts_.use_ssl) https_context_ = AcquireHttpsClientContext();
}

net::awaitable<PanelHttpResponse>
APIClient::HttpRequest(HttpMethod method,
                       std::string path,
                       std::string body_text,
                       std::string if_none_match) {
    return ExecutePanelHttpRequest(
        HttpExchange(method, std::move(path), std::move(body_text),
                     std::move(if_none_match)),
        config_.RequestTimeout);
}

net::awaitable<PanelHttpResponse>
APIClient::HttpExchange(HttpMethod method,
                        std::string path,
                        std::string body_text,
                        std::string if_none_match) {
    PanelHttpResponse result;

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

    const bool has_query = url_parts_.path_prefix.find('?') != std::string::npos ||
                           path.find('?') != std::string::npos;
    std::string request;
    request.reserve(512 + url_parts_.path_prefix.size() + path.size() + body_text.size());
    request += MethodName(method);
    request += ' ';
    if (url_parts_.path_prefix.empty() && path.empty()) {
        request += '/';
    } else {
        request += url_parts_.path_prefix;
        request += path;
    }
    request += has_query ? "&token=" : "?token=";
    request += config_.Key;
    request += " HTTP/1.1\r\nHost: ";
    request += host_header_;
    request += "\r\nUser-Agent: cnode/1.0\r\nAuthorization: Bearer ";
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
        char len_buf[24];
        auto [ptr, ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body_text.size());
        (void)ec;
        request.append(len_buf, ptr);
        request += "\r\n";
    }
    request += "\r\n";
    request += body_text;
    std::string{}.swap(path);
    std::string{}.swap(body_text);
    std::string{}.swap(if_none_match);

    if (url_parts_.use_ssl) {
        co_return co_await ConnectAndExchange<ssl::stream<tcp::socket>>(
            std::move(endpoints), std::move(request));
    }
    co_return co_await ConnectAndExchange<tcp::socket>(
        std::move(endpoints), std::move(request));
}

template <typename Stream>
net::awaitable<PanelHttpResponse>
APIClient::ConnectAndExchange(std::vector<tcp::endpoint> endpoints,
                              std::string request) {
    constexpr bool kTls = !std::is_same_v<Stream, tcp::socket>;
    constexpr std::string_view kScheme = kTls ? "HTTPS" : "HTTP";
    const auto cancellation = co_await net::this_coro::cancellation_state;
    std::string last_error;
    for (const auto& endpoint : endpoints) {
        auto stream = [this] {
            if constexpr (kTls)
                return std::make_unique<PanelStream<Stream>>(io_context_, *https_context_);
            else
                return std::make_unique<PanelStream<Stream>>(io_context_);
        }();
        try {
            if constexpr (kTls) {
                if (literal_address_) {
                    auto* verify_param = SSL_get0_param(stream->stream.native_handle());
                    if (!verify_param ||
                        X509_VERIFY_PARAM_set1_ip_asc(verify_param, url_parts_.host.c_str()) != 1) {
                        co_return PanelHttpResponse{.status = -1, .body = "SSL IP verify param error",
                                               .etag = {}, .not_modified = false};
                    }
                } else {
                    stream->stream.set_verify_callback(ssl::host_name_verification(url_parts_.host));
                    if (!SSL_set_tlsext_host_name(stream->stream.native_handle(), url_parts_.host.c_str())) {
                        co_return PanelHttpResponse{.status = -1, .body = "SSL SNI error",
                                               .etag = {}, .not_modified = false};
                    }
                }
            }
            co_await stream->stream.lowest_layer().async_connect(endpoint, net::use_awaitable);
            if constexpr (kTls) {
                co_await stream->stream.async_handshake(ssl::stream_base::client, net::use_awaitable);
            }
        } catch (const std::exception& e) {
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw;
            }
            last_error = e.what();
            LOG_PANEL_DEBUG(log_context_, "{} endpoint connection failed: endpoint={} reason={}",
                      kScheme,
                      common::FormatEndpointForLog(common::AddressText(endpoint.address()).View(), endpoint.port()),
                      last_error);
            continue;
        }

        std::vector<tcp::endpoint>{}.swap(endpoints);
        std::string{}.swap(last_error);
        co_return co_await WriteRequestAndReadResponse(std::move(stream), std::move(request));
    }
    co_return PanelHttpResponse{
        .status = -1,
        .body = last_error.empty() ? std::format("{} connect failed", kScheme) : last_error,
        .etag = {},
        .not_modified = false,
    };
}

template <typename FetchResult>
net::awaitable<tl::expected<PanelHttpResponse, FetchResult>>
APIClient::FetchConditionalResource(std::string_view endpoint,
                                    std::string committed_etag,
                                    std::string_view missing_etag_error,
                                    std::string_view pull_failure_label,
                                    bool log_not_modified) {
    std::string path = std::format("/api/v1/server/UniProxy/{}?node_id={}&node_type={}",
                                   endpoint, config_.NodeID, ApiNodeType());
    const bool has_etag = !committed_etag.empty();
    auto resp = co_await HttpRequest(HttpMethod::Get, std::move(path), {}, std::move(committed_etag));
    if (resp.not_modified) {
        if (!has_etag) {
            co_return tl::unexpected(FetchResult::Fail(
                common::ErrorCode::PANEL_INVALID_RESPONSE,
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
            common::ErrorCode::PANEL_API_FAILED,
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
    infra::value jv;
    try {
        jv = infra::parse(resp.body);
        std::string{}.swap(resp.body);
    } catch (const std::exception& e) {
        LOG_PANEL_ERROR(log_context_, "Node configuration parsing failed: {}", e.what());
        co_return NodeInfoFetchResult::Fail(common::ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
    if (!jv.is_object()) {
        LOG_PANEL_ERROR(log_context_, "Invalid node configuration: root JSON value must be an object");
        co_return NodeInfoFetchResult::Fail(
            common::ErrorCode::PANEL_INVALID_RESPONSE,
            "root JSON value must be an object");
    }
    const auto& j = jv.as_object();

    auto parsed_config = ParseNodeInfo(j, config_.NodeType);
    if (!parsed_config) {
        LOG_PANEL_ERROR(log_context_, "Invalid node configuration: {}", parsed_config.error());
        co_return NodeInfoFetchResult::Fail(
            common::ErrorCode::PANEL_INVALID_RESPONSE,
            std::move(parsed_config.error()));
    }
    auto rules = ExtractBlockDetectRules(j);
    if (!rules) {
        LOG_PANEL_ERROR(log_context_, "Node configuration parsing failed: {}", rules.error());
        co_return NodeInfoFetchResult::Fail(
            common::ErrorCode::PANEL_INVALID_RESPONSE,
            std::move(rules.error()));
    }
    auto config = std::move(*parsed_config);

    LOG_PANEL_DEBUG(log_context_, "Node configuration received: protocol={} port={} network={}",
                    config.NodeType, config.Port, config.TransportProtocol);

    co_return NodeInfoFetchResult::Success(
        std::move(config), std::move(*rules), std::move(resp.etag));
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
        auto jv = infra::parse(resp.body);
        std::string{}.swap(resp.body);
        if (!jv.is_object()) {
            LOG_PANEL_ERROR(log_context_, "User list parsing failed: root JSON value must be an object");
            co_return UserListFetchResult::Fail(
                common::ErrorCode::PANEL_INVALID_RESPONSE,
                "root JSON value must be an object");
        }

        auto users = ParseUserList(std::move(jv.as_object()));
        jv = infra::value{};
        if (!users) {
            LOG_PANEL_ERROR(log_context_, "User list parsing failed: {}", users.error());
            co_return UserListFetchResult::Fail(
                common::ErrorCode::PANEL_INVALID_RESPONSE,
                std::move(users.error()));
        }

        LOG_PANEL_DEBUG(log_context_, "User list received: users={}", users->size());
        co_return UserListFetchResult::Success(std::move(*users), std::move(resp.etag));

    } catch (const std::exception& e) {
        LOG_PANEL_ERROR(log_context_, "User list parsing failed: {}", e.what());
        co_return UserListFetchResult::Fail(common::ErrorCode::PANEL_INVALID_RESPONSE, e.what());
    }
}

net::awaitable<bool>
APIClient::ReportUserTraffic(const std::vector<UserTraffic>& data) {
    const int node_id = config_.NodeID;

    // V2Board UniProxy push 格式: {user_id: [upload, download], ...}
    struct AggregatedTraffic {
        int64_t uid = 0;
        int64_t up = 0;
        int64_t down = 0;
    };
    std::vector<AggregatedTraffic> items;
    items.reserve(data.size());
    for (const auto& t : data) {
        if (t.UID <= 0 || (t.Upload <= 0 && t.Download <= 0)) {
            continue;
        }
        items.push_back(AggregatedTraffic{
            .uid = t.UID,
            .up = std::max<int64_t>(0, t.Upload),
            .down = std::max<int64_t>(0, t.Download),
        });
    }
    std::sort(items.begin(), items.end(),
              [](const AggregatedTraffic& a, const AggregatedTraffic& b) {
                  return a.uid < b.uid;
              });
    size_t unique_count = 0;
    for (const auto& item : items) {
        if (unique_count > 0 && items[unique_count - 1].uid == item.uid) {
            auto& prev = items[unique_count - 1];
            prev.up = (item.up > INT64_MAX - prev.up) ? INT64_MAX : (prev.up + item.up);
            prev.down = (item.down > INT64_MAX - prev.down) ? INT64_MAX : (prev.down + item.down);
        } else {
            items[unique_count++] = item;
        }
    }
    items.resize(unique_count);
    const size_t reported_users = items.size();

    std::string body_json;
    body_json.reserve(2 + items.size() * 32);
    body_json.push_back('{');
    char num_buf[24];
    auto append_int = [&](int64_t val) {
        auto [ptr, ec] = std::to_chars(num_buf, num_buf + sizeof(num_buf), val);
        (void)ec;
        body_json.append(num_buf, ptr);
    };
    for (size_t i = 0; i < items.size(); ++i) {
        if (i != 0) body_json.push_back(',');
        body_json.push_back('"');
        append_int(items[i].uid);
        body_json.append("\":[");
        append_int(items[i].up);
        body_json.push_back(',');
        append_int(items[i].down);
        body_json.push_back(']');
    }
    body_json.push_back('}');
    std::vector<AggregatedTraffic>{}.swap(items);

    // 路径包含 node_id 和 node_type
    std::string path = std::format("/api/v1/server/UniProxy/push?node_id={}&node_type={}",
                                   node_id, ApiNodeType());

    auto resp = co_await HttpRequest(
        HttpMethod::Post, std::move(path), std::move(body_json), {});
    if (resp.status != 200) {
        LOG_PANEL_WARN(log_context_, "Traffic API acceptance unknown: {}", FormatReportFailure(resp, config_.Key));
        co_return false;
    }

    LOG_PANEL_DEBUG(log_context_, "Traffic API accepted: users={} (not a billing commit acknowledgement)", reported_users);
    co_return true;
}

net::awaitable<bool>
APIClient::ReportNodeOnlineUsers(const std::vector<OnlineUser>& online_users) {
    const int node_id = config_.NodeID;
    auto report = BuildOnlineReportPayload(online_users, node_id);

    if (!report.alive_json.empty()) {
        std::string alive_path = std::format(
            "/api/v1/server/UniProxy/alive?node_id={}&node_type={}",
            node_id, ApiNodeType());
        auto alive_resp = co_await HttpRequest(
            HttpMethod::Post, std::move(alive_path), std::move(report.alive_json), {});
        if (alive_resp.status != 200) {
            LOG_PANEL_WARN(log_context_, "Online device report failed: {}", FormatReportFailure(alive_resp, config_.Key));
            co_return false;
        }
    }

    LOG_PANEL_DEBUG(log_context_, "Online devices reported: users={} devices={}", report.user_count, report.device_count);
    co_return true;
}

std::unique_ptr<API> CreatePanelClient(
    net::io_context& io_context,
    Config config,
    app::DNS& dns_service) {
    return std::make_unique<APIClient>(io_context, std::move(config), dns_service);
}

namespace {

tl::expected<uint16_t, std::string> ParsePanelPort(
    const infra::value& raw,
    std::string_view invalid_type_error,
    std::string_view out_of_range_error) {
    const auto result = PanelUnsignedInteger(raw);
    if (!result) {
        return tl::unexpected(std::string(invalid_type_error));
    }
    if (*result == 0 || *result > std::numeric_limits<uint16_t>::max()) {
        return tl::unexpected(std::string(out_of_range_error));
    }
    return static_cast<uint16_t>(*result);
}

tl::expected<uint16_t, std::string> ParseServerPort(const infra::object& source) {
    const auto* raw = source.if_contains("server_port");
    if (!raw || raw->is_null()) {
        return tl::unexpected("server_port is required");
    }
    return ParsePanelPort(
        *raw,
        "server_port must be an integer or decimal integer string",
        "server_port must be between 1 and 65535");
}

// 0 keeps the local default cadence; the bound keeps the value representable
// in NodeInfo and in steady_clock deadline arithmetic.
tl::expected<int, std::string> ParseReportInterval(
    const infra::object& base, std::string_view field, int current) {
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

tl::expected<const infra::value*, std::string> ResolveAlias(
    const infra::object& obj,
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
    const infra::object& source,
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
tl::expected<const infra::value*, std::string> ResolveRealityAlias(
    const infra::object& obj,
    std::string_view primary,
    std::string_view secondary) {
    return ResolveAlias(obj, primary, secondary, "REALITY tls_settings");
}

tl::expected<std::optional<std::string>, std::string> ReadRealityStringAlias(
    const infra::object& obj,
    std::string_view primary,
    std::string_view secondary) {
    auto resolved = ResolveRealityAlias(obj, primary, secondary);
    if (!resolved) {
        return tl::unexpected(std::move(resolved.error()));
    }
    if (!*resolved) {
        return std::optional<std::string>{};
    }
    if (!(*resolved)->is_string()) {
        return tl::unexpected(std::format("REALITY {} must be a string", primary));
    }
    return std::optional<std::string>{std::string((*resolved)->as_string())};
}

tl::expected<bool, std::string> AssignOptionalNodeString(
    const infra::object& source,
    std::string_view key,
    std::string& out,
    std::string_view label = {},
    bool lowercase = false) {
    const auto* raw = source.if_contains(key);
    if (!raw || raw->is_null()) {
        return false;
    }
    if (!raw->is_string()) {
        return tl::unexpected(std::format(
            "{} must be a string", label.empty() ? key : label));
    }
    out.assign(raw->as_string());
    if (lowercase) {
        common::LowerAsciiInPlace(out);
    }
    return true;
}

tl::expected<void, std::string> ValidateUnsupportedPanelMode(
    const infra::object& source,
    std::string_view field,
    std::string_view unsupported_error,
    bool allow_none = true) {
    const auto* raw = source.if_contains(field);
    if (!raw || raw->is_null()) {
        return {};
    }
    if (!raw->is_string()) {
        return tl::unexpected(std::format("{} must be a string or null", field));
    }
    const std::string_view text = raw->as_string();
    if (!text.empty() &&
        (!allow_none || !common::EqualsAsciiCI(text, common::kNone))) {
        return tl::unexpected(std::string(unsupported_error));
    }
    return {};
}

tl::expected<void, std::string> ValidateOptionalPanelObject(
    const infra::object& source,
    std::string_view field) {
    const auto* settings = source.if_contains(field);
    if (settings && !settings->is_null() && !settings->is_object() &&
        !IsPanelEmptyObject(*settings)) {
        return tl::unexpected(std::format("{} must be an object or null", field));
    }
    return {};
}

tl::expected<std::vector<std::string>, std::string> ReadPanelStringList(
    const infra::value& value, std::string_view field, bool allow_scalar) {
    std::vector<std::string> out;
    if (allow_scalar && value.is_string()) {
        out.push_back(common::LowerAscii(std::string(value.as_string())));
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
        out.push_back(common::LowerAscii(std::string(item.as_string())));
    }
    return out;
}

// Maps v2board tls_settings onto the shared REALITY server input; semantic
// validation belongs to infra::ApplyRealityServerInput.
tl::expected<void, std::string> MapRealitySettings(
    const infra::object& rs,
    std::string_view tls_server_name,
    transport::RealityConfig& out) {
    infra::RealityServerInput input;

    auto private_key = ReadRealityStringAlias(rs, "private_key", "privateKey");
    if (!private_key) {
        return tl::unexpected(std::move(private_key.error()));
    }
    if (*private_key) {
        input.private_key = std::move(**private_key);
    }

    const auto server_names_res = ResolveRealityAlias(rs, "server_names", "serverNames");
    if (!server_names_res) {
        return tl::unexpected(std::move(server_names_res.error()));
    }
    const infra::value* const server_names = *server_names_res;
    auto server_name = ReadRealityStringAlias(rs, "server_name", "serverName");
    if (!server_name) {
        return tl::unexpected(std::move(server_name.error()));
    }
    if (server_names) {
        auto names = ReadPanelStringList(*server_names, "server_names", false);
        if (!names) {
            return tl::unexpected(std::move(names.error()));
        }
        input.server_names = std::move(*names);
    }
    if (*server_name) {
        std::vector<std::string> single{common::LowerAscii(std::move(**server_name))};
        if (server_names && input.server_names != single) {
            return tl::unexpected(
                "REALITY server_names and server_name must match");
        }
        input.server_names = std::move(single);
    } else if (!server_names && !tls_server_name.empty()) {
        input.server_names.emplace_back(tls_server_name);
    }

    const auto short_ids_res = ResolveRealityAlias(rs, "short_ids", "shortIds");
    if (!short_ids_res) {
        return tl::unexpected(std::move(short_ids_res.error()));
    }
    const infra::value* const short_ids = *short_ids_res;
    const auto short_id_res = ResolveRealityAlias(rs, "short_id", "shortId");
    if (!short_id_res) {
        return tl::unexpected(std::move(short_id_res.error()));
    }
    const infra::value* const short_id = *short_id_res;
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

    const auto server_port_res = ResolveRealityAlias(rs, "server_port", "serverPort");
    if (!server_port_res) {
        return tl::unexpected(std::move(server_port_res.error()));
    }
    const infra::value* const server_port = *server_port_res;
    std::optional<uint16_t> sp_port;
    if (server_port) {
        auto port = ParsePanelPort(
            *server_port,
            "REALITY tls_settings.server_port is invalid",
            "REALITY tls_settings.server_port is invalid");
        if (!port) {
            return tl::unexpected(std::move(port.error()));
        }
        sp_port = *port;
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

    auto mldsa65_seed = ReadRealityStringAlias(rs, "mldsa65_seed", "mldsa65Seed");
    if (!mldsa65_seed) {
        return tl::unexpected(std::move(mldsa65_seed.error()));
    }
    if (*mldsa65_seed) {
        input.mldsa65_seed = std::move(**mldsa65_seed);
    }

    auto min_ver = ReadRealityStringAlias(rs, "min_client_ver", "minClientVer");
    if (!min_ver) {
        return tl::unexpected(std::move(min_ver.error()));
    }
    if (*min_ver) {
        input.min_client_ver = std::move(**min_ver);
    }
    auto max_ver = ReadRealityStringAlias(rs, "max_client_ver", "maxClientVer");
    if (!max_ver) {
        return tl::unexpected(std::move(max_ver.error()));
    }
    if (*max_ver) {
        input.max_client_ver = std::move(**max_ver);
    }

    const auto max_time_res = ResolveRealityAlias(rs, "max_time_diff", "maxTimeDiff");
    if (!max_time_res) {
        return tl::unexpected(std::move(max_time_res.error()));
    }
    if (const infra::value* const max_time = *max_time_res) {
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


constexpr uint64_t kBytesPerSecondPerMbps = 1024ULL * 1024ULL / 8ULL;
constexpr uint64_t kMaxSpeedLimitMbps =
    std::numeric_limits<uint64_t>::max() / kBytesPerSecondPerMbps;

tl::expected<uint64_t, std::string> ParseOptionalLimit(
    const infra::object& source,
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

template <typename Object>
tl::expected<std::string, std::string> ParseOptionalString(
    Object&& source,
    std::string_view field,
    size_t user_index) {
    auto* value = source.if_contains(field);
    if (!value || value->is_null()) return std::string{};
    if (!value->is_string()) {
        return tl::unexpected(std::format(
            "users[{}].{} must be a string or null", user_index, field));
    }
    if (common::ContainsControlCharacter(value->as_string())) {
        return tl::unexpected(std::format(
            "users[{}].{} contains control characters", user_index, field));
    }
    if constexpr (!std::is_const_v<std::remove_reference_t<Object>> &&
                  !std::is_lvalue_reference_v<Object>) {
        return std::move(value->as_string());
    } else {
        return std::string(value->as_string());
    }
}

bool IsValidDevice(const OnlineUser& device) noexcept {
    return device.UID > 0 && !device.IP.empty();
}

bool DeviceLess(const OnlineUser& lhs, const OnlineUser& rhs) noexcept {
    if (lhs.UID != rhs.UID) return lhs.UID < rhs.UID;
    return lhs.IP < rhs.IP;
}

bool IsCanonicalDeviceList(std::span<const OnlineUser> devices) noexcept {
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
    std::span<const OnlineUser> devices,
    int node_id) {
    OnlineReportPayload result;
    if (devices.empty()) {
        return result;
    }
    char node_buf[24];
    node_buf[0] = '_';
    const auto [node_end, node_ec] = std::to_chars(
        node_buf + 1, node_buf + sizeof(node_buf), node_id);
    (void)node_ec;
    const std::string_view suffix(
        node_buf, static_cast<size_t>(node_end - node_buf));

    result.device_count = devices.size();
    result.alive_json.reserve(2 + devices.size() * (24 + suffix.size()));
    result.alive_json.push_back('{');

    char uid_buf[24];
    for (size_t i = 0; i < devices.size();) {
        if (result.user_count != 0) {
            result.alive_json.push_back(',');
        }
        const int64_t uid = devices[i].UID;
        result.alive_json.push_back('"');
        const auto [uid_end, uid_ec] = std::to_chars(
            uid_buf, uid_buf + sizeof(uid_buf), uid);
        (void)uid_ec;
        result.alive_json.append(uid_buf, uid_end);
        result.alive_json.append("\":[");

        size_t j = i;
        while (j < devices.size() && devices[j].UID == uid) {
            if (j != i) {
                result.alive_json.push_back(',');
            }
            infra::append_json_string(result.alive_json, devices[j].IP);
            result.alive_json.pop_back();
            result.alive_json.append(suffix);
            result.alive_json.push_back('"');
            ++j;
        }
        result.alive_json.push_back(']');
        ++result.user_count;
        i = j;
    }
    result.alive_json.push_back('}');
    return result;
}

}  // namespace

tl::expected<NodeInfo, std::string> ParseNodeInfo(
    const infra::object& source,
    std::string_view node_type) {
    auto port = ParseServerPort(source);
    if (!port) {
        return tl::unexpected(std::move(port.error()));
    }

    NodeInfo config;
    config.NodeType = common::LowerAscii(node_type);
    config.Port = *port;

    if (auto ok = AssignOptionalNodeString(
            source, "network", config.TransportProtocol, {}, true); !ok) {
        return tl::unexpected(std::move(ok.error()));
    }

    if (const auto* network_settings = source.if_contains("networkSettings");
        network_settings && !network_settings->is_null() &&
        !IsPanelEmptyObject(*network_settings)) {
        if (!network_settings->is_object()) {
            return tl::unexpected("networkSettings must be an object");
        }
        const auto& settings = network_settings->as_object();
        if (auto ok = AssignOptionalNodeString(
                settings, "path", config.Path, "networkSettings path"); !ok) {
            return tl::unexpected(std::move(ok.error()));
        }
        if (auto ok = AssignOptionalNodeString(
                settings, "serviceName", config.ServiceName, "networkSettings serviceName"); !ok) {
            return tl::unexpected(std::move(ok.error()));
        }
        if (const auto* headers = settings.if_contains("headers");
            headers && !headers->is_null() && !IsPanelEmptyObject(*headers)) {
            if (!headers->is_object()) {
                return tl::unexpected(
                    "networkSettings headers must be an object");
            }
            std::optional<std::string> host;
            for (const auto& [name, raw_value] : headers->as_object()) {
                if (!common::EqualsAsciiCI(name, "host")) {
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
    if (config.TransportProtocol == common::kGrpc) {
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

    if (const auto* tls = source.if_contains(common::kTls);
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

    if (auto ok = AssignOptionalNodeString(source, "flow", config.Flow, {}, true); !ok) {
        return tl::unexpected(std::move(ok.error()));
    }

    std::string raw_server_name;
    if (auto has_sni = AssignOptionalNodeString(source, "server_name", raw_server_name); !has_sni) {
        return tl::unexpected(std::move(has_sni.error()));
    } else if (*has_sni) {
        auto normalized = infra::NormalizeTlsServerName(raw_server_name, "server_name");
        if (!normalized) {
            return tl::unexpected(std::move(normalized.error()));
        }
        config.TLSServerName = std::move(*normalized);
    }
    if (auto ok = AssignOptionalNodeString(source, "cipher", config.CypherMethod, {}, true); !ok) {
        return tl::unexpected(std::move(ok.error()));
    }
    if (auto ok = AssignOptionalNodeString(
            source, "server_key", config.ShadowsocksServerKey); !ok) {
        return tl::unexpected(std::move(ok.error()));
    }
    if (const auto* host = source.if_contains("host");
        host && !host->is_null() && !host->is_string()) {
        return tl::unexpected("host must be a string");
    }

    if (config.NodeType == common::kShadowsocks) {
        if (auto ok = ValidateUnsupportedPanelMode(
                source, "obfs", "Shadowsocks obfs is not supported by this runtime"); !ok) {
            return tl::unexpected(std::move(ok.error()));
        }
        if (auto ok = ValidateOptionalPanelObject(source, "obfs_settings"); !ok) {
            return tl::unexpected(std::move(ok.error()));
        }
    }

    if (config.NodeType == common::kVless) {
        if (auto ok = ValidateUnsupportedPanelMode(
                source, "encryption", "panel VLESS encryption is not supported by this runtime"); !ok) {
            return tl::unexpected(std::move(ok.error()));
        }
        if (auto ok = ValidateOptionalPanelObject(source, "encryption_settings"); !ok) {
            return tl::unexpected(std::move(ok.error()));
        }
        if (auto ok = ValidateOptionalPanelObject(source, "tls_settings"); !ok) {
            return tl::unexpected(std::move(ok.error()));
        }
    }

    if (config.NodeType == common::kAnyTLS) {
        if (const auto* padding = source.if_contains("padding_scheme")) {
            auto scheme = infra::ParseAnyTlsPaddingScheme(*padding, "padding_scheme");
            if (!scheme) {
                return tl::unexpected(std::move(scheme.error()));
            }
            config.PaddingScheme = std::move(*scheme);
        }
    }

    if (config.NodeType == common::kHysteria ||
        config.NodeType == common::kHysteria2) {
        auto version = ParseRequiredPanelUint32(source, "version");
        if (!version || (*version != 1 && *version != 2)) {
            return tl::unexpected(
                version ? "version must be 1 or 2" : std::move(version.error()));
        }
        config.NodeType = *version == 1
            ? std::string(common::kHysteria)
            : std::string(common::kHysteria2);

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
            if (auto ok = ValidateUnsupportedPanelMode(
                    source, field, "Hysteria obfs is not supported by this runtime", false); !ok) {
                return tl::unexpected(std::move(ok.error()));
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

tl::expected<std::vector<common::DetectRule>, std::string> ExtractBlockDetectRules(
    const infra::object& config) {
    std::vector<common::DetectRule> rules;
    const auto* routes_value = config.if_contains("routes");
    if (!routes_value || routes_value->is_null()) {
        return rules;
    }
    if (!routes_value->is_array()) {
        return tl::unexpected("routes must be an array");
    }

    const auto& routes = routes_value->as_array();
    rules.reserve(routes.size());
    for (size_t i = 0; i < routes.size(); ++i) {
        const auto& route_value = routes[i];
        if (!route_value.is_object()) {
            return tl::unexpected("route entries must be objects");
        }

        const auto& route = route_value.as_object();
        const auto* action = route.if_contains("action");
        if (action && !action->is_null() && !action->is_string()) {
            return tl::unexpected("route action must be a string");
        }
        if (!action || !action->is_string() || action->as_string() != "block") {
            continue;
        }

        const auto* match_value = route.if_contains("match");
        if (!match_value || !match_value->is_array()) {
            return tl::unexpected("block route match must be an array");
        }

        const auto& matches = match_value->as_array();
        if (matches.empty()) {
            return tl::unexpected("block route match must not be empty");
        }
        for (size_t j = 0; j < matches.size(); ++j) {
            const auto& match = matches[j];
            if (!match.is_string()) {
                return tl::unexpected(
                    "block route match entries must be strings");
            }
            const std::string_view entry = match.as_string();
            if (entry.empty()) {
                return tl::unexpected(
                    "block route match entries must not be empty");
            }
            if (common::ContainsControlCharacter(entry)) {
                return tl::unexpected(
                    "block route match entries must not contain control characters");
            }
            try {
                rules.push_back(common::DetectRule{
                    .Pattern = std::regex(std::string(entry)),
                });
            } catch (const std::regex_error& entry_error) {
                return tl::unexpected(std::format(
                    "Invalid block route detect rule {} (match {}): {}",
                    i, j, entry_error.what()));
            }
        }
    }
    return rules;
}

namespace {

template <typename Object>
tl::expected<std::vector<UserInfo>, std::string>
ParseUserListImpl(Object&& source) {
    constexpr bool kCanConsume =
        !std::is_const_v<std::remove_reference_t<Object>> &&
        !std::is_lvalue_reference_v<Object>;
    auto* users_value = source.if_contains("users");
    if (!users_value) {
        return tl::unexpected("users is required");
    }
    if (!users_value->is_array()) {
        return tl::unexpected("users must be an array");
    }

    auto& users_array = users_value->as_array();
    std::vector<UserInfo> users;
    users.reserve(users_array.size());
    // A repeated id would merge accounting for two users. Credentials are
    // compared after protocol derivation, when the UserStore snapshot is built.
    std::unordered_set<int64_t> seen_ids;
    seen_ids.reserve(users_array.size());
    for (size_t i = 0; i < users_array.size(); ++i) {
        auto& user_value = users_array[i];
        if (!user_value.is_object()) {
            return tl::unexpected(std::format("users[{}] must be an object", i));
        }
        auto& source_user = user_value.as_object();
        UserInfo user;

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

        auto* uuid = source_user.if_contains("uuid");
        if (!uuid || !uuid->is_string() || uuid->as_string().empty()) {
            return tl::unexpected(std::format(
                "users[{}].uuid must be a non-empty string", i));
        }
        if (common::ContainsControlCharacter(uuid->as_string())) {
            return tl::unexpected(std::format(
                "users[{}].uuid contains control characters", i));
        }
        if constexpr (kCanConsume) {
            user.UUID = std::move(uuid->as_string());
        } else {
            user.UUID = std::string(uuid->as_string());
        }

        auto flow = [&]() {
            if constexpr (kCanConsume) {
                return ParseOptionalString(std::move(source_user), "flow", i);
            } else {
                return ParseOptionalString(source_user, "flow", i);
            }
        }();
        if (!flow) return tl::unexpected(std::move(flow.error()));
        user.Flow = common::LowerAscii(std::move(*flow));

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

        auto email = [&]() {
            if constexpr (kCanConsume) {
                return ParseOptionalString(std::move(source_user), "email", i);
            } else {
                return ParseOptionalString(source_user, "email", i);
            }
        }();
        if (!email) return tl::unexpected(std::move(email.error()));
        user.Email = std::move(*email);
        if constexpr (kCanConsume) {
            user_value = infra::value{};
        }
        users.push_back(std::move(user));
    }
    return users;
}

}  // namespace

tl::expected<std::vector<UserInfo>, std::string>
ParseUserList(const infra::object& source) {
    return ParseUserListImpl(source);
}

tl::expected<std::vector<UserInfo>, std::string>
ParseUserList(infra::object&& source) {
    return ParseUserListImpl(std::move(source));
}

OnlineReportPayload BuildOnlineReportPayload(
    std::span<const OnlineUser> online_devices,
    int node_id) {
    if (IsCanonicalDeviceList(online_devices)) {
        return BuildFromCanonicalDevices(online_devices, node_id);
    }

    std::vector<OnlineUser> valid;
    valid.reserve(online_devices.size());
    for (const auto& device : online_devices) {
        if (IsValidDevice(device)) {
            valid.push_back(device);
        }
    }

    std::ranges::sort(valid, DeviceLess);
    const auto duplicate_tail = std::ranges::unique(
        valid, [](const OnlineUser& lhs, const OnlineUser& rhs) {
            return lhs.UID == rhs.UID && lhs.IP == rhs.IP;
        });
    valid.erase(duplicate_tail.begin(), duplicate_tail.end());

    return BuildFromCanonicalDevices(valid, node_id);
}

}  // namespace api
