#include "blackhole_outbound.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "../../app/proxyman/outbound/registration.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/session.hpp"
#include "core/constants.hpp"
#include "core/naming.hpp"
#include "infra/json_field.hpp"
#include "infra/log.hpp"

namespace proxy::blackhole::outbound {

namespace {
constexpr std::string_view kHttp403Response =
    "HTTP/1.1 403 Forbidden\r\n"
    "Connection: close\r\n"
    "Cache-Control: max-age=3600, public\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

}  // namespace

// ============================================================================
// Handler 实现
// ============================================================================

Handler::Handler(const BlackholeSettings& settings)
    : http_response_(settings.http_response) {
}

net::awaitable<OutboundProcessResult> Handler::Process(
    session::Context& ctx,
    transport::Link inbound,
    OutboundDialer& /*dialer*/,
    const TimeoutsConfig& /*timeouts*/,
    StatsShard& /*stats*/,
    const RelayConfig& /*relay_config*/,
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds /*relay_idle_timeout*/,
    std::chrono::seconds /*relay_write_timeout*/) {
    first_payload.clear();
    const bool send_http =
        http_response_ && ctx.content.network == Network::TCP && inbound.writer;
    if (send_http) {
        net::const_buffer response{kHttp403Response.data(), kHttp403Response.size()};
        try {
            co_await inbound.writer->WriteBuffers(
                std::span<const net::const_buffer>{&response, 1});
            co_await inbound.writer->AsyncShutdownWrite();
        } catch (...) {
            LOG_CONN_DEBUG(ctx, "failed to write HTTP response");
        }
    }
    LOG_CONN_DEBUG(ctx, "blocked before relay response={}", send_http ? "http" : "none");
    co_return tl::unexpected(ErrorCode::BLOCKED);
}

}  // namespace proxy::blackhole::outbound

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kBlackholeRegistered = (::proxyman::outbound::RegisterProxy(
    ::constants::protocol::kBlackhole,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::proxyman::outbound::PreparedOutboundProxy> {
        ::proxy::blackhole::outbound::BlackholeSettings settings;
        if (const auto* p = cfg.settings.if_contains("response")) {
            // Xray 格式: {"response": {"type": "http"}}；未知类型或错误类型拒绝加载。
            if (!p->is_object()) {
                LOG_ERROR("blackhole outbound '{}': response must be an object", cfg.tag);
                return std::nullopt;
            }
            const auto type = ::ParseJsonString(p->as_object(), "type");
            if (!type) {
                LOG_ERROR("blackhole outbound '{}': response {}", cfg.tag, type.error());
                return std::nullopt;
            }
            if (*type) {
                const std::string value = ::naming::LowerAscii(**type);
                if (value == ::constants::protocol::kHttp) {
                    settings.http_response = true;
                } else if (value != ::constants::protocol::kNone) {
                    LOG_ERROR("blackhole outbound '{}': response type must be http or none", cfg.tag);
                    return std::nullopt;
                }
            }
        }
        return ::proxyman::outbound::PreparedOutboundProxy{
            .create = ::proxyman::outbound::MakePreparedOutboundCreator<
                ::proxy::blackhole::outbound::BlackholeSettings,
                +[](std::string_view /*tag*/,
                    std::shared_ptr<const ::proxy::blackhole::outbound::BlackholeSettings> s,
                    ::net::io_context& /*io_context*/,
                    ::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::Outbound> {
                    return std::make_unique<::proxy::blackhole::outbound::Handler>(*s);
                }>(std::move(settings)),
            .sender = {},
        };
    }), true);
}  // namespace
