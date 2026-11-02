#include "blackhole_outbound.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../app/proxyman/outbound/registration.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/log.hpp"

namespace acpp::proxy::blackhole::outbound {

namespace {
constexpr std::string_view kHttp403Response =
    "HTTP/1.1 403 Forbidden\r\n"
    "Connection: close\r\n"
    "Cache-Control: max-age=3600, public\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

[[nodiscard]] bool IsHttpResponse(std::string_view response) noexcept {
    return response == constants::protocol::kHttp || response == "HTTP";
}

}  // namespace

// ============================================================================
// Handler 实现
// ============================================================================

Handler::Handler(std::string_view tag,
                 const BlackholeSettings& settings)
    : tag_(tag)
    , http_response_(IsHttpResponse(settings.response)) {
}

net::awaitable<OutboundProcessResult> Handler::Process(
    net::io_context& /*io_context*/,
    const tcp::endpoint* /*inbound_local_addr*/,
    session::Context& ctx,
    const TimeoutsConfig& /*timeouts*/,
    transport::Link inbound,
    StatsShard& /*stats*/,
    const RelayConfig& /*relay_config*/,
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds /*relay_idle_timeout*/,
    std::chrono::seconds /*relay_write_timeout*/) {
    first_payload.clear();
    if (http_response_ && inbound.writer) {
        net::const_buffer response{kHttp403Response.data(), kHttp403Response.size()};
        try {
            co_await inbound.writer->WriteBuffers(
                std::span<const net::const_buffer>{&response, 1});
            co_await inbound.writer->AsyncShutdownWrite();
        } catch (...) {
            LOG_CONN_DEBUG(ctx, "[Blackhole][{}] failed to write http response", tag_);
        }
    }
    LOG_CONN_DEBUG(ctx, "[Blackhole][{}] blocked before relay response={}",
                   tag_, http_response_ ? "http" : "none");
    co_return tl::unexpected(ErrorCode::BLOCKED);
}

}  // namespace acpp::proxy::blackhole::outbound

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kBlackholeRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kBlackhole,
    [](const acpp::infra::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        acpp::proxy::blackhole::outbound::BlackholeSettings settings;
        if (const auto* p = cfg.settings.if_contains("response")) {
            // Xray 格式: {"response": {"type": "http"}}
            if (p->is_object()) {
                const auto& resp = p->as_object();
                if (auto* tp = resp.if_contains("type"); tp && tp->is_string()) {
                    settings.response = std::string(tp->as_string());
                }
            }
        }
        return acpp::proxyman::outbound::MakePreparedOutboundCreator<
            acpp::proxy::blackhole::outbound::BlackholeSettings,
            +[](std::string_view tag,
                std::shared_ptr<const acpp::proxy::blackhole::outbound::BlackholeSettings> s,
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& /*dns*/,
                std::chrono::seconds /*dial_timeout*/) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<acpp::proxy::blackhole::outbound::Handler>(
                    tag, *s);
            }>(std::move(settings));
    }), true);
}  // namespace
