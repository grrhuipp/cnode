#include "acppnode/proxy/blackhole/blackhole_outbound.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../app/proxyman/outbound/source_config.hpp"
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

Handler::Handler(const std::string& tag,
                 const BlackholeSettings& settings)
    : tag_(tag)
    , settings_(settings) {
}

net::awaitable<OutboundProcessResult> Handler::Process(
    net::io_context& /*io_context*/,
    const tcp::endpoint* /*inbound_local_addr*/,
    session::Context& ctx,
    const TimeoutsConfig& /*timeouts*/,
    transport::Link inbound,
    StatsShard& /*stats*/,
    const RelayConfig& /*relay_config*/,
    std::span<const uint8_t> /*initial_payload*/,
    buf::MultiBuffer& first_payload,
    std::chrono::seconds /*relay_idle_timeout*/,
    std::chrono::seconds /*relay_write_timeout*/) {
    first_payload.clear();
    if (IsHttpResponse(settings_.response) && inbound.writer) {
        net::const_buffer response{kHttp403Response.data(), kHttp403Response.size()};
        try {
            co_await inbound.writer->WriteBuffers(
                std::span<const net::const_buffer>{&response, 1});
            co_await inbound.writer->AsyncShutdownWrite();
        } catch (...) {
            LOG_CONN_DEBUG(ctx, "[Blackhole][{}] failed to write http response", tag_);
        }
    }
    LOG_CONN_DEBUG(ctx, "[Blackhole][{}] blocked before relay response={}", tag_, settings_.response);
    co_return std::unexpected(ErrorCode::BLOCKED);
}

}  // namespace acpp::proxy::blackhole::outbound

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kBlackholeRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kBlackhole,
    [](const acpp::proxyman::outbound::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundConfig> {
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
        acpp::proxyman::outbound::PreparedOutboundConfig prepared;
        prepared.tag = cfg.tag;
        prepared.protocol = cfg.protocol;
        prepared.create =
            [tag = cfg.tag, settings = std::move(settings)](
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& /*dns*/,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds /*dial_timeout*/) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<acpp::proxy::blackhole::outbound::Handler>(tag, settings);
            };
        return prepared;
    }), true);
}  // namespace
