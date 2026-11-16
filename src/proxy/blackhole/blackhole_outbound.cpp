#include "app/outbound_handler.hpp"
#include "common/constants.hpp"
#include "proxy/outbound.hpp"

#include <memory>
#include <string_view>
namespace proxy {


class BlackholeOutbound final : public Outbound {
public:
    explicit BlackholeOutbound(const infra::BlackholeSettings& settings);

    struct Session final : OutboundSession {
        bool http_response;
        Session(OutboundPrepareContext&, bool http) noexcept : http_response(http) {}
        OutboundRejection Prepare() const noexcept {
            return {common::ErrorCode::BLOCKED, http_response};
        }
    };
    auto SessionArguments() const noexcept { return std::tuple{http_response_}; }

private:
    bool http_response_;
};

// ============================================================================
// Handler 实现
// ============================================================================

BlackholeOutbound::BlackholeOutbound(const infra::BlackholeSettings& settings)
    : Outbound(std::in_place_type<BlackholeOutbound>)
    , http_response_(settings.http_response) {}


}  // namespace proxy

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kBlackholeRegistered = (::app::RegisterProxy(
    ::common::kBlackhole,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::app::PreparedOutboundProxy> {
        const auto* settings = std::get_if<::infra::BlackholeSettings>(&cfg.settings);
        if (!settings) return std::nullopt;
        return ::app::PreparedOutboundProxy{
            .create = ::app::MakePreparedOutboundCreator<
                ::infra::BlackholeSettings,
                +[](std::string_view /*tag*/,
                    std::shared_ptr<const ::infra::BlackholeSettings> s,
                    ::net::io_context& /*io_context*/,
                    ::common::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::proxy::Outbound> {
                    return std::make_unique<::proxy::BlackholeOutbound>(*s);
                }>(*settings),
            .sender = {},
        };
    }), true);
}  // namespace
