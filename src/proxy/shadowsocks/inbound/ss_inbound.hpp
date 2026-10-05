#pragma once

#include "acppnode/proxy/inbound.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/app/udp_types.hpp"
#include "../ss_udp.hpp"
#include "../validator.hpp"

#include <array>
#include <memory>
#include <tl/expected.hpp>
#include <utility>

namespace acpp {
struct StatsShard;
}  // namespace acpp

namespace acpp::proxy::shadowsocks::inbound {

class Handler final : public ::acpp::Inbound {
public:
    Handler(::acpp::ss::Validator& validator,
            ::acpp::UserOnlineTracker& online,
            ::acpp::ConnectionLimiterPtr limiter,
            ::acpp::ss::SsCipherInfo cipher_info);

    void AdoptOwnerStateFrom(
        ::acpp::Inbound& previous) noexcept override;

    // 解析首包：读 salt + 首 chunk，尝试所有用户密钥，解析 SOCKS5 地址
    ::acpp::net::awaitable<::acpp::RelayResult> ProcessSession(
        std::unique_ptr<::acpp::AsyncStream> stream,
        ::acpp::routing::Dispatcher& dispatcher,
        const ::acpp::proxyman::inbound::ReceiverSettings& receiver,
        ::acpp::net::any_io_executor executor,
        ::acpp::session::Context& ctx,
        ::acpp::StatsShard& stats,
        ::acpp::UserOnlineLease& online,
        const ::acpp::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

    // 对应 xray-core proxy/shadowsocks/server.go 的 handleUDPPayload 解码路径。
    [[nodiscard]] tl::expected<
        ::acpp::InboundDatagramResult,
        ::acpp::ErrorCode> Process(
        const ::acpp::InboundDatagramRequest& request) override;

private:
    ::acpp::ss::Validator& validator_;
    ::acpp::ConnectionLimiterPtr limiter_;
    ::acpp::ss::SsCipherInfo cipher_info_;
    ::acpp::ss::Ss2022UdpReplayCache udp_replay_cache_;
};

}  // namespace acpp::proxy::shadowsocks::inbound
