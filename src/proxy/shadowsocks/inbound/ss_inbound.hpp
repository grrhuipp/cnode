#pragma once

#include "acppnode/app/proxyman/inbound/udp_handler.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/app/udp_types.hpp"
#include "../ss_udp.hpp"
#include "../validator.hpp"

#include <array>
#include <memory>
#include <expected>
#include <utility>

namespace acpp {
struct StatsShard;
}  // namespace acpp

namespace acpp::proxy::shadowsocks::inbound {

class Handler final : public ::acpp::Inbound,
                      public ::acpp::proxyman::inbound::UdpHandler {
public:
    Handler(::acpp::ss::Validator& validator,
            ::acpp::StatsShard& stats,
            ::acpp::ConnectionLimiterPtr limiter,
            std::string cipher_method);

    void AdoptWorkerStateFrom(
        ::acpp::proxyman::inbound::UdpHandler& previous) noexcept override;

    // 解析首包：读 salt + 首 chunk，尝试所有用户密钥，解析 SOCKS5 地址
    ::acpp::net::awaitable<::acpp::RelayResult> Process(
        std::unique_ptr<::acpp::AsyncStream> stream,
        ::acpp::routing::Dispatcher& dispatcher,
        const ::acpp::proxyman::inbound::ReceiverSettings& receiver,
        ::acpp::net::io_context& io_context,
        ::acpp::session::Context& ctx,
        const ::acpp::TimeoutsConfig& timeouts) override;

    // 对应 xray-core proxy/shadowsocks/server.go 的 handleUDPPayload 解码路径。
    [[nodiscard]] std::expected<
        ::acpp::proxyman::inbound::UdpDecodeResult,
        ::acpp::ErrorCode> DecodeUdp(
        std::string_view tag,
        std::string_view client_ip,
        const uint8_t* data,
        size_t len) override;

private:
    ::acpp::ss::Validator& validator_;
    ::acpp::StatsShard* stats_ = nullptr;
    ::acpp::ConnectionLimiterPtr limiter_;
    std::string         cipher_method_;
    ::acpp::ss::SsCipherInfo cipher_info_;
    ::acpp::ss::Ss2022UdpReplayCache udp_replay_cache_;
    // 上次匹配成功的用户索引，用于优先尝试（大概率命中同一活跃用户）
    size_t last_matched_index_ = 0;
};

}  // namespace acpp::proxy::shadowsocks::inbound
