#pragma once

#include "proxy/shadowsocks/ss_udp.hpp"
#include "proxy/inbound.hpp"

class UserOnlineTracker;

namespace proxy::shadowsocks::inbound {

class Handler final : public ::Inbound {
public:
    Handler(::UserOnlineTracker& tracker,
            ::StatsShard& stats,
            ::ConnectionLimiter* limiter,
            ::ss::SsCipherInfo cipher_info);

    // 解析首包：读 salt + 首 chunk，尝试所有用户密钥，解析 SOCKS5 地址
    ::net::awaitable<::RelayResult> Process(
        std::unique_ptr<::AsyncStream> stream,
        ::routing::Dispatcher& dispatcher,
        const ::proxyman::inbound::ReceiverSettings& receiver,
        ::net::io_context& io_context,
        ::session::Context& ctx,
        const ::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

    // 对应 xray-core proxy/shadowsocks/server.go 的 handleUDPPayload 解码路径。
    [[nodiscard]] tl::expected<
        ::InboundDatagramResult,
        ::ErrorCode> Process(
        const ::InboundDatagramRequest& request) override;

    [[nodiscard]] tl::expected<
        std::shared_ptr<::InboundDatagramResponse>, ::ErrorCode>
    CreateDatagramResponse(const ::InboundDatagramResult& decoded) override;

private:
    ::UserOnlineTracker& tracker_;
    ::StatsShard& stats_;
    ::ConnectionLimiter* limiter_;
    ::ss::SsCipherInfo cipher_info_;
    ::ss::Ss2022UdpReplayCache udp_replay_cache_;
    // 上次匹配成功的用户索引，用于优先尝试（大概率命中同一活跃用户）
    size_t last_matched_index_ = 0;
};

}  // namespace proxy::shadowsocks::inbound
