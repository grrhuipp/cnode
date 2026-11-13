#pragma once

#include "proxy/shadowsocks/ss_udp.hpp"
#include "proxy/shadowsocks/ss_stream.hpp"
#include "proxy/inbound.hpp"

namespace app { struct AdmissionEnvironment; }

namespace proxy {

class SsInboundHandler final : public ::proxy::Inbound {
public:
    SsInboundHandler(const ::app::AdmissionEnvironment& environment,
            ::proxy::SsCipherInfo cipher_info);

    // 解析首包：读 salt + 首 chunk，尝试所有用户密钥，解析 SOCKS5 地址
    ::net::awaitable<::app::RelayResult> Process(
        std::unique_ptr<::transport::AsyncStream> stream,
        ::routing::Dispatcher& dispatcher,
        const ::app::ReceiverSettings& receiver,
        ::net::io_context& io_context,
        ::common::Context& ctx,
        const ::infra::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

    // 对应 xray-core proxy/shadowsocks/server.go 的 handleUDPPayload 解码路径。
    [[nodiscard]] tl::expected<
        ::proxy::InboundDatagramResult,
        ::common::ErrorCode> Process(
        const ::proxy::InboundDatagramRequest& request) override;

    [[nodiscard]] tl::expected<
        std::shared_ptr<::proxy::InboundDatagramResponse>, ::common::ErrorCode>
    CreateDatagramResponse(const ::proxy::InboundDatagramResult& decoded) override;

private:
    const ::app::AdmissionEnvironment& environment_;
    ::proxy::SsCipherInfo cipher_info_;
    ::proxy::Ss2022UdpReplayCache udp_replay_cache_;
    // 上次匹配成功的用户索引，用于优先尝试（大概率命中同一活跃用户）
    size_t last_matched_index_ = 0;
};


struct ReadTCPSessionResult {
    std::shared_ptr<const app::UserStore::ShadowsocksCredential> user;
    common::TargetAddress target;
    std::optional<common::ForwardedMetadata> forwarded;
    common::InitialPayload initial_payload;
    std::optional<BodyReader> body_reader;
    KeyBytes request_salt;
};

[[nodiscard]] net::awaitable<tl::expected<ReadTCPSessionResult, common::ErrorCode>>
ReadTCPSession(transport::AsyncStream& stream,
               const SsCipherInfo& cipher_info,
               std::string_view tag,
               size_t& last_matched_index);

[[nodiscard]] tl::expected<SsStreamWriter, common::ErrorCode>
WriteTCPResponse(const app::UserStore::ShadowsocksCredential& user,
                 const SsCipherInfo& cipher_info,
                 const KeyBytes& request_salt,
                 transport::AsyncStream& stream);
}  // namespace proxy
