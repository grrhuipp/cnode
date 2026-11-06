#pragma once

#include "acppnode/proxy/outbound.hpp"
#include "../account.hpp"
#include "../types.hpp"
#include "acppnode/transport/internet/outbound_sender.hpp"

#include <openssl/aes.h>

#include <chrono>
#include <memory>

namespace acpp {

// ============================================================================
// VMess Outbound 配置（传输层与 sendThrough 属于 Handler 的 sender settings）
// ============================================================================
struct VMessOutboundConfig {
    OutboundServer server;
    vmess::Security security = vmess::Security::AES_128_GCM;
};

// ============================================================================
// VMess Outbound
// ============================================================================
namespace proxy::vmess::outbound {

struct PreparedSettings {
    VMessOutboundConfig config;
    ::acpp::vmess::MemoryAccount user;
    AES_KEY auth_id_key{};  // Encrypt schedule of user.auth_key, built on prepare.
};

class Handler final : public ::acpp::Outbound {
public:
    explicit Handler(std::shared_ptr<const PreparedSettings> prepared);

    ::acpp::net::awaitable<::acpp::OutboundProcessResult> Process(
        ::acpp::session::Context& ctx,
        ::acpp::transport::Link inbound,
        ::acpp::OutboundDialer& dialer,
        const ::acpp::TimeoutsConfig& timeouts,
        ::acpp::StatsShard& stats,
        const ::acpp::RelayConfig& relay_config,
        ::acpp::buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    std::shared_ptr<const PreparedSettings> prepared_;
};

}  // namespace proxy::vmess::outbound

}  // namespace acpp
