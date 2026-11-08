#pragma once

#include "proxy/outbound.hpp"
#include "../account.hpp"
#include "../types.hpp"
#include "transport/internet/outbound_sender.hpp"

#include <openssl/aes.h>
#include "common/unsafe.hpp"
#include <chrono>
#include <memory>


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
    ::vmess::MemoryAccount user;
    AES_KEY auth_id_key{};  // Encrypt schedule of user.auth_key, built on prepare.

    ~PreparedSettings() noexcept {
        ::SecureZeroMemory(&auth_id_key, sizeof(auth_id_key));
    }
};

class Handler final : public ::Outbound {
public:
    explicit Handler(std::shared_ptr<const PreparedSettings> prepared);

    ::net::awaitable<::OutboundProcessResult> Process(
        ::session::Context& ctx,
        ::transport::Link inbound,
        ::OutboundDialer& dialer,
        const ::TimeoutsConfig& timeouts,
        ::StatsShard& stats,
        const ::RelayConfig& relay_config,
        ::buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    std::shared_ptr<const PreparedSettings> prepared_;
};

}  // namespace proxy::vmess::outbound

