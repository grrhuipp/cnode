#pragma once

#include "proxy/outbound.hpp"
#include "../shadowsocks_protocol.hpp"
#include "../../uot/uot.hpp"
#include "infra/json.hpp"
#include "transport/internet/outbound_sender.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <tl/expected.hpp>
#include <utility>
#include <vector>

// ============================================================================
// SS Outbound 配置
// ============================================================================
struct SsOutboundConfig {
    OutboundServer server;
    std::optional<proxy::uot::Version> uot_version;
};

// ============================================================================
// SsOutbound — 出站编排（握手、初始 payload、relay、收尾）
// 协议加密状态由 shadowsocks_protocol.cpp 承担。
// ============================================================================
namespace proxy::shadowsocks::outbound {

// A complete, validated credential value. Preparation never drops a chain link
// or substitutes a different cipher; Worker handlers only consume this value.
class Credentials {
public:
    [[nodiscard]] static std::optional<Credentials> Prepare(
        std::string_view method, std::string_view password);

    [[nodiscard]] const ss::SsCipherInfo& Cipher() const noexcept { return cipher_; }
    [[nodiscard]] const ss::KeyBytes& MasterKey() const noexcept { return master_key_; }
    [[nodiscard]] std::span<const ss::KeyBytes> PskChain() const noexcept {
        return psk_chain_;
    }

private:
    Credentials(ss::SsCipherInfo cipher, ss::KeyBytes master_key,
                std::vector<ss::KeyBytes> psk_chain)
        : cipher_(cipher), master_key_(master_key), psk_chain_(std::move(psk_chain)) {}

    ss::SsCipherInfo cipher_;
    ss::KeyBytes master_key_;
    std::vector<ss::KeyBytes> psk_chain_;
};

[[nodiscard]] tl::expected<std::optional<proxy::uot::Version>, std::string>
ParseUotVersion(const json::object& source);

struct PreparedSettings {
    SsOutboundConfig config;
    Credentials credentials;
};

class Handler final : public ::Outbound {
public:
    explicit Handler(std::shared_ptr<const PreparedSettings> prepared);

    ~Handler() noexcept override = default;

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

}  // namespace proxy::shadowsocks::outbound

