#pragma once

#include "acppnode/proxy/inbound.hpp"
#include "acppnode/proxy/vless/validator.hpp"

#include <memory>
#include <string>

namespace acpp {
struct StatsShard;
}  // namespace acpp

namespace acpp::vless {
struct VlessEncryptionConfig;
}  // namespace acpp::vless

namespace acpp::proxy::vless::inbound {

class Handler final : public ::acpp::Inbound {
public:
    Handler(::acpp::vless::Validator& validator,
            ::acpp::StatsShard& stats,
            ::acpp::ConnectionLimiterPtr limiter,
            std::string vless_decryption = {});

    ::acpp::net::awaitable<::acpp::RelayResult> Process(
        std::unique_ptr<::acpp::AsyncStream> stream,
        ::acpp::routing::Dispatcher& dispatcher,
        const ::acpp::proxyman::inbound::ReceiverSettings& receiver,
        ::acpp::net::io_context& io_context,
        ::acpp::session::Context& ctx,
        const ::acpp::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

    void SetBanTrackingEnabled(bool enabled) noexcept override {
        ban_tracking_enabled_ = enabled;
    }

private:
    ::acpp::vless::Validator& validator_;
    ::acpp::StatsShard* stats_ = nullptr;
    ::acpp::ConnectionLimiterPtr limiter_;
    std::shared_ptr<const ::acpp::vless::VlessEncryptionConfig> decryption_;
    bool ban_tracking_enabled_ = false;
};

}  // namespace acpp::proxy::vless::inbound
