#pragma once

#include "acppnode/proxy/inbound.hpp"
#include "../validator.hpp"

#include <memory>
#include <string>

namespace acpp {
struct StatsShard;
}  // namespace acpp

namespace acpp::vless {
struct VlessEncryptionConfig;
class VlessEncryptionServerTicketStore;
}  // namespace acpp::vless

namespace acpp::proxy::vless::inbound {

class Handler final : public ::acpp::Inbound {
public:
    Handler(::acpp::vless::Validator& validator,
            ::acpp::StatsShard& stats,
            ::acpp::ConnectionLimiterPtr limiter,
            std::string vless_decryption = {});
    ~Handler() override;

    ::acpp::net::awaitable<::acpp::RelayResult> Process(
        std::unique_ptr<::acpp::AsyncStream> stream,
        ::acpp::routing::Dispatcher& dispatcher,
        const ::acpp::proxyman::inbound::ReceiverSettings& receiver,
        ::acpp::net::io_context& io_context,
        ::acpp::session::Context& ctx,
        const ::acpp::TimeoutsConfig& timeouts) override;

private:
    ::acpp::vless::Validator& validator_;
    ::acpp::StatsShard* stats_ = nullptr;
    ::acpp::ConnectionLimiterPtr limiter_;
    std::shared_ptr<const ::acpp::vless::VlessEncryptionConfig> decryption_;
    std::unique_ptr<::acpp::vless::VlessEncryptionServerTicketStore>
        decryption_tickets_;
};

}  // namespace acpp::proxy::vless::inbound
