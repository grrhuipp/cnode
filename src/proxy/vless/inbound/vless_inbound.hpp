#pragma once

#include "proxy/inbound.hpp"
#include "common/sharded_user_stats.hpp"

#include <memory>
#include <string>

struct StatsShard;

namespace vless {
struct VlessEncryptionConfig;
}  // namespace vless

namespace proxy::vless::inbound {

class Handler final : public ::Inbound {
public:
    Handler(::UserOnlineTracker& validator,
            ::StatsShard& stats,
            ::ConnectionLimiter* limiter,
            std::shared_ptr<
                const ::vless::VlessEncryptionConfig> decryption = {});
    ~Handler() override;

    ::net::awaitable<::RelayResult> Process(
        std::unique_ptr<::AsyncStream> stream,
        ::routing::Dispatcher& dispatcher,
        const ::proxyman::inbound::ReceiverSettings& receiver,
        ::net::io_context& io_context,
        ::session::Context& ctx,
        const ::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    ::UserOnlineTracker& validator_;
    ::StatsShard* stats_ = nullptr;
    ::ConnectionLimiter* limiter_;
    std::shared_ptr<const ::vless::VlessEncryptionConfig> decryption_;
};

}  // namespace proxy::vless::inbound
