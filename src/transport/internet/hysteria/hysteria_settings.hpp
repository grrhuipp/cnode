#pragma once

#include "app/proxyman/inbound/prepared_config.hpp"
#include "hysteria_protocol.hpp"

#include <cstdint>

namespace transport::internet::hysteria {

// Prepared Hysteria settings, built by the proxy registration on the cold
// path. The QUIC transport selects ALPN/auth/framing by version and announces
// the bandwidth; the inbound handler reads the request format by version.
class Settings final : public proxyman::inbound::ProtocolSettings {
public:
    Version version = Version::V2;
    uint64_t upload_bytes_per_second = 0;
    uint64_t download_bytes_per_second = 0;
};

[[nodiscard]] inline const Settings* GetSettings(
    const proxyman::inbound::BuildRequest& request) noexcept {
    return dynamic_cast<const Settings*>(request.settings.get());
}

}  // namespace transport::internet::hysteria
