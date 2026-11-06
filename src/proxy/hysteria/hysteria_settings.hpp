#pragma once

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "hysteria_protocol.hpp"

#include <cstdint>

namespace acpp::proxy::hysteria {

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

}  // namespace acpp::proxy::hysteria
