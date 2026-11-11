#pragma once

#include "app/proxyman/inbound/handler.hpp"
#include "transport/internet/hysteria/hysteria_wire.hpp"

namespace transport::internet::hysteria {

// 准备期的协议快照，供注册表和 QUIC 入口共享；不暴露 QUIC 库或监听器实现。
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
