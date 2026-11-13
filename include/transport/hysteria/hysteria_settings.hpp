#pragma once

#include "app/proxyman/inbound_handler.hpp"
#include "transport/hysteria/hysteria_wire.hpp"
namespace transport {

// 准备期的协议快照，供注册表和 QUIC 入口共享；不暴露 QUIC 库或监听器实现。
class HysteriaSettings final : public app::ProtocolSettings {
public:
    HysteriaVersion version = HysteriaVersion::V2;
    uint64_t upload_bytes_per_second = 0;
    uint64_t download_bytes_per_second = 0;
};

[[nodiscard]] inline const HysteriaSettings* GetSettings(
    const app::BuildRequest& request) noexcept {
    return dynamic_cast<const HysteriaSettings*>(request.settings.get());
}

}  // namespace transport
