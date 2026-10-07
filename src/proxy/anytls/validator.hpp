#pragma once

#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct OnlineDevice;
}  // namespace acpp

namespace acpp::anytls {

class Validator {
public:
    Validator();
    ~Validator();

    Validator(const Validator&) = delete;
    Validator& operator=(const Validator&) = delete;
    Validator(Validator&&) noexcept;
    Validator& operator=(Validator&&) noexcept;

    [[nodiscard]] std::shared_ptr<const proxyman::inbound::UserStore::AnyTlsCredential> Validate(
        std::string_view tag,
        const std::array<uint8_t, 32>& password_hash) const;

    [[nodiscard]] size_t Size() const;
    [[nodiscard]] size_t SizeForTag(std::string_view tag) const;

    void OnUserConnected(std::string_view tag,
                         uint64_t user_id,
                         std::string_view client_ip);

    void OnUserDisconnected(std::string_view tag,
                            uint64_t user_id,
                            std::string_view client_ip);

    [[nodiscard]] bool CanAcceptDevice(std::string_view tag,
                                       uint64_t user_id,
                                       std::string_view client_ip,
                                       uint32_t device_limit) const;

    [[nodiscard]] size_t OnlineDeviceCount(std::string_view tag,
                                           uint64_t user_id) const;

    [[nodiscard]] std::vector<OnlineDevice>
    GetOnlineDevices(std::string_view tag) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::anytls
