#pragma once

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct OnlineDevice;
}  // namespace acpp

namespace acpp::vless {

// Parses a UUID string, or maps a 1-30 byte VLESS custom id to UUIDv5.
[[nodiscard]] std::optional<std::array<uint8_t, 16>>
ParseUuidBytes(std::string_view uuid) noexcept;

[[nodiscard]] std::string NormalizeFlow(std::string_view flow);

class Validator {
public:
    Validator();
    ~Validator();

    Validator(const Validator&) = delete;
    Validator& operator=(const Validator&) = delete;
    Validator(Validator&&) noexcept;
    Validator& operator=(Validator&&) noexcept;

    std::shared_ptr<const proxyman::inbound::UserStore::VlessCredential>
    FindUser(std::string_view tag,
             const std::array<uint8_t, 16>& uuid_bytes) const;

    size_t Size() const;
    size_t SizeForTag(std::string_view tag) const;

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

}  // namespace acpp::vless
