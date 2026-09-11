#include "validator.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"

namespace acpp::vless {

struct Validator::Impl {
    UserOnlineTracker stats;
};

Validator::Validator()
    : impl_(std::make_unique<Impl>()) {
}

Validator::~Validator() = default;
Validator::Validator(Validator&&) noexcept = default;
Validator& Validator::operator=(Validator&&) noexcept = default;

std::shared_ptr<const proxyman::inbound::UserStore::VlessCredential>
Validator::FindUser(std::string_view tag,
                    const std::array<uint8_t, 16>& uuid_bytes) const {
    return proxyman::inbound::UserStore::FindVlessUser(tag, uuid_bytes);
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().vless_users;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(
        proxyman::inbound::UserProtocol::Vless, tag);
}

void Validator::OnUserConnected(std::string_view tag,
                                uint64_t user_id,
                                std::string_view client_ip) {
    impl_->stats.OnUserConnected(tag, user_id, client_ip);
}

void Validator::OnUserDisconnected(std::string_view tag,
                                   uint64_t user_id,
                                   std::string_view client_ip) {
    impl_->stats.OnUserDisconnected(tag, user_id, client_ip);
}

bool Validator::CanAcceptDevice(std::string_view tag,
                                uint64_t user_id,
                                std::string_view client_ip,
                                uint32_t device_limit) const {
    return impl_->stats.CanAcceptDevice(tag, user_id, client_ip, device_limit);
}

size_t Validator::OnlineDeviceCount(std::string_view tag,
                                    uint64_t user_id) const {
    return impl_->stats.OnlineDeviceCount(tag, user_id);
}

std::vector<OnlineDevice> Validator::GetOnlineDevices(std::string_view tag) const {
    return impl_->stats.GetOnlineDevices(tag);
}

}  // namespace acpp::vless
