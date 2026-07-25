#include "validator.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"

namespace acpp::anytls {

struct Validator::Impl {
    UserOnlineTracker stats;
};

Validator::Validator()
    : impl_(std::make_unique<Impl>()) {}

Validator::~Validator() = default;
Validator::Validator(Validator&&) noexcept = default;
Validator& Validator::operator=(Validator&&) noexcept = default;

std::shared_ptr<const proxyman::inbound::UserStore::AnyTlsCredential> Validator::Validate(
    std::string_view tag,
    const std::array<uint8_t, 32>& password_hash) const {
    return proxyman::inbound::UserStore::FindAnyTlsUser(tag, password_hash);
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().anytls_users;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(
        proxyman::inbound::UserProtocol::AnyTls, tag);
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

}  // namespace acpp::anytls
