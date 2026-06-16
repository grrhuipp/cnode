#include "acppnode/proxy/vless/validator.hpp"

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/core/constants.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace acpp::vless {

namespace {

[[nodiscard]] int HexValue(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

[[nodiscard]] std::array<uint8_t, 16>
MapCustomIdToUuidV5(std::string_view id) noexcept {
    std::array<uint8_t, 16 + 30> input{};
    std::memcpy(input.data() + 16, id.data(), id.size());

    std::array<uint8_t, SHA_DIGEST_LENGTH> digest{};
    SHA1(input.data(), 16 + id.size(), digest.data());

    std::array<uint8_t, 16> out{};
    std::copy_n(digest.begin(), out.size(), out.begin());
    out[6] = static_cast<uint8_t>((out[6] & 0x0f) | 0x50);
    out[8] = static_cast<uint8_t>((out[8] & 0x3f) | 0x80);
    return out;
}

std::vector<proxyman::inbound::PreparedVlessUser>
ToPreparedUsers(const std::vector<UserInfo>& users) {
    std::vector<proxyman::inbound::PreparedVlessUser> prepared;
    prepared.reserve(users.size());
    for (const auto& user : users) {
        prepared.push_back(proxyman::inbound::PreparedVlessUser{
            .uuid = user.uuid,
            .uuid_bytes = user.uuid_bytes,
            .flow = user.flow,
            .profile = user.profile,
        });
    }
    return prepared;
}

}  // namespace

std::optional<std::array<uint8_t, 16>>
ParseUuidBytes(std::string_view uuid) noexcept {
    std::array<uint8_t, 16> out{};
    size_t nibble_index = 0;
    bool uuid_candidate = true;

    for (char ch : uuid) {
        if (ch == '-') {
            continue;
        }
        const int value = HexValue(ch);
        if (value < 0 || nibble_index >= 32) {
            uuid_candidate = false;
            break;
        }
        const size_t byte_index = nibble_index / 2;
        if ((nibble_index & 1) == 0) {
            out[byte_index] = static_cast<uint8_t>(value << 4);
        } else {
            out[byte_index] |= static_cast<uint8_t>(value);
        }
        ++nibble_index;
    }

    if (uuid_candidate && nibble_index == 32) {
        return out;
    }
    if (!uuid.empty() && uuid.size() <= 30) {
        return MapCustomIdToUuidV5(uuid);
    }
    return std::nullopt;
}

std::string NormalizeFlow(std::string_view flow) {
    std::string out(flow);
    std::ranges::transform(out, out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

struct Validator::Impl {
    UserOnlineTracker stats;
};

Validator::Validator()
    : impl_(std::make_unique<Impl>()) {
}

Validator::~Validator() = default;
Validator::Validator(Validator&&) noexcept = default;
Validator& Validator::operator=(Validator&&) noexcept = default;

void Validator::ApplyUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.vless_users = ToPreparedUsers(users);
    proxyman::inbound::UserStore::ApplyUsers(constants::protocol::kVless, tag, set);
}

void Validator::AddUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.vless_users = ToPreparedUsers(users);
    proxyman::inbound::UserStore::AddUsers(constants::protocol::kVless, tag, set);
}

void Validator::RemoveUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.vless_users = ToPreparedUsers(users);
    proxyman::inbound::UserStore::RemoveUsers(constants::protocol::kVless, tag, set);
}

void Validator::ClearUsers(std::string_view tag) {
    proxyman::inbound::UserStore::ClearUsers(constants::protocol::kVless, tag);
}

std::shared_ptr<const proxyman::inbound::UserStore::VlessCredential>
Validator::FindUser(std::string_view tag,
                    const std::array<uint8_t, 16>& uuid_bytes) const {
    return proxyman::inbound::UserStore::FindVlessUser(tag, uuid_bytes);
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().vless_users;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(constants::protocol::kVless, tag);
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
