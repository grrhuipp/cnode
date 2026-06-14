#include "acppnode/proxy/anytls/validator.hpp"

#include <openssl/evp.h>

namespace acpp::anytls {

std::array<uint8_t, 32> PasswordHash(std::string_view password) noexcept {
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 0;
    EVP_Digest(password.data(), password.size(), out.data(), &out_len, EVP_sha256(), nullptr);
    return out;
}

size_t Validator::Hash::operator()(const std::array<uint8_t, 32>& value) const noexcept {
    size_t out = 1469598103934665603ull;
    for (uint8_t byte : value) {
        out ^= byte;
        out *= 1099511628211ull;
    }
    return out;
}

void Validator::ApplyUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    UserMap map;
    map.reserve(users.size());
    for (const auto& user : users) {
        map[user.password_hash] = user;
    }
    users_[std::string(tag)] = std::move(map);
}

void Validator::AddUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    auto& map = users_[std::string(tag)];
    map.reserve(map.size() + users.size());
    for (const auto& user : users) {
        map[user.password_hash] = user;
    }
}

void Validator::RemoveUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    auto it = users_.find(std::string(tag));
    if (it == users_.end()) {
        return;
    }
    for (const auto& user : users) {
        it->second.erase(user.password_hash);
    }
    if (it->second.empty()) {
        users_.erase(it);
    }
}

void Validator::ClearUsers(std::string_view tag) {
    users_.erase(std::string(tag));
}

std::optional<UserInfo> Validator::Validate(
    std::string_view tag,
    const std::array<uint8_t, 32>& password_hash) const {
    auto tag_it = users_.find(std::string(tag));
    if (tag_it == users_.end()) {
        return std::nullopt;
    }
    auto user_it = tag_it->second.find(password_hash);
    if (user_it == tag_it->second.end()) {
        return std::nullopt;
    }
    return user_it->second;
}

size_t Validator::Size() const noexcept {
    size_t total = 0;
    for (const auto& [tag, users] : users_) {
        (void)tag;
        total += users.size();
    }
    return total;
}

}  // namespace acpp::anytls
