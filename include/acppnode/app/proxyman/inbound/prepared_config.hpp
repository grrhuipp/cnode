#pragma once

#include "acppnode/common/user_profile.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstddef>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace acpp::proxyman::inbound {

// ============================================================================
// BuildRequest - prepared inbound handler construction input
// ============================================================================
struct BuildRequest {
    std::string tag;
    std::string protocol;
    std::string cipher_method;  // SS uses this; other protocols may ignore it.
    std::string ss_identity_password;
    std::string anytls_padding_scheme;
    std::string vless_decryption;
};

struct RuntimeUser {
    int64_t user_id = 0;
    std::string email;
    std::string password;
    std::string uuid;
    std::string flow;
    uint64_t speed_limit = 0;
    uint32_t device_limit = 0;
};

struct PreparedKeyBytes {
    static constexpr size_t kMaxSize = 32;

    std::array<uint8_t, kMaxSize> bytes{};
    size_t size = 0;

    [[nodiscard]] const uint8_t* data() const noexcept { return bytes.data(); }
    [[nodiscard]] uint8_t* data() noexcept { return bytes.data(); }
    [[nodiscard]] bool empty() const noexcept { return size == 0; }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept {
        return {bytes.data(), size};
    }

    bool assign(std::span<const uint8_t> src) noexcept {
        if (src.size() > bytes.size()) {
            size = 0;
            return false;
        }
        std::copy(src.begin(), src.end(), bytes.begin());
        size = src.size();
        return true;
    }
};

enum class PreparedAeadCipher : uint8_t {
    AES_128_GCM = 0,
    AES_256_GCM = 1,
    CHACHA20_POLY1305 = 2,
    AES_128_GCM_2022 = 3,
    AES_256_GCM_2022 = 4,
    CHACHA20_POLY1305_2022 = 5,
};

struct PreparedVmessUser {
    std::string uuid;
    std::array<uint8_t, 16> uuid_bytes{};
    std::array<uint8_t, 16> cmd_key{};
    std::array<uint8_t, 16> auth_key{};
    std::array<uint8_t, 16> cached_auth_aes_key{};
    ::acpp::UserProfile profile;
};

struct PreparedVlessUser {
    std::string uuid;
    std::array<uint8_t, 16> uuid_bytes{};
    std::string flow;
    ::acpp::UserProfile profile;
};

struct PreparedTrojanUser {
    std::string password_hash;
    ::acpp::UserProfile profile;
};

struct PreparedShadowsocksUser {
    std::string password;
    PreparedKeyBytes derived_key;
    PreparedKeyBytes identity_key;
    PreparedAeadCipher cipher_type = PreparedAeadCipher::AES_256_GCM;
    size_t key_size = 32;
    size_t salt_size = 32;
    ::acpp::UserProfile profile;
};

struct PreparedAnyTlsUser {
    std::array<uint8_t, 32> password_hash{};
    ::acpp::UserProfile profile;
};

using PreparedVmessUsers = std::vector<PreparedVmessUser>;
using PreparedVlessUsers = std::vector<PreparedVlessUser>;
using PreparedTrojanUsers = std::vector<PreparedTrojanUser>;
using PreparedShadowsocksUsers = std::vector<PreparedShadowsocksUser>;
using PreparedAnyTlsUsers = std::vector<PreparedAnyTlsUser>;

// A prepared user payload belongs to exactly one protocol. Keeping the protocol
// implicit in the variant makes contradictory protocol + payload pairs
// unrepresentable at the UserStore boundary.
using UserSet = std::variant<
    PreparedVmessUsers,
    PreparedVlessUsers,
    PreparedTrojanUsers,
    PreparedShadowsocksUsers,
    PreparedAnyTlsUsers>;

[[nodiscard]] inline bool UserSetEmpty(const UserSet& users) noexcept {
    return std::visit([](const auto& value) { return value.empty(); }, users);
}

}  // namespace acpp::proxyman::inbound
