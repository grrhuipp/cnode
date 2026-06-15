#pragma once

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/common/user_profile.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace acpp::proxyman::inbound {

struct UserSet;

// ============================================================================
// UserStore - process-wide inbound user RCU store
//
// Authentication users are immutable snapshots shared by all workers. Cold-path
// updates publish a new snapshot; hot-path validation only loads shared read-only
// views and performs protocol-specific matching without locks.
// ============================================================================
class UserStore final {
public:
    struct Array32Hash {
        [[nodiscard]] size_t operator()(const std::array<uint8_t, 32>& value) const noexcept;
    };

    using Profile = ::acpp::UserProfile;

    struct VmessCredential {
        std::string uuid;
        std::array<uint8_t, 16> uuid_bytes{};
        std::array<uint8_t, 16> cmd_key{};
        std::array<uint8_t, 16> auth_key{};
        std::array<uint8_t, 16> cached_auth_aes_key{};
        std::shared_ptr<const Profile> profile;
    };

    struct TrojanCredential {
        std::string password_hash;
        std::shared_ptr<const Profile> profile;
    };

    struct ShadowsocksCredential {
        std::string password;
        PreparedKeyBytes derived_key;
        PreparedKeyBytes identity_key;
        PreparedAeadCipher cipher_type = PreparedAeadCipher::AES_256_GCM;
        size_t key_size = 32;
        size_t salt_size = 32;
        std::shared_ptr<const Profile> profile;
    };

    struct AnyTlsCredential {
        std::array<uint8_t, 32> password_hash{};
        std::shared_ptr<const Profile> profile;
    };

    using VmessUserMap =
        std::unordered_map<std::string,
                           VmessCredential,
                           TransparentStringHash,
                           TransparentStringEq>;
    using TrojanUserMap =
        std::unordered_map<std::string,
                           TrojanCredential,
                           TransparentStringHash,
                           TransparentStringEq>;
    using ShadowsocksUserList = std::vector<ShadowsocksCredential>;
    using AnyTlsUserMap =
        std::unordered_map<std::array<uint8_t, 32>,
                           AnyTlsCredential,
                           Array32Hash>;

    struct VmessUsersView {
        std::shared_ptr<const VmessUserMap> users;

        [[nodiscard]] bool empty() const noexcept { return !users || users->empty(); }
        [[nodiscard]] size_t size() const noexcept { return users ? users->size() : 0; }
        [[nodiscard]] std::shared_ptr<const VmessCredential>
        Share(const VmessCredential& user) const noexcept {
            return users
                ? std::shared_ptr<const VmessCredential>(users, &user)
                : std::shared_ptr<const VmessCredential>{};
        }
    };

    struct ShadowsocksUsersView {
        std::shared_ptr<const ShadowsocksUserList> users;

        [[nodiscard]] bool empty() const noexcept { return !users || users->empty(); }
        [[nodiscard]] size_t size() const noexcept { return users ? users->size() : 0; }
        [[nodiscard]] const ShadowsocksCredential& operator[](size_t index) const noexcept {
            return (*users)[index];
        }
        [[nodiscard]] std::shared_ptr<const ShadowsocksCredential>
        Share(const ShadowsocksCredential& user) const noexcept {
            return users
                ? std::shared_ptr<const ShadowsocksCredential>(users, &user)
                : std::shared_ptr<const ShadowsocksCredential>{};
        }
    };

    struct Stats {
        size_t vmess_accounts = 0;
        size_t trojan_users = 0;
        size_t shadowsocks_users = 0;
        size_t anytls_users = 0;

        [[nodiscard]] size_t TotalUsers() const noexcept {
            return vmess_accounts + trojan_users + shadowsocks_users + anytls_users;
        }
    };

    static void ApplyUsers(std::string_view protocol,
                           std::string_view tag,
                           const UserSet& users);
    static void AddUsers(std::string_view protocol,
                         std::string_view tag,
                         const UserSet& users);
    static void RemoveUsers(std::string_view protocol,
                            std::string_view tag,
                            const UserSet& users);
    static void ClearUsers(std::string_view protocol,
                           std::string_view tag);
    static void ClearProtocol(std::string_view protocol);
    static void ClearAll();

    [[nodiscard]] static VmessUsersView VmessUsers(std::string_view tag);
    [[nodiscard]] static std::shared_ptr<const TrojanCredential>
    FindTrojanUser(std::string_view tag, std::string_view password_hash);
    [[nodiscard]] static bool HasTrojanUser(std::string_view tag,
                                            std::string_view password_hash);
    [[nodiscard]] static ShadowsocksUsersView ShadowsocksUsers(std::string_view tag);
    [[nodiscard]] static std::shared_ptr<const ShadowsocksCredential>
    FindShadowsocksUserById(std::string_view tag, int64_t user_id);
    [[nodiscard]] static std::shared_ptr<const AnyTlsCredential>
    FindAnyTlsUser(std::string_view tag,
                   const std::array<uint8_t, 32>& password_hash);

    [[nodiscard]] static Stats GetStats();
    [[nodiscard]] static size_t SizeForProtocolTag(std::string_view protocol,
                                                   std::string_view tag);
};

}  // namespace acpp::proxyman::inbound
