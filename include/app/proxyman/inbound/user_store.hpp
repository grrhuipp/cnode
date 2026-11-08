#pragma once

#include "app/proxyman/inbound/prepared_config.hpp"
#include "common/string_hash.hpp"
#include "common/user_profile.hpp"

#include <openssl/aes.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace proxyman::inbound {

// One immutable process-wide user table, published only on the cold path.
// Each Worker installs an independent lease; hot aliases share only that
// Worker's control block and keep retired credentials alive for active sessions.
class UserStore final {
public:
    struct Array16Hash {
        [[nodiscard]] size_t operator()(const std::array<uint8_t, 16>& value) const noexcept;
    };

    struct Array32Hash {
        [[nodiscard]] size_t operator()(const std::array<uint8_t, 32>& value) const noexcept;
    };

    using Profile = ::UserProfile;

    struct VmessCredential {
        std::array<uint8_t, 16> uuid_bytes{};
        std::array<uint8_t, 16> cmd_key{};
        // AES-128 decrypt schedule of the AuthID key, expanded once when the
        // snapshot is built; handshakes never rebuild it per candidate user.
        AES_KEY auth_id_key{};
        Profile profile;

        ~VmessCredential() noexcept {
            ::SecureZeroMemory(uuid_bytes.data(), uuid_bytes.size());
            ::SecureZeroMemory(cmd_key.data(), cmd_key.size());
            ::SecureZeroMemory(&auth_id_key, sizeof(auth_id_key));
        }
    };

    struct TrojanCredential {
        Profile profile;
    };

    struct VlessCredential {
        std::array<uint8_t, 16> uuid_bytes{};
        std::string flow;
        Profile profile;
    };

    struct ShadowsocksCredential {
        PreparedKeyBytes derived_key;
        PreparedKeyBytes identity_key;
        std::array<uint8_t, 16> psk_hash{};
        size_t key_size = 32;
        size_t salt_size = 32;
        Profile profile;
    };

    struct AnyTlsCredential {
        std::array<uint8_t, 32> password_hash{};
        Profile profile;
    };

    struct HysteriaCredential {
        std::array<uint8_t, 32> credential_hash{};
        Profile profile;
    };

    using VmessUserMap = std::vector<VmessCredential>;
    using TrojanUserMap =
        std::unordered_map<std::string,
                           TrojanCredential,
                           TransparentStringHash,
                           TransparentStringEq>;
    using VlessUserMap =
        std::unordered_map<std::array<uint8_t, 16>,
                           VlessCredential,
                           Array16Hash>;
    using ShadowsocksUserList = std::vector<ShadowsocksCredential>;
    using AnyTlsUserMap =
        std::unordered_map<std::array<uint8_t, 32>,
                           AnyTlsCredential,
                           Array32Hash>;
    using HysteriaUserMap =
        std::unordered_map<std::array<uint8_t, 32>,
                           HysteriaCredential,
                           Array32Hash>;

    struct VmessUsersView {
        std::shared_ptr<const VmessUserMap> users;

        [[nodiscard]] bool empty() const noexcept { return !users || users->empty(); }
        [[nodiscard]] size_t size() const noexcept { return users ? users->size() : 0; }
        [[nodiscard]] const VmessCredential& operator[](size_t index) const noexcept {
            return (*users)[index];
        }
        [[nodiscard]] std::shared_ptr<const VmessCredential>
        Share(const VmessCredential& user) const noexcept {
            return users
                ? std::shared_ptr<const VmessCredential>(users, &user)
                : std::shared_ptr<const VmessCredential>{};
        }
    };

    struct VlessUsersView {
        std::shared_ptr<const VlessUserMap> users;

        [[nodiscard]] bool empty() const noexcept { return !users || users->empty(); }
        [[nodiscard]] size_t size() const noexcept { return users ? users->size() : 0; }
        [[nodiscard]] std::shared_ptr<const VlessCredential>
        Share(const VlessCredential& user) const noexcept {
            return users
                ? std::shared_ptr<const VlessCredential>(users, &user)
                : std::shared_ptr<const VlessCredential>{};
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

    struct Snapshot;
    using PublishedSnapshot = std::shared_ptr<const Snapshot>;
    struct WorkerLease;
    using WorkerView = std::shared_ptr<const WorkerLease>;
    struct UserUpdate;

    // Control-plane gate must serialize prepare/install/commit or rollback.
    // Preparation never mutates global or Worker state; callers allocate every
    // forward and rollback lease before starting bounded Worker operations.
    [[nodiscard]] static PublishedSnapshot CaptureSnapshot();
    [[nodiscard]] static PublishedSnapshot PrepareUsers(
        std::span<const UserUpdate> updates);
    [[nodiscard]] static PublishedSnapshot PrepareUsers(
        std::string_view tag, const UserSet& users);
    [[nodiscard]] static PublishedSnapshot PrepareClearUsers(
        UserProtocol protocol, std::string_view tag);
    static void CommitSnapshot(PublishedSnapshot snapshot) noexcept;
    // Install/Clear execute only on the destination Worker's thread.
    [[nodiscard]] static WorkerView PrepareWorkerView(PublishedSnapshot snapshot);
    static void InstallWorkerView(WorkerView view) noexcept;
    // Domain callback entry/exit swaps a lease without dropping the suspended
    // Worker's view. Credential aliases retain their immutable snapshot.
    [[nodiscard]] static WorkerView ExchangeWorkerView(WorkerView view) noexcept;
    [[nodiscard]] static WorkerView CaptureWorkerView() noexcept;
    static void ClearWorkerView() noexcept;
    [[nodiscard]] static uint64_t WorkerViewRevision() noexcept;
    // Shared by Workers using the same protocol/tag credential publication;
    // negative authentication caches must not outlive that publication.
    [[nodiscard]] static uint64_t CredentialRevision(
        UserProtocol protocol, std::string_view tag) noexcept;

    struct UserUpdate {
        std::string_view tag;
        const UserSet& users;
    };

    [[nodiscard]] static VmessUsersView VmessUsers(std::string_view tag);
    [[nodiscard]] static VlessUsersView VlessUsers(std::string_view tag);
    [[nodiscard]] static std::shared_ptr<const VlessCredential>
    FindVlessUser(std::string_view tag,
                  const std::array<uint8_t, 16>& uuid_bytes);
    [[nodiscard]] static std::shared_ptr<const TrojanCredential>
    FindTrojanUser(std::string_view tag, std::string_view password_hash);
    [[nodiscard]] static ShadowsocksUsersView ShadowsocksUsers(std::string_view tag);
    [[nodiscard]] static std::shared_ptr<const AnyTlsCredential>
    FindAnyTlsUser(std::string_view tag,
                   const std::array<uint8_t, 32>& password_hash);
    [[nodiscard]] static std::shared_ptr<const HysteriaCredential>
    FindHysteriaUser(std::string_view tag,
                     const std::array<uint8_t, 32>& credential_hash);

    [[nodiscard]] static size_t TotalUsers();
};

}  // namespace proxyman::inbound
