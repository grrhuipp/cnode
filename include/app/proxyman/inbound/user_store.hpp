#pragma once

#include "common/string_hash.hpp"
#include "common/target_address.hpp"
#include <openssl/mem.h>

#include <openssl/aes.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>
namespace proxyman::inbound {

// ============================================================================
// BuildRequest - prepared inbound handler construction input
// ============================================================================
class ProtocolSettings {
public:
    virtual ~ProtocolSettings() noexcept = default;
};

struct BuildRequest {
    std::string tag;
    std::string protocol;
    // The concrete type is private to the registered protocol implementation.
    // Generic runtime layers only carry the immutable prepared value.
    std::shared_ptr<const ProtocolSettings> settings;
};

struct PreparedKeyBytes {
    static constexpr size_t kMaxSize = 32;

    std::array<uint8_t, kMaxSize> bytes{};
    size_t size = 0;

    PreparedKeyBytes() = default;
    PreparedKeyBytes(const PreparedKeyBytes&) = default;
    PreparedKeyBytes& operator=(const PreparedKeyBytes&) = default;
    PreparedKeyBytes(PreparedKeyBytes&&) noexcept = default;
    PreparedKeyBytes& operator=(PreparedKeyBytes&&) noexcept = default;
    ~PreparedKeyBytes() noexcept {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }

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

struct PreparedVmessUser {
    std::array<uint8_t, 16> uuid_bytes{};
    std::array<uint8_t, 16> cmd_key{};
    std::array<uint8_t, 16> auth_key{};
    ::UserProfile profile;

    ~PreparedVmessUser() noexcept {
        OPENSSL_cleanse(uuid_bytes.data(), uuid_bytes.size());
        OPENSSL_cleanse(cmd_key.data(), cmd_key.size());
        OPENSSL_cleanse(auth_key.data(), auth_key.size());
    }
};

struct PreparedVlessUser {
    std::array<uint8_t, 16> uuid_bytes{};
    std::string flow;
    ::UserProfile profile;
};

struct PreparedTrojanUser {
    std::string password_hash;
    ::UserProfile profile;
};

struct PreparedShadowsocksUser {
    PreparedKeyBytes derived_key;
    PreparedKeyBytes identity_key;
    std::array<uint8_t, 16> psk_hash{};
    ::UserProfile profile;
};

struct PreparedAnyTlsUser {
    std::array<uint8_t, 32> password_hash{};
    ::UserProfile profile;
};

struct PreparedHysteriaUser {
    std::array<uint8_t, 32> credential_hash{};
    ::UserProfile profile;
};

using PreparedVmessUsers = std::vector<PreparedVmessUser>;
using PreparedVlessUsers = std::vector<PreparedVlessUser>;
using PreparedTrojanUsers = std::vector<PreparedTrojanUser>;
using PreparedShadowsocksUsers = std::vector<PreparedShadowsocksUser>;
using PreparedAnyTlsUsers = std::vector<PreparedAnyTlsUser>;
using PreparedHysteriaUsers = std::vector<PreparedHysteriaUser>;

// A prepared user payload belongs to exactly one protocol. Keeping the protocol
// implicit in the variant makes contradictory protocol + payload pairs
// unrepresentable at the UserStore boundary.
using UserSet = std::variant<
    PreparedVmessUsers,
    PreparedVlessUsers,
    PreparedTrojanUsers,
    PreparedShadowsocksUsers,
    PreparedAnyTlsUsers,
    PreparedHysteriaUsers>;

enum class UserProtocol : uint8_t {
    Vmess,
    Vless,
    Trojan,
    Shadowsocks,
    AnyTls,
    Hysteria,
};

template <typename Users>
inline constexpr bool kHasKeyedInboundCredential =
    std::is_same_v<Users, PreparedVlessUsers> ||
    std::is_same_v<Users, PreparedTrojanUsers> ||
    std::is_same_v<Users, PreparedAnyTlsUsers> ||
    std::is_same_v<Users, PreparedHysteriaUsers>;

[[nodiscard]] inline UserProtocol UserProtocolOf(const UserSet& users) noexcept {
    return std::visit([](const auto& value) noexcept {
        using Users = std::remove_cvref_t<decltype(value)>;
        if constexpr (std::is_same_v<Users, PreparedVmessUsers>) {
            return UserProtocol::Vmess;
        } else if constexpr (std::is_same_v<Users, PreparedVlessUsers>) {
            return UserProtocol::Vless;
        } else if constexpr (std::is_same_v<Users, PreparedTrojanUsers>) {
            return UserProtocol::Trojan;
        } else if constexpr (std::is_same_v<Users, PreparedShadowsocksUsers>) {
            return UserProtocol::Shadowsocks;
        } else if constexpr (std::is_same_v<Users, PreparedAnyTlsUsers>) {
            return UserProtocol::AnyTls;
        } else {
            static_assert(std::is_same_v<Users, PreparedHysteriaUsers>);
            return UserProtocol::Hysteria;
        }
    }, users);
}

[[nodiscard]] inline bool UserSetEmpty(const UserSet& users) noexcept {
    return std::visit([](const auto& value) { return value.empty(); }, users);
}

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
            OPENSSL_cleanse(uuid_bytes.data(), uuid_bytes.size());
            OPENSSL_cleanse(cmd_key.data(), cmd_key.size());
            OPENSSL_cleanse(&auth_id_key, sizeof(auth_id_key));
        }
    };

    // Keyed credentials keep only what authentication reads afterwards; the
    // credential key itself lives once, as the owning map's key.
    struct ProfileCredential {
        Profile profile;
    };

    struct VlessCredential {
        std::string flow;
        Profile profile;
    };

    using TrojanCredential = ProfileCredential;
    using ShadowsocksCredential = PreparedShadowsocksUser;
    using AnyTlsCredential = ProfileCredential;
    using HysteriaCredential = ProfileCredential;

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

    struct ShadowsocksUsersView {
        // Identity-enabled vectors are ordered by key length, key bytes, then
        // PSK hash; others retain input order. Indices are snapshot-local hints.
        std::shared_ptr<const ShadowsocksUserList> users;

        [[nodiscard]] bool empty() const noexcept { return !users || users->empty(); }
        [[nodiscard]] size_t size() const noexcept { return users ? users->size() : 0; }
        [[nodiscard]] const ShadowsocksCredential& operator[](size_t index) const noexcept {
            return (*users)[index];
        }
        // Queries require a canonical snapshot and a valid index/range within
        // one identity-key group. Hash lookup is not authentication.
        [[nodiscard]] size_t IdentityGroupEnd(size_t begin) const noexcept;
        [[nodiscard]] size_t IdentityHashLowerBound(
            size_t begin, size_t end, const std::array<uint8_t, 16>& hash) const noexcept;
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
    static void ClearWorkerView() noexcept;
    [[nodiscard]] static uint64_t WorkerViewRevision() noexcept;
    // Shared by Workers using the same protocol/tag credential publication;
    // negative authentication caches must not outlive that publication.
    [[nodiscard]] static uint64_t CredentialRevision(
        UserProtocol protocol, std::string_view tag) noexcept;

    struct UserUpdate {
        std::string_view tag;
        std::reference_wrapper<const UserSet> users;
    };

    [[nodiscard]] static VmessUsersView VmessUsers(std::string_view tag);
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
