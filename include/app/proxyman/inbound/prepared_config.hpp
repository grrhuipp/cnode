#pragma once

#include "common/user_profile.hpp"

#include "common/unsafe.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <type_traits>
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

    ~PreparedKeyBytes() noexcept {
        ::SecureZeroMemory(bytes.data(), bytes.size());
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
    std::string uuid;
    std::array<uint8_t, 16> uuid_bytes{};
    std::array<uint8_t, 16> cmd_key{};
    std::array<uint8_t, 16> auth_key{};
    ::UserProfile profile;

    ~PreparedVmessUser() noexcept {
        ::SecureZeroMemory(uuid_bytes.data(), uuid_bytes.size());
        ::SecureZeroMemory(cmd_key.data(), cmd_key.size());
        ::SecureZeroMemory(auth_key.data(), auth_key.size());
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
    size_t key_size = 32;
    size_t salt_size = 32;
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

}  // namespace proxyman::inbound
