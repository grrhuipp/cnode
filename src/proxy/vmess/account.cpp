#include "acppnode/proxy/vmess/account.hpp"
#include "vmess_crypto.hpp"
#include "vmess_request.hpp"

#include <cstring>

namespace acpp::vmess {

namespace {
static const char* VMESS_MAGIC = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
static constexpr size_t kVmessMagicLen = 36;
}  // namespace

std::optional<MemoryAccount> MemoryAccount::FromUUID(
    const std::string& uuid_str,
    int64_t user_id,
    const std::string& email,
    uint64_t speed_limit,
    uint32_t device_limit) {
    auto uuid_bytes = ParseUUID(uuid_str);
    if (!uuid_bytes) {
        return std::nullopt;
    }

    MemoryAccount account;
    account.uuid = uuid_str;
    account.uuid_bytes = *uuid_bytes;
    account.profile.user_id = user_id;
    account.profile.email = email;
    account.profile.speed_limit = speed_limit;
    account.profile.device_limit = device_limit;

    std::array<uint8_t, 16 + kVmessMagicLen> key_material{};
    std::memcpy(key_material.data(), account.uuid_bytes.data(), account.uuid_bytes.size());
    std::memcpy(key_material.data() + account.uuid_bytes.size(), VMESS_MAGIC, kVmessMagicLen);
    account.cmd_key = MD5Hash(key_material.data(), key_material.size());

    const std::array<std::string_view, 1> auth_key_path{
        KDFSalt::AUTH_ID_ENCRYPTION_KEY
    };
    account.auth_key = KDF16(account.cmd_key.data(), 16, auth_key_path);
    account.cached_auth_aes_key.InitDecryptKey(account.auth_key.data());

    return account;
}

}  // namespace acpp::vmess
