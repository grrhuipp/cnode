#pragma once

#include "acppnode/proxy/shadowsocks/user_info.hpp"
#include "acppnode/proxy/anytls/user_info.hpp"
#include "acppnode/proxy/trojan/user_info.hpp"
#include "acppnode/proxy/vmess/account.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace acpp::proxyman::inbound {

// ============================================================================
// BuildRequest - prepared inbound handler construction input
// ============================================================================
struct BuildRequest {
    std::string tag;
    std::string protocol;
    std::string cipher_method;  // SS uses this; other protocols may ignore it.
    std::string anytls_padding_scheme;
};

struct RuntimeUser {
    int64_t user_id = 0;
    std::string email;
    std::string password;
    std::string uuid;
    uint64_t speed_limit = 0;
    uint32_t device_limit = 0;
};

struct UserSet {
    std::vector<::acpp::vmess::MemoryAccount> vmess_accounts;
    std::vector<::acpp::trojan::TrojanUserInfo> trojan_users;
    std::vector<::acpp::ss::SsUserInfo> ss_users;
    std::vector<::acpp::anytls::UserInfo> anytls_users;
};

}  // namespace acpp::proxyman::inbound
