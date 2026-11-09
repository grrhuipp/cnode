#pragma once

// ============================================================================
// validator.hpp — VMess AuthID 查找与防重放准入
// ============================================================================

#include "app/proxyman/inbound/user_store.hpp"
#include "common/asio_types.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string_view>

namespace vmess {

// 通过 AuthID 查找用户，限定 tag（优化：O(N_tag) 而非 O(N_total)）
[[nodiscard]] std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>
FindByAuthIDForTag(std::string_view tag,
                   const uint8_t* auth_id,
                   int64_t* out_timestamp = nullptr);

// Records AEAD request body key/IV for replay protection.
// Returns false if the same user/key/IV tuple is still inside the replay window.
[[nodiscard]] net::awaitable<bool> RegisterSessionIfNew(
    const proxyman::inbound::UserStore::VmessCredential& user,
    const std::array<uint8_t, 16>& body_key,
    const std::array<uint8_t, 16>& body_iv);

}  // namespace vmess
