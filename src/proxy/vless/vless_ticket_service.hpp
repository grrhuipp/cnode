#pragma once

#include "vless_encryption_runtime.hpp"
#include <memory>
#include <string>
#include <string_view>

namespace vless {

// Directory entries carry only routing/lifetime metadata. PFS secrets and the
// mutable replay set are accessed exclusively on the ticket owner's domain.

[[nodiscard]] net::awaitable<bool> AuthenticateVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string_view inbound_tag,
    VlessEncryptionIssuedTicket ticket,
    std::array<uint8_t, 16> identity);

[[nodiscard]] net::awaitable<std::optional<VlessEncryptionServerTicketStore::ResumedSession>>
LookupVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string_view inbound_tag,
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket,
    VlessEncryptionNfsKey nfs_key);

} // namespace vless
