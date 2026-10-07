#pragma once

#include "../shadowsocks_protocol.hpp"

#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace acpp::proxy::shadowsocks::outbound {

// A complete, validated credential value. Preparation never drops a chain link
// or substitutes a different cipher; Worker handlers only consume this value.
class Credentials {
public:
    [[nodiscard]] static std::optional<Credentials> Prepare(
        std::string_view method, std::string_view password);

    [[nodiscard]] const ss::SsCipherInfo& Cipher() const noexcept { return cipher_; }
    [[nodiscard]] const ss::KeyBytes& MasterKey() const noexcept { return master_key_; }
    [[nodiscard]] std::span<const ss::KeyBytes> PskChain() const noexcept {
        return psk_chain_;
    }

private:
    Credentials(ss::SsCipherInfo cipher, ss::KeyBytes master_key,
                std::vector<ss::KeyBytes> psk_chain)
        : cipher_(cipher), master_key_(master_key), psk_chain_(std::move(psk_chain)) {}

    ss::SsCipherInfo cipher_;
    ss::KeyBytes master_key_;
    std::vector<ss::KeyBytes> psk_chain_;
};

}  // namespace acpp::proxy::shadowsocks::outbound
