#pragma once

#include "acppnode/common/asio_types.hpp"

#include <cstdint>
#include <string>

namespace acpp::features::policy {

// Runtime-local request admission policy. Implementations may record policy
// hits, but Dispatcher only observes the allow/block result.
class RequestPolicy {
public:
    virtual ~RequestPolicy() noexcept = default;

    [[nodiscard]] virtual net::awaitable<bool> Blocked(
        std::string inbound_tag,
        int64_t user_id,
        std::string user_email,
        std::string destination) = 0;
};

}  // namespace acpp::features::policy
