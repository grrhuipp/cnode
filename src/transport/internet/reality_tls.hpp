#pragma once

#include <memory>
#include <openssl/ssl.h>

namespace acpp {

[[nodiscard]] bool VerifyRealityClientHandshake(
    SSL* ssl,
    const std::shared_ptr<void>& app_state);

}  // namespace acpp