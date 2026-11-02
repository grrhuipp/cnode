#pragma once

#include "acppnode/transport/internet/tls_config.hpp"

#include <string>
#include <string_view>

namespace acpp {

struct RealityConfig;

namespace transport::internet {

[[nodiscard]] std::string MakeTlsContextCacheKey(
    std::string_view role,
    const TlsConfig& config);
[[nodiscard]] std::string MakeRealityServerContextCacheKey(
    const RealityConfig& reality,
    const TlsConfig& tls_config);
[[nodiscard]] std::string MakeRealityClientContextCacheKey(
    const RealityConfig& reality,
    const TlsConfig& tls_config);

}  // namespace transport::internet
}  // namespace acpp
