#include "anytls_outbound_settings.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"
#include "../credentials.hpp"

#include "acppnode/infra/json_field.hpp"

#include <chrono>
#include <format>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace acpp::proxy::anytls::outbound {

namespace {

tl::expected<std::chrono::seconds, std::string> ReadPositiveSeconds(
    const json::object& source,
    std::string_view key,
    std::chrono::seconds fallback) {
    auto parsed = ParseJsonUint64(source, key);
    if (!parsed) return tl::unexpected(std::move(parsed.error()));
    if (!*parsed) return fallback;
    if (**parsed == 0) {
        return tl::unexpected(std::format(
            "{} must be positive", key));
    }
    using Rep = std::chrono::seconds::rep;
    if (**parsed > static_cast<uint64_t>(std::numeric_limits<Rep>::max())) {
        return tl::unexpected(std::format(
            "{} exceeds the seconds range", key));
    }
    const auto clock_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::duration::max()).count();
    if (**parsed > static_cast<uint64_t>(clock_seconds)) {
        return tl::unexpected(std::format(
            "{} exceeds the steady clock range", key));
    }
    return std::chrono::seconds(static_cast<Rep>(**parsed));
}

}  // namespace

tl::expected<Settings, std::string> ParseSettings(const json::object& source) {
    Settings result;

    // A present field of the wrong type is a configuration error, never an
    // implicit default.
    auto address = ParseJsonString(source, "address");
    if (!address) return tl::unexpected(std::move(address.error()));
    result.address = std::move(*address).value_or(std::string{});

    const auto port = ReadJsonPort(source, "port");
    if (port.Invalid()) {
        return tl::unexpected("AnyTLS server port must be between 1 and 65535");
    }
    if (port.Valid()) result.port = port.value;

    auto source_password = ParseJsonString(source, "password");
    if (!source_password) return tl::unexpected(std::move(source_password.error()));
    auto source_key = ParseJsonString(source, "key");
    if (!source_key) return tl::unexpected(std::move(source_key.error()));
    auto password = std::move(*source_password).value_or(std::string{});
    if (password.empty()) password = std::move(*source_key).value_or(std::string{});

    auto check_interval = ReadPositiveSeconds(
        source,
        "idleSessionCheckInterval",
        result.idle_session_check_interval);
    if (!check_interval) {
        return tl::unexpected(std::move(check_interval.error()));
    }
    result.idle_session_check_interval = *check_interval;

    auto idle_timeout = ReadPositiveSeconds(
        source,
        "idleSessionTimeout",
        result.idle_session_timeout);
    if (!idle_timeout) return tl::unexpected(std::move(idle_timeout.error()));
    result.idle_session_timeout = *idle_timeout;

    auto min_idle = ParseJsonUint64(
        source, "minIdleSession", std::numeric_limits<size_t>::max());
    if (!min_idle) return tl::unexpected(std::move(min_idle.error()));
    if (*min_idle) result.min_idle_sessions = static_cast<size_t>(**min_idle);

    if (result.address.empty()) return tl::unexpected("AnyTLS address is required");
    result.literal_address = iputil::ParseLiteral(result.address);
    if (!result.literal_address && !domain::IsValidDnsHostname(
            result.address, domain::TrailingDotPolicy::Allow)) {
        return tl::unexpected("AnyTLS address must be an IP literal or DNS hostname");
    }
    if (password.empty()) return tl::unexpected("AnyTLS password is required");
    if (result.port == 0) return tl::unexpected("AnyTLS port is required");
    result.password_hash = acpp::anytls::PasswordHash(password);
    return result;
}

}  // namespace acpp::proxy::anytls::outbound
