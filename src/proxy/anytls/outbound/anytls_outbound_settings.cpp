#include "anytls_outbound_settings.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"
#include "../credentials.hpp"

#include "acppnode/infra/json_port.hpp"

#include <chrono>
#include <format>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace acpp::proxy::anytls::outbound {

namespace {

std::expected<std::optional<uint64_t>, std::string> ReadOptionalUnsigned(
    const json::object& source,
    std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<uint64_t>{};
    }

    if (raw->is_int64()) {
        const int64_t signed_value = raw->as_int64();
        if (signed_value < 0) {
            return std::unexpected(std::format(
                "{} must not be negative", key));
        }
        return std::optional<uint64_t>{static_cast<uint64_t>(signed_value)};
    }
    if (raw->is_uint64()) {
        return std::optional<uint64_t>{raw->as_uint64()};
    }
    return std::unexpected(std::format("{} must be an integer", key));
}

std::string ReadString(const json::object& source, std::string_view key) {
    const auto* value = source.if_contains(key);
    return value && value->is_string()
        ? std::string(value->as_string())
        : std::string{};
}

std::expected<std::chrono::seconds, std::string> ReadPositiveSeconds(
    const json::object& source,
    std::string_view key,
    std::chrono::seconds fallback) {
    auto parsed = ReadOptionalUnsigned(source, key);
    if (!parsed) return std::unexpected(std::move(parsed.error()));
    if (!*parsed) return fallback;
    if (**parsed == 0) {
        return std::unexpected(std::format(
            "{} must be positive", key));
    }
    using Rep = std::chrono::seconds::rep;
    if (**parsed > static_cast<uint64_t>(std::numeric_limits<Rep>::max())) {
        return std::unexpected(std::format(
            "{} exceeds the seconds range", key));
    }
    const auto clock_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::duration::max()).count();
    if (**parsed > static_cast<uint64_t>(clock_seconds)) {
        return std::unexpected(std::format(
            "{} exceeds the steady clock range", key));
    }
    return std::chrono::seconds(static_cast<Rep>(**parsed));
}

}  // namespace

std::expected<Settings, std::string> ParseSettings(const json::object& source) {
    Settings result;

    result.address = ReadString(source, "address");

    const auto port = ReadJsonPort(source, "port");
    if (port.Invalid()) {
        return std::unexpected("AnyTLS server port must be between 1 and 65535");
    }
    if (port.Valid()) result.port = port.value;

    auto password = ReadString(source, "password");
    if (password.empty()) password = ReadString(source, "key");

    auto check_interval = ReadPositiveSeconds(
        source,
        "idleSessionCheckInterval",
        result.idle_session_check_interval);
    if (!check_interval) {
        return std::unexpected(std::move(check_interval.error()));
    }
    result.idle_session_check_interval = *check_interval;

    auto idle_timeout = ReadPositiveSeconds(
        source,
        "idleSessionTimeout",
        result.idle_session_timeout);
    if (!idle_timeout) return std::unexpected(std::move(idle_timeout.error()));
    result.idle_session_timeout = *idle_timeout;

    auto min_idle = ReadOptionalUnsigned(
        source, "minIdleSession");
    if (!min_idle) return std::unexpected(std::move(min_idle.error()));
    if (*min_idle) {
        if (**min_idle > std::numeric_limits<size_t>::max()) {
            return std::unexpected("minIdleSession exceeds the size range");
        }
        result.min_idle_sessions = static_cast<size_t>(**min_idle);
    }

    if (result.address.empty()) return std::unexpected("AnyTLS address is required");
    result.literal_address = iputil::ParseLiteral(result.address);
    if (!result.literal_address && !domain::IsValidDnsHostname(
            result.address, domain::TrailingDotPolicy::Allow)) {
        return std::unexpected("AnyTLS address must be an IP literal or DNS hostname");
    }
    if (password.empty()) return std::unexpected("AnyTLS password is required");
    if (result.port == 0) return std::unexpected("AnyTLS port is required");
    result.password_hash = acpp::anytls::PasswordHash(password);
    return result;
}

}  // namespace acpp::proxy::anytls::outbound
