#include "anytls_outbound_settings.hpp"

#include "acppnode/infra/json_port.hpp"

#include <chrono>
#include <format>
#include <initializer_list>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace acpp::proxy::anytls::outbound {

namespace {

struct AliasedUnsigned {
    std::optional<uint64_t> value;
};

std::expected<AliasedUnsigned, std::string> ReadAliasedUnsigned(
    const json::object& source,
    std::initializer_list<std::string_view> aliases) {
    AliasedUnsigned result;
    std::string_view first_key;
    for (const auto key : aliases) {
        const auto* raw = source.if_contains(key);
        if (!raw) continue;

        uint64_t value = 0;
        if (raw->is_int64()) {
            const int64_t signed_value = raw->as_int64();
            if (signed_value < 0) {
                return std::unexpected(std::format(
                    "{} must not be negative", key));
            }
            value = static_cast<uint64_t>(signed_value);
        } else if (raw->is_uint64()) {
            value = raw->as_uint64();
        } else {
            return std::unexpected(std::format("{} must be an integer", key));
        }

        if (result.value && *result.value != value) {
            return std::unexpected(std::format(
                "{} and {} must match", first_key, key));
        }
        if (!result.value) {
            result.value = value;
            first_key = key;
        }
    }
    return result;
}

std::string ReadString(const json::object& source, std::string_view key) {
    const auto* value = source.if_contains(key);
    return value && value->is_string()
        ? std::string(value->as_string())
        : std::string{};
}

std::expected<std::chrono::seconds, std::string> ReadPositiveSeconds(
    const json::object& source,
    std::initializer_list<std::string_view> aliases,
    std::chrono::seconds fallback) {
    auto parsed = ReadAliasedUnsigned(source, aliases);
    if (!parsed) return std::unexpected(std::move(parsed.error()));
    if (!parsed->value) return fallback;
    if (*parsed->value == 0) {
        return std::unexpected(std::format(
            "{} must be positive", *aliases.begin()));
    }
    using Rep = std::chrono::seconds::rep;
    if (*parsed->value > static_cast<uint64_t>(std::numeric_limits<Rep>::max())) {
        return std::unexpected(std::format(
            "{} exceeds the seconds range", *aliases.begin()));
    }
    return std::chrono::seconds(static_cast<Rep>(*parsed->value));
}

}  // namespace

std::expected<Settings, std::string> ParseSettings(const json::object& source) {
    Settings result;

    result.address = ReadString(source, "address");
    if (result.address.empty()) result.address = ReadString(source, "server");

    const auto port = ReadJsonPort(source, {"server_port", "port"});
    if (port.Invalid()) {
        return std::unexpected("AnyTLS server port must be between 1 and 65535");
    }
    if (port.Valid()) result.port = port.value;

    result.password = ReadString(source, "password");
    if (result.password.empty()) result.password = ReadString(source, "key");

    auto check_interval = ReadPositiveSeconds(
        source,
        {"idleSessionCheckInterval", "idle_session_check_interval"},
        result.idle_session_check_interval);
    if (!check_interval) {
        return std::unexpected(std::move(check_interval.error()));
    }
    result.idle_session_check_interval = *check_interval;

    auto idle_timeout = ReadPositiveSeconds(
        source,
        {"idleSessionTimeout", "idle_session_timeout"},
        result.idle_session_timeout);
    if (!idle_timeout) return std::unexpected(std::move(idle_timeout.error()));
    result.idle_session_timeout = *idle_timeout;

    auto min_idle = ReadAliasedUnsigned(
        source, {"minIdleSession", "min_idle_session"});
    if (!min_idle) return std::unexpected(std::move(min_idle.error()));
    if (min_idle->value) {
        if (*min_idle->value > std::numeric_limits<size_t>::max()) {
            return std::unexpected("minIdleSession exceeds the size range");
        }
        result.min_idle_sessions = static_cast<size_t>(*min_idle->value);
    }

    IoErrorCode address_error;
    auto literal_address = net::ip::make_address(result.address, address_error);
    if (!address_error) result.literal_address = literal_address;

    if (result.address.empty()) return std::unexpected("AnyTLS address is required");
    if (result.password.empty()) return std::unexpected("AnyTLS password is required");
    if (result.port == 0) return std::unexpected("AnyTLS port is required");
    return result;
}

}  // namespace acpp::proxy::anytls::outbound
