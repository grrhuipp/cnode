#pragma once

#include "infra/json.hpp"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <tl/expected.hpp>


// Typed readers for one object member. A missing key yields an empty optional
// (or nullptr); a present key with the wrong type, including JSON null, is an
// error, so callers apply defaults only to absent fields.

// The parser stores integers up to INT64_MAX as int64 and larger ones as
// uint64; this is the single conversion of either form to a non-negative value.
[[nodiscard]] std::optional<uint64_t> JsonUnsignedInteger(
    const json::value& value) noexcept;

[[nodiscard]] tl::expected<std::optional<bool>, std::string>
ParseJsonBool(const json::object& source, std::string_view key);

[[nodiscard]] tl::expected<std::optional<std::string>, std::string>
ParseJsonString(const json::object& source, std::string_view key);

[[nodiscard]]
tl::expected<std::optional<std::vector<std::string>>, std::string>
ParseJsonStringArray(const json::object& source, std::string_view key);

[[nodiscard]] tl::expected<std::optional<uint64_t>, std::string>
ParseJsonUint64(
    const json::object& source,
    std::string_view key,
    uint64_t maximum = std::numeric_limits<uint64_t>::max());

// The returned object borrows from source and is valid only while source
// remains alive and unmodified.
[[nodiscard]] tl::expected<const json::object*, std::string>
ParseJsonObject(const json::object& source, std::string_view key);

// Throwing forms for configuration loaders that report errors as
// std::invalid_argument; the fallback applies only to an absent key.
[[nodiscard]] std::string JsonStringOr(
    const json::object& source, std::string_view key, std::string_view fallback);
[[nodiscard]] bool JsonBoolOr(
    const json::object& source, std::string_view key, bool fallback);

enum class JsonPortError {
    None,
    Missing,
    InvalidType,
    OutOfRange,
};

struct JsonPortResult {
    JsonPortError error = JsonPortError::Missing;
    uint16_t value = 0;

    [[nodiscard]] bool Valid() const noexcept {
        return error == JsonPortError::None;
    }

    [[nodiscard]] bool Invalid() const noexcept {
        return error == JsonPortError::InvalidType ||
               error == JsonPortError::OutOfRange;
    }
};

[[nodiscard]] JsonPortResult ReadJsonPort(
    const json::object& source, std::string_view key) noexcept;

