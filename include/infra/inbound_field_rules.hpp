#pragma once

// Authoritative semantic validation for inbound fields that both the panel
// mapping (src/api/v2board) and the local configuration (src/infra/config.cpp)
// accept. Sources only translate their wire keys into these inputs.

#include "infra/json.hpp"
#include "transport/internet/stream_settings.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <tl/expected.hpp>

namespace infra {

// ---------------------------------------------------------------------------
// REALITY (Xray-core infra/conf/transport_internet.go REALITYConfig semantics)
// ---------------------------------------------------------------------------

// A REALITY server name names a TLS ClientHello SNI: a DNS hostname, never an
// IP literal and never with a trailing dot.
[[nodiscard]] bool IsValidRealityServerName(std::string_view name) noexcept;

// Server-side REALITY fields after wire mapping. `std::nullopt` means the
// field was not declared; a declared empty value is invalid where Xray-core
// rejects it.
struct RealityServerInput {
    std::optional<std::string> private_key;
    // An empty entry permits a ClientHello without SNI.
    std::vector<std::string> server_names;
    // Each entry holds "" .. 16 hex characters.
    std::vector<std::string> short_ids;
    std::optional<std::string> dest;  // "host:port"
    uint64_t xver = 0;
    std::optional<std::string> mldsa65_seed;
    std::string min_client_ver;  // "" = unbounded
    std::string max_client_ver;  // "" = unbounded
    uint64_t max_time_diff = 0;
};

// Validates and writes the server-side fields into `out`; client-only fields
// of `out` are left untouched.
[[nodiscard]] tl::expected<void, std::string> ApplyRealityServerInput(
    const RealityServerInput& input, RealityConfig& out);

// Requirements of a REALITY config terminating client connections.
[[nodiscard]] tl::expected<void, std::string> ValidateInboundReality(
    const RealityConfig& config);

// ---------------------------------------------------------------------------
// TLS / transport request fields
// ---------------------------------------------------------------------------

// "" stays unset; otherwise an IP literal or DNS hostname, lowercased.
[[nodiscard]] tl::expected<std::string, std::string> NormalizeTlsServerName(
    std::string_view value, std::string_view field);

// "" selects the transport default "/"; otherwise an HTTP request target.
[[nodiscard]] tl::expected<std::string, std::string> NormalizeTransportPath(
    std::string_view value, std::string_view field);

// "" stays unset; otherwise an HTTP authority, lowercased.
[[nodiscard]] tl::expected<std::string, std::string> NormalizeHttpAuthority(
    std::string_view value, std::string_view field);

// gRPC serviceName: no whitespace, controls or '#', and the derived request
// path must be a valid HTTP request target.
[[nodiscard]] tl::expected<void, std::string> ValidateGrpcServiceName(
    std::string_view value, std::string_view field);

// ---------------------------------------------------------------------------
// Sniffing
// ---------------------------------------------------------------------------

// Xray destOverride names to the SniffConfig bitset; fakedns is rejected.
[[nodiscard]] tl::expected<uint8_t, std::string> ParseSniffDestOverride(
    std::span<const std::string> protocols);

// ---------------------------------------------------------------------------
// AnyTLS padding scheme
// ---------------------------------------------------------------------------

// A string or an array of strings joined with '\n'; null leaves the scheme
// unset (""). A non-empty scheme must parse and fit one UpdatePaddingScheme
// frame.
[[nodiscard]] tl::expected<std::string, std::string> ParseAnyTlsPaddingScheme(
    const json::value& value, std::string_view field);

}  // namespace infra
