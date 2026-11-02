#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace acpp::transport::internet {

enum class TlsServerNameExtensionError {
    InvalidFormat,
};

[[nodiscard]] std::expected<std::string_view, TlsServerNameExtensionError>
ParseTlsServerNameExtension(std::span<const uint8_t> extension) noexcept;

}  // namespace acpp::transport::internet
