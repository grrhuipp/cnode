#pragma once

#include <cstdint>
#include <tl/expected.hpp>
#include <span>
#include <string_view>

namespace acpp::transport::internet {

enum class TlsServerNameExtensionError {
    InvalidFormat,
};

[[nodiscard]] tl::expected<std::string_view, TlsServerNameExtensionError>
ParseTlsServerNameExtension(std::span<const uint8_t> extension) noexcept;

}  // namespace acpp::transport::internet
