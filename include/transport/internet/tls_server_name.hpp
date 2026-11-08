#pragma once

#include <cstdint>
#include <tl/expected.hpp>
#include <span>
#include <string_view>

namespace transport::internet {

enum class TlsServerNameExtensionError {
    InvalidFormat,
};

[[nodiscard]] tl::expected<std::string_view, TlsServerNameExtensionError>
ParseTlsServerNameExtension(std::span<const uint8_t> extension) noexcept;

}  // namespace transport::internet
