#pragma once

#include "common/byte_reader.hpp"
#include "common/domain_name.hpp"

#include <algorithm>
#include <bitset>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <tl/expected.hpp>

namespace transport::internet {

enum class TlsServerNameExtensionError {
    InvalidFormat,
};

[[nodiscard]] inline tl::expected<std::string_view, TlsServerNameExtensionError>
ParseTlsServerNameExtension(std::span<const uint8_t> extension) noexcept {
    ByteReader outer(extension);
    const auto list = outer.ReadBytes(outer.ReadU16BE());
    if (!outer.Ok() || !outer.Empty()) {
        return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
    }

    std::bitset<256> seen_types;
    std::string_view host_name;
    ByteReader reader(list);
    while (!reader.Empty()) {
        const uint8_t name_type = reader.ReadU8();
        const uint16_t name_size = reader.ReadU16BE();
        const std::string_view name = reader.ReadStringView(name_size);
        if (!reader.Ok() || name_size == 0 || seen_types.test(name_type)) {
            return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
        }
        seen_types.set(name_type);
        if (name_type == 0) {
            if (std::ranges::find(name, '\0') != name.end()) {
                return tl::unexpected(
                    TlsServerNameExtensionError::InvalidFormat);
            }
            host_name = name;
        }
    }
    if (host_name.empty()) {
        return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
    }
    return host_name;
}

[[nodiscard]] inline bool IsRealityServerNameAllowed(
    std::span<const std::string> allowed,
    std::string_view requested) noexcept {
    return std::ranges::any_of(allowed, [requested](const std::string& name) {
        return domain::DnsHostnamesEqual(name, requested);
    });
}

}  // namespace transport::internet
