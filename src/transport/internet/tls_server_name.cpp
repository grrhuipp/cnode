#include "transport/internet/tls_server_name.hpp"
#include "common/byte_reader.hpp"

#include <algorithm>
#include <bitset>

namespace transport::internet {

tl::expected<std::string_view, TlsServerNameExtensionError>
ParseTlsServerNameExtension(std::span<const uint8_t> extension) noexcept {
    if (extension.size() < 2) {
        return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
    }

    const uint16_t list_size = LoadU16BE(extension.data());
    if (static_cast<std::size_t>(list_size) + 2 != extension.size()) {
        return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
    }

    std::bitset<256> seen_types;
    std::string_view host_name;
    std::size_t position = 2;
    const std::size_t end = extension.size();
    while (position < end) {
        if (end - position < 3) {
            return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
        }
        const uint8_t name_type = extension[position++];
        if (seen_types.test(name_type)) {
            return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
        }
        seen_types.set(name_type);
        const uint16_t name_size =
            LoadU16BE(extension.data() + position);
        position += 2;
        if (name_size == 0 || name_size > end - position) {
            return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
        }
        if (name_type == 0) {
            host_name = std::string_view(
                reinterpret_cast<const char*>(extension.data() + position),
                name_size);
            if (std::ranges::find(host_name, '\0') != host_name.end()) {
                return tl::unexpected(
                    TlsServerNameExtensionError::InvalidFormat);
            }
        }
        position += name_size;
    }
    if (host_name.empty()) {
        return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
    }
    return host_name;
}

}  // namespace transport::internet
