#pragma once

#include "common/byte_reader.hpp"

#include <algorithm>
#include <bitset>
#include <cstdint>
#include <span>
#include <string_view>
#include <tl/expected.hpp>

namespace transport::internet {

enum class TlsServerNameExtensionError {
    InvalidFormat,
};

// 解析 ClientHello 的 server_name 扩展体（RFC 6066 §3），返回 host_name。
// 嗅探与 REALITY 服务端共用；名称类型重复、空名或含 NUL 均视为格式错误。
[[nodiscard]] inline tl::expected<std::string_view, TlsServerNameExtensionError>
ParseTlsServerNameExtension(std::span<const uint8_t> extension) noexcept {
    common::ByteReader outer(extension);
    const auto list = outer.ReadBytes(outer.ReadU16BE());
    if (!outer.Ok() || !outer.Empty()) {
        return tl::unexpected(TlsServerNameExtensionError::InvalidFormat);
    }

    std::bitset<256> seen_types;
    std::string_view host_name;
    common::ByteReader reader(list);
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

}  // namespace transport::internet
