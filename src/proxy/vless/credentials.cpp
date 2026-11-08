#include "credentials.hpp"

#include "../uuid.hpp"
#include "core/naming.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <cstring>

namespace vless {

namespace {

[[nodiscard]] std::array<uint8_t, 16>
MapCustomIdToUuidV5(std::string_view id) noexcept {
    std::array<uint8_t, 16 + 30> input{};
    std::memcpy(input.data() + 16, id.data(), id.size());

    std::array<uint8_t, SHA_DIGEST_LENGTH> digest{};
    SHA1(input.data(), 16 + id.size(), digest.data());

    std::array<uint8_t, 16> out{};
    std::copy_n(digest.begin(), out.size(), out.begin());
    out[6] = static_cast<uint8_t>((out[6] & 0x0f) | 0x50);
    out[8] = static_cast<uint8_t>((out[8] & 0x3f) | 0x80);
    return out;
}

}  // namespace

std::optional<std::array<uint8_t, 16>>
ParseUuidBytes(std::string_view uuid) noexcept {
    if (auto parsed = proxy::ParseUuid(uuid)) {
        return parsed;
    }
    if (!uuid.empty() && uuid.size() <= 30) {
        return MapCustomIdToUuidV5(uuid);
    }
    return std::nullopt;
}

std::string NormalizeFlow(std::string_view flow) {
    return naming::LowerAscii(std::string(flow));
}

}  // namespace vless
