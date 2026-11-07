#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/target_address.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>

namespace acpp {

// SOCKS5: type/address/port; VLESS, VMess and Mux: port/type/address;
// UoT datagrams: type/address/port with the UoT-specific 0/1/2 types.
enum class AddressWireFormat : uint8_t { Socks5, PortFirst, Uot };
enum class AddressDecodeStatus : uint8_t { Complete, Incomplete, Invalid };

struct AddressDecodeOptions {
    size_t max_domain_len = 255;
    bool require_non_empty_domain = false;
    bool allow_metadata = true;
};

inline constexpr uint8_t kAddressMetadataFlag = 0x80;
inline constexpr uint8_t kAddressMetaHasUserId = 0x01;
inline constexpr uint8_t kAddressMetaHasUserEmail = 0x02;
inline constexpr uint8_t kAddressMetaHasClientIpv4 = 0x04;
inline constexpr uint8_t kAddressMetaHasClientIpv6 = 0x08;
inline constexpr uint8_t kAddressMetaHasInboundTag = 0x10;
inline constexpr uint8_t kAddressMetaKnownFlags = 0x1F;
inline constexpr size_t kMaxAddressMetadataPayloadSize =
    1 + 10 + 1 + kMaxForwardedEmailLength + 16 + 1 + kMaxForwardedTagLength;
inline constexpr size_t kMaxBaseEncodedAddressSize = 1 + 1 + 255 + 2;
inline constexpr size_t kMaxEncodedAddressSize =
    kMaxBaseEncodedAddressSize + 1 + kMaxAddressMetadataPayloadSize;

struct DecodedAddress {
    TargetAddress target;
    size_t consumed = 0;
    std::optional<ForwardedMetadata> forwarded;
};

struct AddressDecodeResult {
    AddressDecodeStatus status = AddressDecodeStatus::Incomplete;
    TargetAddress target;
    size_t consumed = 0;
    // Incomplete only: minimum total address bytes needed for the next stage.
    size_t required = 1;
    std::optional<ForwardedMetadata> forwarded;
};

namespace detail {

[[nodiscard]] constexpr size_t AddressMetadataVarintSize(uint64_t value) noexcept {
    size_t size = 1;
    while (value >= 0x80) {
        value >>= 7;
        ++size;
    }
    return size;
}

inline size_t WriteAddressMetadataVarint(uint8_t* out, uint64_t value) noexcept {
    size_t pos = 0;
    while (value >= 0x80) {
        out[pos++] = static_cast<uint8_t>((value & 0x7Fu) | 0x80u);
        value >>= 7;
    }
    out[pos++] = static_cast<uint8_t>(value);
    return pos;
}

[[nodiscard]] inline bool ReadAddressMetadataVarint(
    std::span<const uint8_t> data, size_t& pos, uint64_t& out) noexcept {
    uint64_t value = 0;
    unsigned shift = 0;
    for (size_t i = 0; i < 10; ++i) {
        if (pos >= data.size()) return false;
        const uint8_t byte = data[pos++];
        if (shift == 63 && byte > 1) return false;
        value |= static_cast<uint64_t>(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) {
            if ((i > 0 && byte == 0) || value == 0 ||
                value > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
                return false;
            }
            out = value;
            return true;
        }
        shift += 7;
    }
    return false;
}

struct NormalizedMetadataView {
    uint8_t flags = 0;
    uint64_t user_id = 0;
    std::string_view user_email{};
    net::ip::address client_ip{};
    std::string_view inbound_tag{};
    size_t payload_size = 0;
};

[[nodiscard]] inline NormalizedMetadataView NormalizeMetadataView(
    ForwardedMetadataView metadata) noexcept {
    NormalizedMetadataView out;
    if (metadata.user_id > 0) {
        out.flags |= kAddressMetaHasUserId;
        out.user_id = static_cast<uint64_t>(metadata.user_id);
        out.payload_size += AddressMetadataVarintSize(out.user_id);
    }
    std::string_view email = metadata.user_email.substr(
        0, std::min(metadata.user_email.size(), kMaxForwardedEmailLength));
    if (const size_t nul = email.find('\0'); nul != std::string_view::npos) {
        email = email.substr(0, nul);
    }
    if (!email.empty()) {
        out.flags |= kAddressMetaHasUserEmail;
        out.user_email = email;
        out.payload_size += 1 + email.size();
    }
    if (metadata.client_ip) {
        const auto normalized = iputil::NormalizeAddress(*metadata.client_ip);
        if (!normalized.is_unspecified()) {
            out.client_ip = normalized;
            if (normalized.is_v4()) {
                out.flags |= kAddressMetaHasClientIpv4;
                out.payload_size += 4;
            } else if (normalized.is_v6()) {
                out.flags |= kAddressMetaHasClientIpv6;
                out.payload_size += 16;
            }
        }
    }
    std::string_view tag = metadata.inbound_tag.substr(
        0, std::min(metadata.inbound_tag.size(), kMaxForwardedTagLength));
    if (const size_t nul = tag.find('\0'); nul != std::string_view::npos) {
        tag = tag.substr(0, nul);
    }
    if (!tag.empty()) {
        out.flags |= kAddressMetaHasInboundTag;
        out.inbound_tag = tag;
        out.payload_size += 1 + tag.size();
    }
    if (out.flags != 0) {
        out.payload_size += 1;  // flags byte
    }
    return out;
}

[[nodiscard]] inline size_t BaseAddressEncodedSize(const TargetAddress& target) noexcept {
    if (target.IsDomain()) {
        return target.host.size() <= 255 ? 4 + target.host.size() : 0;
    }
    if (target.resolved_addr) {
        if (target.resolved_addr->is_v4()) return 7;
        if (target.resolved_addr->is_v6()) return 19;
    }
    return 0;
}

}  // namespace detail

// Every AddressWireFormat encodes the same fields, so the size is format-free.
[[nodiscard]] inline size_t AddressEncodedSize(
    const TargetAddress& target,
    ForwardedMetadataView metadata = {}) noexcept {
    const size_t base_size = detail::BaseAddressEncodedSize(target);
    if (base_size == 0) return 0;
    const auto normalized = detail::NormalizeMetadataView(metadata);
    if (normalized.payload_size == 0) return base_size;
    return base_size + 1 + normalized.payload_size;
}

[[nodiscard]] inline size_t EncodeAddressTo(
    const TargetAddress& target, uint8_t* output, size_t capacity,
    AddressWireFormat format,
    ForwardedMetadataView metadata = {}) noexcept {
    const size_t base_size = detail::BaseAddressEncodedSize(target);
    if (!output || base_size == 0) return 0;
    const auto normalized = detail::NormalizeMetadataView(metadata);
    const size_t size = normalized.payload_size == 0
        ? base_size
        : base_size + 1 + normalized.payload_size;
    if (size > capacity) return 0;
    // An address may borrow from an existing frame, but never from the region
    // being overwritten by this encoding operation.
    if (target.IsDomain() && !target.host.empty()) {
        const auto host = reinterpret_cast<uintptr_t>(target.host.data());
        const auto out = reinterpret_cast<uintptr_t>(output);
        if (host <= out ? out - host < target.host.size() : host - out < size)
            return 0;
    }
    if (!normalized.user_email.empty()) {
        const auto email = reinterpret_cast<uintptr_t>(normalized.user_email.data());
        const auto out = reinterpret_cast<uintptr_t>(output);
        if (email <= out ? out - email < normalized.user_email.size() : email - out < size)
            return 0;
    }
    if (!normalized.inbound_tag.empty()) {
        const auto tag = reinterpret_cast<uintptr_t>(normalized.inbound_tag.data());
        const auto out = reinterpret_cast<uintptr_t>(output);
        if (tag <= out ? out - tag < normalized.inbound_tag.size() : tag - out < size)
            return 0;
    }
    const bool port_first = format == AddressWireFormat::PortFirst;
    const size_t port_pos = port_first ? 0 : base_size - 2;
    size_t pos = port_first ? 2 : 0;
    const uint8_t meta_bit = normalized.payload_size != 0 ? kAddressMetadataFlag : 0;
    if (target.IsDomain()) {
        output[pos++] = static_cast<uint8_t>(
            (format == AddressWireFormat::Socks5 ? 3 : 2) | meta_bit);
        output[pos++] = static_cast<uint8_t>(target.host.size());
        if (!target.host.empty())
            std::memcpy(output + pos, target.host.data(), target.host.size());
    } else if (target.resolved_addr->is_v4()) {
        output[pos++] = static_cast<uint8_t>(
            (format == AddressWireFormat::Uot ? 0 : 1) | meta_bit);
        const auto bytes = target.resolved_addr->to_v4().to_bytes();
        std::memcpy(output + pos, bytes.data(), bytes.size());
    } else {
        const uint8_t v6_code = format == AddressWireFormat::Socks5 ? 4
            : format == AddressWireFormat::PortFirst ? 3 : 1;
        output[pos++] = static_cast<uint8_t>(v6_code | meta_bit);
        const auto bytes = target.resolved_addr->to_v6().to_bytes();
        std::memcpy(output + pos, bytes.data(), bytes.size());
    }
    output[port_pos] = static_cast<uint8_t>(target.port >> 8);
    output[port_pos + 1] = static_cast<uint8_t>(target.port);
    if (normalized.payload_size != 0) {
        size_t meta_pos = base_size;
        output[meta_pos++] = static_cast<uint8_t>(normalized.payload_size);
        output[meta_pos++] = normalized.flags;
        if ((normalized.flags & kAddressMetaHasUserId) != 0) {
            meta_pos += detail::WriteAddressMetadataVarint(
                output + meta_pos, normalized.user_id);
        }
        if ((normalized.flags & kAddressMetaHasUserEmail) != 0) {
            output[meta_pos++] = static_cast<uint8_t>(normalized.user_email.size());
            std::memcpy(output + meta_pos,
                        normalized.user_email.data(),
                        normalized.user_email.size());
            meta_pos += normalized.user_email.size();
        }
        if ((normalized.flags & kAddressMetaHasClientIpv4) != 0) {
            const auto bytes = normalized.client_ip.to_v4().to_bytes();
            std::memcpy(output + meta_pos, bytes.data(), bytes.size());
            meta_pos += bytes.size();
        } else if ((normalized.flags & kAddressMetaHasClientIpv6) != 0) {
            const auto bytes = normalized.client_ip.to_v6().to_bytes();
            std::memcpy(output + meta_pos, bytes.data(), bytes.size());
            meta_pos += bytes.size();
        }
        if ((normalized.flags & kAddressMetaHasInboundTag) != 0) {
            output[meta_pos++] = static_cast<uint8_t>(normalized.inbound_tag.size());
            std::memcpy(output + meta_pos,
                        normalized.inbound_tag.data(),
                        normalized.inbound_tag.size());
            meta_pos += normalized.inbound_tag.size();
        }
    }
    return size;
}
[[nodiscard]] inline AddressDecodeResult DecodeAddress(
    std::span<const uint8_t> data, AddressWireFormat format,
    AddressDecodeOptions options = {}) {
    AddressDecodeResult result;
    const bool port_first = format == AddressWireFormat::PortFirst;
    const size_t type_pos = port_first ? 2 : 0;
    result.required = type_pos + 1;
    if (data.size() < result.required) return result;
    const uint8_t raw_type = data[type_pos];
    const bool has_metadata = (raw_type & kAddressMetadataFlag) != 0;
    const uint8_t type = raw_type & static_cast<uint8_t>(~kAddressMetadataFlag);
    const uint8_t v4_type = format == AddressWireFormat::Uot ? 0 : 1;
    const uint8_t v6_type = format == AddressWireFormat::Socks5 ? 4
        : format == AddressWireFormat::PortFirst ? 3 : 1;
    const uint8_t domain_type = format == AddressWireFormat::Socks5 ? 3 : 2;
    size_t body_pos = type_pos + 1;
    size_t body_size = 0;
    if (type == v4_type) {
        body_size = 4;
    } else if (type == v6_type) {
        body_size = 16;
    } else if (type == domain_type) {
        result.required = body_pos + 1;
        if (data.size() < result.required) return result;
        body_size = data[body_pos++];
        if (body_size > options.max_domain_len ||
            (body_size == 0 && options.require_non_empty_domain)) {
            result.status = AddressDecodeStatus::Invalid;
            result.required = 0;
            return result;
        }
    } else {
        result.status = AddressDecodeStatus::Invalid;
        result.required = 0;
        return result;
    }
    const size_t base_size = body_pos + body_size + (port_first ? 0 : 2);
    size_t total_size = base_size;
    if (!has_metadata) {
        result.required = base_size;
        if (data.size() < base_size) return result;
    } else {
        if (!options.allow_metadata) {
            result.status = AddressDecodeStatus::Invalid;
            result.required = 0;
            return result;
        }
        result.required = base_size + 1;
        if (data.size() < result.required) return result;
        const uint8_t meta_len = data[base_size];
        if (meta_len < 2 || meta_len > kMaxAddressMetadataPayloadSize) {
            result.status = AddressDecodeStatus::Invalid;
            result.required = 0;
            return result;
        }
        total_size = base_size + 1 + meta_len;
        result.required = total_size;
        if (data.size() < total_size) return result;
    }
    const size_t port_pos = port_first ? 0 : base_size - 2;
    const uint16_t port = static_cast<uint16_t>(
        (static_cast<uint16_t>(data[port_pos]) << 8) | data[port_pos + 1]);
    if (type == v4_type) {
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + body_pos, bytes.size());
        result.target = TargetAddress(net::ip::make_address_v4(bytes), port);
    } else if (type == v6_type) {
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + body_pos, bytes.size());
        result.target = TargetAddress(net::ip::make_address_v6(bytes), port);
    } else {
        result.target = TargetAddress(std::string_view(
            reinterpret_cast<const char*>(data.data() + body_pos), body_size), port);
    }
    if (has_metadata) {
        const uint8_t meta_len = data[base_size];
        const std::span<const uint8_t> meta = data.subspan(base_size + 1, meta_len);
        size_t meta_pos = 0;
        const uint8_t flags = meta[meta_pos++];
        if (flags == 0 || (flags & static_cast<uint8_t>(~kAddressMetaKnownFlags)) != 0 ||
            ((flags & kAddressMetaHasClientIpv4) != 0 &&
             (flags & kAddressMetaHasClientIpv6) != 0)) {
            result.status = AddressDecodeStatus::Invalid;
            result.required = 0;
            return result;
        }
        ForwardedMetadata forwarded;
        if ((flags & kAddressMetaHasUserId) != 0) {
            uint64_t uid = 0;
            if (!detail::ReadAddressMetadataVarint(meta, meta_pos, uid)) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            forwarded.user_id = static_cast<int64_t>(uid);
        }
        if ((flags & kAddressMetaHasUserEmail) != 0) {
            if (meta_pos >= meta.size()) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            const uint8_t email_len = meta[meta_pos++];
            if (email_len == 0 || email_len > kMaxForwardedEmailLength ||
                meta.size() - meta_pos < email_len) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            const std::string_view email_view(
                reinterpret_cast<const char*>(meta.data() + meta_pos), email_len);
            if (email_view.find('\0') != std::string_view::npos) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            forwarded.user_email.assign(email_view.data(), email_view.size());
            meta_pos += email_len;
        }
        if ((flags & kAddressMetaHasClientIpv4) != 0) {
            if (meta.size() - meta_pos < 4) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            net::ip::address_v4::bytes_type v4_bytes{};
            std::memcpy(v4_bytes.data(), meta.data() + meta_pos, v4_bytes.size());
            meta_pos += v4_bytes.size();
            const auto addr = net::ip::make_address_v4(v4_bytes);
            if (addr.is_unspecified()) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            forwarded.client_ip = addr;
        } else if ((flags & kAddressMetaHasClientIpv6) != 0) {
            if (meta.size() - meta_pos < 16) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            net::ip::address_v6::bytes_type v6_bytes{};
            std::memcpy(v6_bytes.data(), meta.data() + meta_pos, v6_bytes.size());
            meta_pos += v6_bytes.size();
            const auto addr = iputil::NormalizeAddress(net::ip::make_address_v6(v6_bytes));
            if (addr.is_unspecified()) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            forwarded.client_ip = addr;
        }
        if ((flags & kAddressMetaHasInboundTag) != 0) {
            if (meta_pos >= meta.size()) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            const uint8_t tag_len = meta[meta_pos++];
            if (tag_len == 0 || tag_len > kMaxForwardedTagLength ||
                meta.size() - meta_pos < tag_len) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            const std::string_view tag_view(
                reinterpret_cast<const char*>(meta.data() + meta_pos), tag_len);
            if (tag_view.find('\0') != std::string_view::npos) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            forwarded.inbound_tag.assign(tag_view.data(), tag_view.size());
            meta_pos += tag_len;
        }
        if (meta_pos != meta.size() || forwarded.Empty()) {
            result.status = AddressDecodeStatus::Invalid;
            result.required = 0;
            return result;
        }
        result.forwarded = std::move(forwarded);
    }
    result.status = AddressDecodeStatus::Complete;
    result.consumed = total_size;
    result.required = 0;
    return result;
}

// Reader must provide ReadMultiBuffer(). The pending owner retains every byte,
// including the decoded prefix; only its caller decides when to consume it.
// A clean EOF before an address is still an incomplete address, not success.
template <typename Reader>
[[nodiscard]] net::awaitable<tl::expected<DecodedAddress, ErrorCode>> ReadAddress(
    Reader& reader, buf::MultiBuffer& pending, AddressWireFormat format,
    size_t offset = 0, AddressDecodeOptions options = {}) {
    std::array<uint8_t, kMaxEncodedAddressSize> bytes{};
    size_t copied = 0;
    for (;;) {
        const size_t total = pending.byte_size();
        const size_t available = total > offset
            ? std::min(total - offset, bytes.size()) : 0;
        size_t skip = offset + copied;
        for (const auto* buffer : pending) {
            if (!buffer || buffer->IsEmpty()) continue;
            const auto source = buffer->Bytes();
            if (skip >= source.size()) {
                skip -= source.size();
                continue;
            }
            const size_t count = std::min(source.size() - skip, available - copied);
            if (count != 0)
                std::memcpy(bytes.data() + copied, source.data() + skip, count);
            copied += count;
            skip = 0;
            if (copied == available) break;
        }
        auto decoded = DecodeAddress(std::span<const uint8_t>(bytes.data(), copied),
                                     format, options);
        if (decoded.status == AddressDecodeStatus::Complete) {
            co_return DecodedAddress{
                std::move(decoded.target),
                decoded.consumed,
                std::move(decoded.forwarded)};
        }
        if (decoded.status == AddressDecodeStatus::Invalid) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        auto next = co_await ReadMultiBufferOrThrowOnCancel(reader);
        if (next.byte_size() == 0) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        pending.AppendAndCoalesce(std::move(next));
    }
}

}  // namespace acpp
