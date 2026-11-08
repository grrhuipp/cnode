#pragma once

#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buffer_util.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"

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


// SOCKS5: type/address/port; VLESS, VMess and Mux: port/type/address;
// UoT datagrams: type/address/port with the UoT-specific 0/1/2 types.
enum class AddressWireFormat : uint8_t { Socks5, PortFirst, Uot };
enum class AddressDecodeStatus : uint8_t { Complete, Incomplete, Invalid };

struct AddressDecodeOptions {
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

[[nodiscard]] inline size_t WriteAddressMetadataVarint(
    std::span<uint8_t> out, uint64_t value) noexcept {
    size_t pos = 0;
    while (value >= 0x80) {
        if (pos >= out.size()) return 0;
        out[pos++] = static_cast<uint8_t>((value & 0x7Fu) | 0x80u);
        value >>= 7;
    }
    if (pos >= out.size()) return 0;
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
    if (!output || base_size < 4) return 0;
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
    std::span<uint8_t> out_span(output, size);
    const bool port_first = format == AddressWireFormat::PortFirst;
    const size_t port_pos = port_first ? 0 : base_size - 2;
    const size_t body_pos = port_first ? 2 : 0;
    if (base_size > out_span.size() || port_pos + 2 > out_span.size()) return 0;
    std::span<uint8_t> body = out_span.subspan(body_pos, base_size - 2);
    const uint8_t meta_bit = normalized.payload_size != 0 ? kAddressMetadataFlag : 0;
    if (target.IsDomain()) {
        const size_t host_len = target.host.size();
        if (host_len > 255 || body.size() != 2 + host_len) return 0;
        body[0] = static_cast<uint8_t>(
            (format == AddressWireFormat::Socks5 ? 3 : 2) | meta_bit);
        body[1] = static_cast<uint8_t>(host_len);
        if (host_len != 0)
            std::memcpy(body.data() + 2, target.host.data(), host_len);
    } else if (target.resolved_addr && target.resolved_addr->is_v4()) {
        const auto bytes = target.resolved_addr->to_v4().to_bytes();
        if (body.size() != 1 + bytes.size()) return 0;
        body[0] = static_cast<uint8_t>(
            (format == AddressWireFormat::Uot ? 0 : 1) | meta_bit);
        std::memcpy(body.data() + 1, bytes.data(), bytes.size());
    } else if (target.resolved_addr && target.resolved_addr->is_v6()) {
        const auto bytes = target.resolved_addr->to_v6().to_bytes();
        if (body.size() != 1 + bytes.size()) return 0;
        const uint8_t v6_code = format == AddressWireFormat::Socks5 ? 4
            : format == AddressWireFormat::PortFirst ? 3 : 1;
        body[0] = static_cast<uint8_t>(v6_code | meta_bit);
        std::memcpy(body.data() + 1, bytes.data(), bytes.size());
    } else {
        return 0;
    }
    out_span[port_pos] = static_cast<uint8_t>(target.port >> 8);
    out_span[port_pos + 1] = static_cast<uint8_t>(target.port);
    if (normalized.payload_size != 0) {
        std::span<uint8_t> meta_rem = out_span.subspan(base_size);
        if (meta_rem.size() < 2) return 0;
        meta_rem[0] = static_cast<uint8_t>(normalized.payload_size);
        meta_rem[1] = normalized.flags;
        meta_rem = meta_rem.subspan(2);
        if ((normalized.flags & kAddressMetaHasUserId) != 0) {
            const size_t varint_len = detail::WriteAddressMetadataVarint(
                meta_rem, normalized.user_id);
            if (varint_len == 0 || varint_len > meta_rem.size()) return 0;
            meta_rem = meta_rem.subspan(varint_len);
        }
        if ((normalized.flags & kAddressMetaHasUserEmail) != 0) {
            const size_t email_len = normalized.user_email.size();
            if (meta_rem.size() < 1 + email_len) return 0;
            meta_rem[0] = static_cast<uint8_t>(email_len);
            std::memcpy(meta_rem.data() + 1,
                        normalized.user_email.data(),
                        email_len);
            meta_rem = meta_rem.subspan(1 + email_len);
        }
        if ((normalized.flags & kAddressMetaHasClientIpv4) != 0) {
            const auto bytes = normalized.client_ip.to_v4().to_bytes();
            if (meta_rem.size() < bytes.size()) return 0;
            std::memcpy(meta_rem.data(), bytes.data(), bytes.size());
            meta_rem = meta_rem.subspan(bytes.size());
        } else if ((normalized.flags & kAddressMetaHasClientIpv6) != 0) {
            const auto bytes = normalized.client_ip.to_v6().to_bytes();
            if (meta_rem.size() < bytes.size()) return 0;
            std::memcpy(meta_rem.data(), bytes.data(), bytes.size());
            meta_rem = meta_rem.subspan(bytes.size());
        }
        if ((normalized.flags & kAddressMetaHasInboundTag) != 0) {
            const size_t tag_len = normalized.inbound_tag.size();
            if (meta_rem.size() < 1 + tag_len) return 0;
            meta_rem[0] = static_cast<uint8_t>(tag_len);
            std::memcpy(meta_rem.data() + 1,
                        normalized.inbound_tag.data(),
                        tag_len);
            meta_rem = meta_rem.subspan(1 + tag_len);
        }
        if (!meta_rem.empty()) return 0;
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
        // TargetAddress validates hostname limits after removing the root dot.
        if (body_size == 0 && options.require_non_empty_domain) {
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
    int64_t meta_user_id = 0;
    std::string_view meta_email_view{};
    std::optional<net::ip::address> meta_client_ip{};
    std::string_view meta_tag_view{};
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
        if ((flags & kAddressMetaHasUserId) != 0) {
            uint64_t uid = 0;
            if (!detail::ReadAddressMetadataVarint(meta, meta_pos, uid)) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            meta_user_id = static_cast<int64_t>(uid);
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
            meta_email_view = std::string_view(
                reinterpret_cast<const char*>(meta.data() + meta_pos), email_len);
            if (meta_email_view.find('\0') != std::string_view::npos) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
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
            meta_client_ip = addr;
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
            meta_client_ip = addr;
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
            meta_tag_view = std::string_view(
                reinterpret_cast<const char*>(meta.data() + meta_pos), tag_len);
            if (meta_tag_view.find('\0') != std::string_view::npos) {
                result.status = AddressDecodeStatus::Invalid;
                result.required = 0;
                return result;
            }
            meta_pos += tag_len;
        }
        const ForwardedMetadataView validated_view{
            .user_id = meta_user_id,
            .user_email = meta_email_view,
            .client_ip = meta_client_ip,
            .inbound_tag = meta_tag_view,
        };
        if (meta_pos != meta.size() || validated_view.Empty()) {
            result.status = AddressDecodeStatus::Invalid;
            result.required = 0;
            return result;
        }
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
        auto& forwarded = result.forwarded.emplace();
        forwarded.user_id = meta_user_id;
        if (!meta_email_view.empty()) {
            forwarded.user_email.assign(meta_email_view.data(), meta_email_view.size());
        }
        forwarded.client_ip = meta_client_ip;
        if (!meta_tag_view.empty()) {
            forwarded.inbound_tag.assign(meta_tag_view.data(), meta_tag_view.size());
        }
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
    size_t needed = 1;
    for (;;) {
        const auto front = pending.FrontSpan();
        if (front.size() > offset && front.size() - offset >= needed) {
            auto decoded = DecodeAddress(front.subspan(offset), format, options);
            if (decoded.status == AddressDecodeStatus::Complete) {
                co_return DecodedAddress{
                    std::move(decoded.target),
                    decoded.consumed,
                    std::move(decoded.forwarded)};
            }
            if (decoded.status == AddressDecodeStatus::Invalid) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
            }
            needed = std::min(decoded.required, bytes.size());
        }
        const size_t total = pending.byte_size();
        const size_t available = total > offset
            ? std::min(total - offset, bytes.size()) : 0;
        while (available >= needed) {
            const size_t target_copy = std::min(available, needed);
            if (copied < target_copy) {
                size_t skip = offset + copied;
                for (const auto* buffer : pending) {
                    if (!buffer || buffer->IsEmpty()) continue;
                    const auto source = buffer->Bytes();
                    if (skip >= source.size()) {
                        skip -= source.size();
                        continue;
                    }
                    const size_t count = std::min(source.size() - skip, target_copy - copied);
                    if (count != 0)
                        std::memcpy(bytes.data() + copied, source.data() + skip, count);
                    copied += count;
                    skip = 0;
                    if (copied == target_copy) break;
                }
            }
            auto decoded = DecodeAddress(
                std::span<const uint8_t>(bytes.data(), copied), format, options);
            if (decoded.status == AddressDecodeStatus::Complete) {
                co_return DecodedAddress{
                    std::move(decoded.target),
                    decoded.consumed,
                    std::move(decoded.forwarded)};
            }
            if (decoded.status == AddressDecodeStatus::Invalid) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
            }
            needed = std::min(decoded.required, bytes.size());
            if (needed <= copied) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
            }
        }
        auto next = co_await ReadMultiBufferOrThrowOnCancel(reader);
        if (next.byte_size() == 0) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        pending.AppendAndCoalesce(std::move(next));
    }
}

