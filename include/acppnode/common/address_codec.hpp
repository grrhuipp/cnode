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
};

inline constexpr size_t kMaxEncodedAddressSize = 1 + 1 + 255 + 2;

struct DecodedAddress {
    TargetAddress target;
    size_t consumed = 0;
};

struct AddressDecodeResult {
    AddressDecodeStatus status = AddressDecodeStatus::Incomplete;
    TargetAddress target;
    size_t consumed = 0;
    // Incomplete only: minimum total address bytes needed for the next stage.
    size_t required = 1;
};

// Every AddressWireFormat encodes the same fields, so the size is format-free.
[[nodiscard]] inline size_t AddressEncodedSize(const TargetAddress& target) noexcept {
    if (target.IsDomain()) {
        return target.host.size() <= 255 ? 4 + target.host.size() : 0;
    }
    if (target.resolved_addr) {
        if (target.resolved_addr->is_v4()) return 7;
        if (target.resolved_addr->is_v6()) return 19;
    }
    return 0;
}

[[nodiscard]] inline size_t EncodeAddressTo(
    const TargetAddress& target, uint8_t* output, size_t capacity,
    AddressWireFormat format) noexcept {
    const size_t size = AddressEncodedSize(target);
    if (!output || size == 0 || size > capacity) return 0;
    // An address may borrow from an existing frame, but never from the region
    // being overwritten by this encoding operation.
    if (target.IsDomain() && !target.host.empty()) {
        const auto host = reinterpret_cast<uintptr_t>(target.host.data());
        const auto out = reinterpret_cast<uintptr_t>(output);
        if (host <= out ? out - host < target.host.size() : host - out < size)
            return 0;
    }
    const bool port_first = format == AddressWireFormat::PortFirst;
    const size_t port_pos = port_first ? 0 : size - 2;
    size_t pos = port_first ? 2 : 0;
    if (target.IsDomain()) {
        output[pos++] = format == AddressWireFormat::Socks5 ? 3 : 2;
        output[pos++] = static_cast<uint8_t>(target.host.size());
        if (!target.host.empty())
            std::memcpy(output + pos, target.host.data(), target.host.size());
    } else if (target.resolved_addr->is_v4()) {
        output[pos++] = format == AddressWireFormat::Uot ? 0 : 1;
        const auto bytes = target.resolved_addr->to_v4().to_bytes();
        std::memcpy(output + pos, bytes.data(), bytes.size());
    } else {
        output[pos++] = format == AddressWireFormat::Socks5 ? 4
            : format == AddressWireFormat::PortFirst ? 3 : 1;
        const auto bytes = target.resolved_addr->to_v6().to_bytes();
        std::memcpy(output + pos, bytes.data(), bytes.size());
    }
    output[port_pos] = static_cast<uint8_t>(target.port >> 8);
    output[port_pos + 1] = static_cast<uint8_t>(target.port);
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
    const uint8_t type = data[type_pos];
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
    const size_t size = body_pos + body_size + (port_first ? 0 : 2);
    result.required = size;
    if (data.size() < size) return result;
    const size_t port_pos = port_first ? 0 : size - 2;
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
    result.status = AddressDecodeStatus::Complete;
    result.consumed = size;
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
        if (decoded.status == AddressDecodeStatus::Complete)
            co_return DecodedAddress{std::move(decoded.target), decoded.consumed};
        if (decoded.status == AddressDecodeStatus::Invalid)
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        auto next = co_await ReadMultiBufferOrThrowOnCancel(reader);
        if (next.byte_size() == 0) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        pending.AppendAndCoalesce(std::move(next));
    }
}

}  // namespace acpp
