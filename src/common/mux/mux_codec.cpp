#include "common/mux/mux_codec.hpp"
#include "common/byte_reader.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/address_codec.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace mux {

namespace {

// 元数据必须被完整消费，超出最大合法布局（含 GlobalID）的 MetaLen 无需等待数据即可判定非法；
// Xray-core 解码端同样拒绝超长 metaLen。
constexpr size_t kMaxFrameMetadataBytes = 4 + 1 + kMaxEncodedAddressSize + 8;
// MetaLen + 元数据 + DataLen：解码所需的全部连续前缀
constexpr size_t kMaxFramePrefixBytes = 2 + kMaxFrameMetadataBytes + 2;

[[nodiscard]] bool ParsePortThenAddress(
    ByteReader& reader,
    TargetAddress& target,
    std::optional<ForwardedMetadata>& forwarded,
    bool allow_metadata) {
    auto view = reader;
    AddressDecodeOptions options;
    options.allow_metadata = allow_metadata;
    auto decoded = DecodeAddress(view.ReadBytes(view.Remaining()),
                                 AddressWireFormat::PortFirst,
                                 options);
    if (decoded.status != AddressDecodeStatus::Complete ||
        !reader.Skip(decoded.consumed)) return false;
    target = std::move(decoded.target);
    forwarded = std::move(decoded.forwarded);
    return target.IsValid();
}

[[nodiscard]] bool DecodeFrameMetadata(ByteReader& meta, FrameHeader& out) {
    const uint16_t session_id = meta.ReadU16BE();
    const uint8_t status_raw = meta.ReadU8();
    const uint8_t option = meta.ReadU8();
    constexpr uint8_t kKnownOptions = kOptionData | kOptionError;
    if (!meta.Ok() || status_raw < 1 || status_raw > 4 ||
        (option & static_cast<uint8_t>(~kKnownOptions)) != 0) {
        return false;
    }

    out.session_id = session_id;
    out.status = static_cast<SessionStatus>(status_raw);
    out.option = option;

    bool read_address = out.status == SessionStatus::NEW;
    if (out.status == SessionStatus::KEEP && meta.Remaining() > 0) {
        const auto network = meta.Peek();
        if (!network || *network != static_cast<uint8_t>(NetworkType::UDP)) {
            return false;
        }
        read_address = true;
    }

    if (read_address) {
        if (meta.Remaining() == 0) {
            return false;
        }
        const uint8_t network_raw = meta.ReadU8();
        if (!meta.Ok() ||
            (network_raw != static_cast<uint8_t>(NetworkType::TCP) &&
             network_raw != static_cast<uint8_t>(NetworkType::UDP))) {
            return false;
        }
        out.network = static_cast<NetworkType>(network_raw);
        out.has_target = true;
        const bool allow_metadata = out.status == SessionStatus::NEW;
        if (!ParsePortThenAddress(meta, out.target, out.forwarded, allow_metadata)) {
            return false;
        }

        if (out.status == SessionStatus::NEW &&
            out.network == NetworkType::UDP && meta.Remaining() == 8) {
            if (!meta.Skip(8)) {
                return false;
            }
            out.has_global_id = true;
        }
    }

    return meta.Ok() && meta.Remaining() == 0;
}

// prefix 必须是帧首至少 min(total_len, size_t{2} + meta_len + 2) 字节。
[[nodiscard]] std::optional<FrameHeader> DecodeFramePrefix(
    std::span<const uint8_t> prefix,
    size_t total_len) {
    if (prefix.size() < 2) {
        return std::nullopt;
    }

    const uint16_t meta_len = static_cast<uint16_t>(
        (static_cast<uint16_t>(prefix[0]) << 8) | prefix[1]);
    if (meta_len < 4 || meta_len > kMaxFrameMetadataBytes) {
        return FrameHeader{};
    }
    const size_t metadata_end = 2 + static_cast<size_t>(meta_len);
    if (prefix.size() < metadata_end) {
        return std::nullopt;
    }

    ByteReader meta(prefix.data() + 2, meta_len);
    FrameHeader out;
    if (!DecodeFrameMetadata(meta, out)) {
        return FrameHeader{};
    }

    size_t frame_size = metadata_end;
    if ((out.option & kOptionData) != 0) {
        if (prefix.size() < frame_size + 2) {
            return std::nullopt;
        }
        const uint16_t data_len = static_cast<uint16_t>(
            (static_cast<uint16_t>(prefix[frame_size]) << 8) | prefix[frame_size + 1]);
        frame_size += 2 + static_cast<size_t>(data_len);
        if (total_len < frame_size) {
            return std::nullopt;
        }
        out.has_data = true;
        out.data_len = data_len;
        out.data_offset = frame_size - data_len;
    }
    out.frame_size = frame_size;
    return out;
}

}  // namespace

std::optional<FrameHeader> DecodeFrame(const buf::MultiBuffer& data) {
    const size_t total_len = data.byte_size();
    if (total_len < 2) {
        return std::nullopt;
    }
    const auto front = data.FrontSpan();
    uint16_t meta_len = 0;
    if (front.size() >= 2) {
        meta_len = static_cast<uint16_t>(
            (static_cast<uint16_t>(front[0]) << 8) | front[1]);
    } else {
        std::array<uint8_t, 2> len_bytes{};
        if (data.CopyPrefixTo(len_bytes) < 2) {
            return std::nullopt;
        }
        meta_len = static_cast<uint16_t>(
            (static_cast<uint16_t>(len_bytes[0]) << 8) | len_bytes[1]);
    }
    if (meta_len < 4 || meta_len > kMaxFrameMetadataBytes) {
        return FrameHeader{};
    }
    const size_t needed_prefix = std::min(total_len, size_t{2} + meta_len + 2);
    if (front.size() >= needed_prefix) {
        return DecodeFramePrefix(front, total_len);
    }
    std::array<uint8_t, kMaxFramePrefixBytes> prefix{};
    const size_t copied = data.CopyPrefixTo(
        std::span<uint8_t>(prefix.data(), needed_prefix));
    return DecodeFramePrefix(std::span<const uint8_t>(prefix.data(), copied), total_len);
}

// ============================================================================
// 内部：将 PortThenAddress 写入 buf
// ============================================================================
[[nodiscard]] static size_t WriteFrameBase(
    std::span<uint8_t> out,
    uint16_t session_id,
    SessionStatus status,
    uint8_t option) noexcept {
    if (out.size() < 6) {
        return 0;
    }
    out[0] = 0;
    out[1] = 0;
    out[2] = static_cast<uint8_t>(session_id >> 8);
    out[3] = static_cast<uint8_t>(session_id & 0xFF);
    out[4] = static_cast<uint8_t>(status);
    out[5] = option;
    return 6;
}

[[nodiscard]] static size_t FinalizeFrameHeaderSpan(
    std::span<uint8_t> out,
    size_t meta_end,
    size_t payload_len,
    bool has_data) noexcept {
    constexpr size_t kMaxWireLength = std::numeric_limits<uint16_t>::max();
    if (meta_end < 2 || meta_end - 2 > kMaxWireLength ||
        payload_len > kMaxWireLength) {
        return 0;
    }
    const size_t total_len = meta_end + (has_data ? 2 : 0);
    if (out.size() < total_len) {
        return 0;
    }
    const uint16_t meta_len = static_cast<uint16_t>(meta_end - 2);
    out[0] = static_cast<uint8_t>(meta_len >> 8);
    out[1] = static_cast<uint8_t>(meta_len & 0xFF);
    if (has_data) {
        out[meta_end] = static_cast<uint8_t>(payload_len >> 8);
        out[meta_end + 1] = static_cast<uint8_t>(payload_len & 0xFF);
    }
    return total_len;
}

// ============================================================================
// EncodeKeepAlive
// ============================================================================
size_t EncodeKeepAliveTo(std::span<uint8_t> out) noexcept {
    if (out.size() < 6) {
        return 0;
    }
    out[0] = 0x00;
    out[1] = 0x04;
    out[2] = 0x00;
    out[3] = 0x00;
    out[4] = static_cast<uint8_t>(SessionStatus::KEEPALIVE);
    out[5] = 0x00;
    return 6;
}

size_t EncodeNewHeaderTo(std::span<uint8_t> out,
                         uint16_t session_id,
                         NetworkType network,
                         const TargetAddress& target,
                         size_t payload_len,
                         bool has_data,
                         ForwardedMetadataView forwarded) noexcept {
    if ((network != NetworkType::TCP && network != NetworkType::UDP) ||
        payload_len > std::numeric_limits<uint16_t>::max() ||
        (!has_data && payload_len != 0) ||
        !target.IsValid()) {
        return 0;
    }
    size_t pos = WriteFrameBase(
        out,
        session_id,
        SessionStatus::NEW,
        has_data ? kOptionData : 0x00);
    if (pos == 0 || out.size() < pos + 1) {
        return 0;
    }
    out[pos++] = static_cast<uint8_t>(network);
    const size_t addr_len = EncodeAddressTo(
        target,
        out.data() + pos,
        out.size() - pos,
        AddressWireFormat::PortFirst,
        forwarded);
    if (addr_len == 0) {
        return 0;
    }
    pos += addr_len;
    return FinalizeFrameHeaderSpan(out, pos, payload_len, has_data);
}

// ============================================================================
// EncodeEnd
// ============================================================================
size_t EncodeEndTo(std::span<uint8_t> out,
                   uint16_t session_id,
                   bool error) noexcept {
    const uint8_t option = error ? kOptionError : 0x00;
    const size_t pos = WriteFrameBase(out, session_id, SessionStatus::END, option);
    if (pos == 0) {
        return 0;
    }
    return FinalizeFrameHeaderSpan(out, pos, 0, false);
}

// ============================================================================
// EncodeKeepDataHeaderTo（TCP 数据帧头）
// ============================================================================
size_t EncodeKeepDataHeaderTo(std::span<uint8_t> out,
                              uint16_t session_id,
                              size_t payload_len) noexcept {
    if (payload_len > std::numeric_limits<uint16_t>::max()) {
        return 0;
    }
    const size_t pos = WriteFrameBase(
        out, session_id, SessionStatus::KEEP, kOptionData);
    if (pos == 0) {
        return 0;
    }
    return FinalizeFrameHeaderSpan(out, pos, payload_len, true);
}

// ============================================================================
// EncodeKeepUDPHeaderTo（UDP 回包帧头，携带源地址）
// ============================================================================
size_t EncodeKeepUDPHeaderTo(std::span<uint8_t> out,
                             uint16_t session_id,
                             const TargetAddress& src,
                             size_t payload_len) noexcept {
    if (payload_len > std::numeric_limits<uint16_t>::max() ||
        !src.IsValid()) {
        return 0;
    }
    size_t pos = WriteFrameBase(
        out, session_id, SessionStatus::KEEP, kOptionData);
    if (pos == 0 || out.size() < pos + 1) {
        return 0;
    }
    out[pos++] = static_cast<uint8_t>(NetworkType::UDP);
    const size_t addr_len = EncodeAddressTo(
        src,
        out.data() + pos,
        out.size() - pos,
        AddressWireFormat::PortFirst);
    if (addr_len == 0) {
        return 0;
    }
    pos += addr_len;
    return FinalizeFrameHeaderSpan(out, pos, payload_len, true);
}

}  // namespace mux
