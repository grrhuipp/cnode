#include "acppnode/common/mux/mux_codec.hpp"
#include "acppnode/common/byte_reader.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/address_codec.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>

namespace acpp::mux {


class MultiBufferFrameReader {
public:
    MultiBufferFrameReader(const buf::MultiBuffer& data, size_t offset, size_t size) noexcept
        : data_(data), offset_(offset), size_(size) {}

    [[nodiscard]] bool Ok() const noexcept { return !error_; }
    [[nodiscard]] size_t Remaining() const noexcept {
        return error_ || pos_ > size_ ? 0 : size_ - pos_;
    }
    [[nodiscard]] size_t Position() const noexcept { return pos_; }

    [[nodiscard]] uint8_t ReadU8() noexcept {
        uint8_t out = 0;
        if (!ReadBytes(std::span<uint8_t>(&out, 1))) {
            return 0;
        }
        return out;
    }

    [[nodiscard]] uint16_t ReadU16BE() noexcept {
        std::array<uint8_t, 2> bytes{};
        if (!ReadBytes(bytes)) {
            return 0;
        }
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(bytes[0]) << 8) |
            static_cast<uint16_t>(bytes[1]));
    }

    [[nodiscard]] std::optional<uint8_t> Peek() noexcept {
        if (!CanRead(1)) {
            return std::nullopt;
        }
        uint8_t out = 0;
        if (!CopyAt(offset_ + pos_, std::span<uint8_t>(&out, 1))) {
            return std::nullopt;
        }
        return out;
    }

    [[nodiscard]] bool ReadBytes(std::span<uint8_t> out) noexcept {
        if (!CanRead(out.size())) {
            return false;
        }
        if (!CopyAt(offset_ + pos_, out)) {
            error_ = true;
            return false;
        }
        pos_ += out.size();
        return true;
    }

private:
    [[nodiscard]] bool CanRead(size_t n) noexcept {
        if (error_ || pos_ + n > size_) {
            error_ = true;
            return false;
        }
        return true;
    }

    [[nodiscard]] bool CopyAt(size_t absolute_offset, std::span<uint8_t> out) const noexcept {
        size_t skip = absolute_offset;
        size_t copied = 0;
        for (const auto* buffer : data_) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            if (skip >= bytes.size()) {
                skip -= bytes.size();
                continue;
            }
            const size_t n = std::min(bytes.size() - skip, out.size() - copied);
            std::memcpy(out.data() + copied, bytes.data() + skip, n);
            copied += n;
            if (copied == out.size()) {
                return true;
            }
            skip = 0;
        }
        return copied == out.size();
    }

    const buf::MultiBuffer& data_;
    size_t offset_ = 0;
    size_t size_ = 0;
    size_t pos_ = 0;
    bool error_ = false;
};

static bool ParsePortThenAddress(ByteReader& reader, TargetAddress& target) {
    auto view = reader;
    auto decoded = DecodeAddress(view.ReadBytes(view.Remaining()),
                                 AddressWireFormat::PortFirst);
    if (decoded.status != AddressDecodeStatus::Complete ||
        !reader.Skip(decoded.consumed)) return false;
    target = std::move(decoded.target);
    return target.IsValid();
}

static bool ParsePortThenAddress(MultiBufferFrameReader& reader, TargetAddress& target) {
    std::array<uint8_t, kMaxEncodedAddressSize> bytes{};
    size_t size = 0;
    for (;;) {
        auto decoded = DecodeAddress(std::span<const uint8_t>(bytes.data(), size),
                                     AddressWireFormat::PortFirst);
        if (decoded.status == AddressDecodeStatus::Invalid) return false;
        if (decoded.status == AddressDecodeStatus::Complete) {
            target = std::move(decoded.target);
            return target.IsValid();
        }
        if (!reader.ReadBytes(std::span<uint8_t>(
                bytes.data() + size, decoded.required - size))) return false;
        size = decoded.required;
    }
}

// ============================================================================
// DecodeFrame
// ============================================================================

[[nodiscard]] static FrameHeader InvalidFrame() noexcept {
    return FrameHeader{};
}

[[nodiscard]] static bool ReadGlobalId(
    ByteReader& reader,
    std::array<uint8_t, 8>& out) noexcept {
    const auto bytes = reader.ReadBytes(out.size());
    if (!reader.Ok()) {
        return false;
    }
    std::memcpy(out.data(), bytes.data(), out.size());
    return true;
}

[[nodiscard]] static bool ReadGlobalId(
    MultiBufferFrameReader& reader,
    std::array<uint8_t, 8>& out) noexcept {
    return reader.ReadBytes(out) && reader.Ok();
}

template <typename Reader>
[[nodiscard]] bool DecodeFrameMetadata(Reader& meta, FrameHeader& out) {
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
        if (!ParsePortThenAddress(meta, out.target)) {
            return false;
        }

        if (out.status == SessionStatus::NEW &&
            out.network == NetworkType::UDP && meta.Remaining() == 8) {
            if (!ReadGlobalId(meta, out.global_id)) {
                return false;
            }
            out.has_global_id = true;
        }
    }

    return meta.Ok() && meta.Remaining() == 0;
}


std::optional<FrameHeader> DecodeFramePrefix(
    const uint8_t* data,
    size_t contiguous_len,
    size_t total_len) {
    if (!data || contiguous_len < 2 || total_len < 2) {
        return std::nullopt;
    }

    const uint16_t meta_len =
        (static_cast<uint16_t>(data[0]) << 8) |
        static_cast<uint16_t>(data[1]);
    if (meta_len < 4) {
        return InvalidFrame();
    }
    const size_t metadata_end = 2 + meta_len;
    if (total_len < metadata_end || contiguous_len < metadata_end) {
        return std::nullopt;
    }

    ByteReader meta(data + 2, meta_len);
    FrameHeader out;
    if (!DecodeFrameMetadata(meta, out)) {
        return InvalidFrame();
    }

    size_t frame_size = metadata_end;
    if ((out.option & kOptionData) != 0) {
        if (total_len < frame_size + 2 || contiguous_len < frame_size + 2) {
            return std::nullopt;
        }
        const uint16_t data_len =
            (static_cast<uint16_t>(data[frame_size]) << 8) |
            static_cast<uint16_t>(data[frame_size + 1]);
        frame_size += 2 + data_len;
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

std::optional<FrameHeader> DecodeFrame(
    const buf::MultiBuffer& data,
    size_t offset,
    size_t len) {
    if (len < 2) {
        return std::nullopt;
    }

    MultiBufferFrameReader frame_reader(data, offset, len);
    const uint16_t meta_len = frame_reader.ReadU16BE();
    if (!frame_reader.Ok()) {
        return std::nullopt;
    }
    if (meta_len < 4) {
        return InvalidFrame();
    }
    if (len < static_cast<size_t>(2 + meta_len)) {
        return std::nullopt;
    }

    MultiBufferFrameReader meta(data, offset + 2, meta_len);
    FrameHeader out;
    if (!DecodeFrameMetadata(meta, out)) {
        return InvalidFrame();
    }

    size_t frame_size = 2 + meta_len;
    if ((out.option & kOptionData) != 0) {
        if (len < frame_size + 2) {
            return std::nullopt;
        }
        MultiBufferFrameReader data_len_reader(data, offset + frame_size, 2);
        const uint16_t data_len = data_len_reader.ReadU16BE();
        if (!data_len_reader.Ok()) {
            return std::nullopt;
        }
        frame_size += 2 + data_len;
        if (len < frame_size) {
            return std::nullopt;
        }
        out.has_data = true;
        out.data_len = data_len;
        out.data_offset = frame_size - data_len;
    }
    out.frame_size = frame_size;
    return out;
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

void EncodeKeepAliveTo(memory::ByteVector& out) {
    std::array<uint8_t, 6> header{};
    const size_t n = EncodeKeepAliveTo(header);
    out.assign(header.data(), header.data() + n);
}

size_t EncodeNewHeaderTo(std::span<uint8_t> out,
                         uint16_t session_id,
                         NetworkType network,
                         const TargetAddress& target,
                         size_t payload_len) noexcept {
    if ((network != NetworkType::TCP && network != NetworkType::UDP) ||
        payload_len > std::numeric_limits<uint16_t>::max() ||
        !target.IsValid()) {
        return 0;
    }
    size_t pos = WriteFrameBase(
        out,
        session_id,
        SessionStatus::NEW,
        payload_len > 0 ? kOptionData : 0x00);
    if (pos == 0 || out.size() < pos + 1) {
        return 0;
    }
    out[pos++] = static_cast<uint8_t>(network);
    const size_t addr_len = EncodeAddressTo(
        target,
        out.data() + pos,
        out.size() - pos,
        AddressWireFormat::PortFirst);
    if (addr_len == 0) {
        return 0;
    }
    pos += addr_len;
    return FinalizeFrameHeaderSpan(out, pos, payload_len, payload_len > 0);
}

bool EncodeNewHeaderTo(memory::ByteVector& out,
                       uint16_t session_id,
                       NetworkType network,
                       const TargetAddress& target,
                       size_t payload_len) {
    std::array<uint8_t, kMaxFrameHeaderBytes> header{};
    const size_t n = EncodeNewHeaderTo(
        header, session_id, network, target, payload_len);
    if (n == 0) {
        out.clear();
        return false;
    }
    out.assign(header.data(), header.data() + n);
    return true;
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

void EncodeEndTo(memory::ByteVector& out, uint16_t session_id, bool error) {
    std::array<uint8_t, 6> header{};
    const size_t n = EncodeEndTo(header, session_id, error);
    out.assign(header.data(), header.data() + n);
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

bool EncodeKeepDataHeaderTo(
    memory::ByteVector& out,
    uint16_t session_id,
    size_t payload_len) {
    std::array<uint8_t, 8> header{};
    const size_t n = EncodeKeepDataHeaderTo(header, session_id, payload_len);
    if (n == 0) {
        out.clear();
        return false;
    }
    out.assign(header.data(), header.data() + n);
    return true;
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

bool EncodeKeepUDPHeaderTo(
    memory::ByteVector& out,
    uint16_t session_id,
    const TargetAddress& src,
    size_t payload_len) {
    std::array<uint8_t, kMaxFrameHeaderBytes> header{};
    const size_t n = EncodeKeepUDPHeaderTo(
        header, session_id, src, payload_len);
    if (n == 0) {
        out.clear();
        return false;
    }
    out.assign(header.data(), header.data() + n);
    return true;
}
}  // namespace acpp::mux
