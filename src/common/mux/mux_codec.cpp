#include "acppnode/common/mux/mux_codec.hpp"
#include "acppnode/common/byte_reader.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>

namespace acpp::mux {

// ============================================================================
// 地址类型转换
// ============================================================================

uint8_t ToMuxAddrType(AddressType t) noexcept {
    switch (t) {
        case AddressType::IPv4:   return 1;
        case AddressType::Domain: return 2;
        case AddressType::IPv6:   return 3;
        default:                  return 0;
    }
}

// ============================================================================
// 内部：解析 PortThenAddress（Mux 线上格式）
// 返回解析是否成功；成功时填入 target
// ============================================================================
static bool ParsePortThenAddress(ByteReader& r, TargetAddress& target) {
    uint16_t port     = r.ReadU16BE();
    uint8_t  addr_raw = r.ReadU8();
    if (!r.Ok()) return false;

    if (addr_raw == 1) {
        // IPv4: 4 字节
        auto span = r.ReadBytes(4);
        if (!r.Ok()) return false;
        net::ip::address_v4::bytes_type bytes;
        std::memcpy(bytes.data(), span.data(), 4);
        auto addr = net::ip::make_address_v4(bytes);
        target = TargetAddress(addr, port);

    } else if (addr_raw == 2) {
        // Domain: 1 字节长度 + N 字节域名
        uint8_t domain_len = r.ReadU8();
        if (!r.Ok()) return false;
        std::string_view domain = r.ReadStringView(domain_len);
        if (!r.Ok()) return false;
        target = TargetAddress(domain, port);

    } else if (addr_raw == 3) {
        // IPv6: 16 字节
        auto span = r.ReadBytes(16);
        if (!r.Ok()) return false;
        net::ip::address_v6::bytes_type bytes;
        std::memcpy(bytes.data(), span.data(), 16);
        auto addr = net::ip::make_address_v6(bytes);
        target = TargetAddress(addr, port);
    } else {
        return false;
    }

    return target.IsValid();
}

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

    [[nodiscard]] std::string ReadString(size_t len) {
        std::string out(len, '\0');
        if (len == 0) {
            return out;
        }
        if (!ReadBytes(std::span<uint8_t>(
                reinterpret_cast<uint8_t*>(out.data()), out.size()))) {
            return {};
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

static bool ParsePortThenAddress(MultiBufferFrameReader& r, TargetAddress& target) {
    uint16_t port = r.ReadU16BE();
    uint8_t addr_raw = r.ReadU8();
    if (!r.Ok()) return false;

    if (addr_raw == 1) {
        net::ip::address_v4::bytes_type bytes{};
        if (!r.ReadBytes(std::span<uint8_t>(bytes.data(), bytes.size()))) return false;
        target = TargetAddress(net::ip::make_address_v4(bytes), port);
        return target.IsValid();
    }
    if (addr_raw == 2) {
        uint8_t domain_len = r.ReadU8();
        if (!r.Ok()) return false;
        std::string domain = r.ReadString(domain_len);
        if (!r.Ok()) return false;
        target = TargetAddress(std::string_view(domain), port);
        return target.IsValid();
    }
    if (addr_raw == 3) {
        net::ip::address_v6::bytes_type bytes{};
        if (!r.ReadBytes(std::span<uint8_t>(bytes.data(), bytes.size()))) return false;
        target = TargetAddress(net::ip::make_address_v6(bytes), port);
        return target.IsValid();
    }
    return false;
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

std::optional<FrameHeader> DecodeFrame(const uint8_t* data, size_t len) {
    if (!data || len < 2) {
        return std::nullopt;
    }

    const uint16_t meta_len =
        (static_cast<uint16_t>(data[0]) << 8) |
        static_cast<uint16_t>(data[1]);
    if (meta_len < 4) {
        return InvalidFrame();
    }
    if (len < static_cast<size_t>(2 + meta_len)) {
        return std::nullopt;
    }

    ByteReader meta(data + 2, meta_len);
    FrameHeader out;
    if (!DecodeFrameMetadata(meta, out)) {
        return InvalidFrame();
    }

    size_t frame_size = 2 + meta_len;
    if ((out.option & kOptionData) != 0) {
        if (len < frame_size + 2) {
            return std::nullopt;
        }
        const uint16_t data_len =
            (static_cast<uint16_t>(data[frame_size]) << 8) |
            static_cast<uint16_t>(data[frame_size + 1]);
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
template <class ByteContainer>
static bool AppendAddress(ByteContainer& buf, const TargetAddress& addr) {
    if (!addr.IsValid() ||
        (addr.IsDomain() && addr.host.size() > std::numeric_limits<uint8_t>::max())) {
        return false;
    }

    // Port (2 BE)
    buf.push_back(static_cast<uint8_t>(addr.port >> 8));
    buf.push_back(static_cast<uint8_t>(addr.port & 0xFF));

    uint8_t atype = ToMuxAddrType(addr.type);
    buf.push_back(atype);

    switch (addr.type) {
    case AddressType::IPv4: {
        if (addr.resolved_addr && addr.resolved_addr->is_v4()) {
            auto bytes = addr.resolved_addr->to_v4().to_bytes();
            buf.insert(buf.end(), bytes.begin(), bytes.end());
        } else {
            return false;
        }
        break;
    }
    case AddressType::Domain: {
        uint8_t dlen = static_cast<uint8_t>(addr.host.size());
        buf.push_back(dlen);
        buf.insert(buf.end(), addr.host.begin(), addr.host.begin() + dlen);
        break;
    }
    case AddressType::IPv6: {
        if (addr.resolved_addr && addr.resolved_addr->is_v6()) {
            auto bytes = addr.resolved_addr->to_v6().to_bytes();
            buf.insert(buf.end(), bytes.begin(), bytes.end());
        } else {
            return false;
        }
        break;
    }
    case AddressType::Invalid:
        return false;
    }
    return true;
}

static void InitFrameBase(
    auto& buf,
    uint16_t session_id,
    SessionStatus status,
    uint8_t option,
    size_t reserve_extra = 0)
{
    buf.clear();
    buf.reserve(8 + reserve_extra);

    // MetaLen 占位（稍后回填）
    buf.push_back(0);
    buf.push_back(0);
    // SessionID
    buf.push_back(static_cast<uint8_t>(session_id >> 8));
    buf.push_back(static_cast<uint8_t>(session_id & 0xFF));
    // Status
    buf.push_back(static_cast<uint8_t>(status));
    // Option
    buf.push_back(option);
}

// 回填 MetaLen（= buf.size() - 2）并按需追加 DataLen。
static bool FinalizeFrameHeader(
    auto& buf,
    size_t payload_len,
    bool has_data)
{
    constexpr size_t kMaxWireLength = std::numeric_limits<uint16_t>::max();
    if (buf.size() < 2 || buf.size() - 2 > kMaxWireLength ||
        payload_len > kMaxWireLength) {
        buf.clear();
        return false;
    }
    // 回填 MetaLen
    uint16_t meta_len = static_cast<uint16_t>(buf.size() - 2);
    buf[0] = static_cast<uint8_t>(meta_len >> 8);
    buf[1] = static_cast<uint8_t>(meta_len & 0xFF);

    if (has_data) {
        // DataLen
        buf.push_back(static_cast<uint8_t>(payload_len >> 8));
        buf.push_back(static_cast<uint8_t>(payload_len & 0xFF));
    }
    return true;
}

// 回填 MetaLen（= buf.size() - 2）并追加 DataLen + Payload
static bool FinalizeFrame(
    auto& buf,
    const uint8_t* payload,
    size_t payload_len,
    bool has_data)
{
    if (has_data && payload_len > 0 && !payload) {
        buf.clear();
        return false;
    }
    if (!FinalizeFrameHeader(buf, payload_len, has_data)) {
        return false;
    }

    if (has_data && payload_len > 0) {
        // Payload
        buf.insert(buf.end(), payload, payload + payload_len);
    }
    return true;
}

// ============================================================================
// EncodeKeepAlive
// ============================================================================
template <class ByteContainer>
static void EncodeKeepAliveToImpl(ByteContainer& out) {
    out.clear();
    out.reserve(6);
    out.push_back(0x00);
    out.push_back(0x04);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(static_cast<uint8_t>(SessionStatus::KEEPALIVE));
    out.push_back(0x00);
}

void EncodeKeepAliveTo(memory::ByteVector& out) {
    EncodeKeepAliveToImpl(out);
}

template <class ByteContainer>
static bool EncodeNewToImpl(ByteContainer& out,
                            uint16_t session_id,
                            NetworkType network,
                            const TargetAddress& target,
                            const uint8_t* data,
                            size_t len) {
    if ((network != NetworkType::TCP && network != NetworkType::UDP) ||
        len > std::numeric_limits<uint16_t>::max()) {
        out.clear();
        return false;
    }
    size_t addr_reserve = 1 + 2 + 1 + 16;
    if (target.IsDomain()) {
        addr_reserve = 1 + 2 + 1 + 1 + target.host.size();
    } else if (target.resolved_addr && target.resolved_addr->is_v4()) {
        addr_reserve = 1 + 2 + 1 + 4;
    }

    InitFrameBase(out, session_id, SessionStatus::NEW,
                  len > 0 ? kOptionData : 0x00,
                  addr_reserve + len);
    out.push_back(static_cast<uint8_t>(network));
    if (!AppendAddress(out, target)) {
        out.clear();
        return false;
    }
    return FinalizeFrame(out, data, len, len > 0);
}

bool EncodeNewTo(memory::ByteVector& out,
                 uint16_t session_id,
                 NetworkType network,
                 const TargetAddress& target,
                 const uint8_t* data,
                 size_t len) {
    return EncodeNewToImpl(out, session_id, network, target, data, len);
}

// ============================================================================
// EncodeEnd
// ============================================================================
template <class ByteContainer>
static void EncodeEndToImpl(ByteContainer& out, uint16_t session_id, bool error) {
    uint8_t option = error ? kOptionError : 0x00;
    InitFrameBase(out, session_id, SessionStatus::END, option);
    (void)FinalizeFrame(out, nullptr, 0, false);
}

void EncodeEndTo(memory::ByteVector& out, uint16_t session_id, bool error) {
    EncodeEndToImpl(out, session_id, error);
}

// ============================================================================
// EncodeKeepData（TCP 数据）
// ============================================================================
template <class ByteContainer>
static bool EncodeKeepDataToImpl(
    ByteContainer& out,
    uint16_t session_id,
    const uint8_t* data, size_t len)
{
    if (len > std::numeric_limits<uint16_t>::max()) {
        out.clear();
        return false;
    }
    InitFrameBase(out, session_id, SessionStatus::KEEP, kOptionData, len);
    return FinalizeFrame(out, data, len, true);
}

bool EncodeKeepDataTo(
    memory::ByteVector& out,
    uint16_t session_id,
    const uint8_t* data, size_t len)
{
    return EncodeKeepDataToImpl(out, session_id, data, len);
}

template <class ByteContainer>
static bool EncodeKeepDataHeaderToImpl(
    ByteContainer& out,
    uint16_t session_id,
    size_t payload_len)
{
    if (payload_len > std::numeric_limits<uint16_t>::max()) {
        out.clear();
        return false;
    }
    InitFrameBase(out, session_id, SessionStatus::KEEP, kOptionData, payload_len);
    return FinalizeFrameHeader(out, payload_len, true);
}

bool EncodeKeepDataHeaderTo(
    memory::ByteVector& out,
    uint16_t session_id,
    size_t payload_len)
{
    return EncodeKeepDataHeaderToImpl(out, session_id, payload_len);
}

// ============================================================================
// EncodeKeepUDP（UDP 回包，携带源地址）
// ============================================================================
template <class ByteContainer>
static bool EncodeKeepUDPToImpl(
    ByteContainer& out,
    uint16_t session_id,
    const TargetAddress& src,
    const uint8_t* data, size_t len)
{
    if (len > std::numeric_limits<uint16_t>::max()) {
        out.clear();
        return false;
    }
    // 预估地址字节数
    size_t addr_reserve = 3 + 4;  // NetworkType(1) + Port(2) + AddrType(1) + IPv4(4)
    InitFrameBase(out, session_id, SessionStatus::KEEP,
                  kOptionData, addr_reserve + len);

    // NetworkType = UDP
    out.push_back(static_cast<uint8_t>(NetworkType::UDP));
    // PortThenAddress
    if (!AppendAddress(out, src)) {
        out.clear();
        return false;
    }

    return FinalizeFrame(out, data, len, true);
}

bool EncodeKeepUDPTo(
    memory::ByteVector& out,
    uint16_t session_id,
    const TargetAddress& src,
    const uint8_t* data, size_t len)
{
    return EncodeKeepUDPToImpl(out, session_id, src, data, len);
}

template <class ByteContainer>
static bool EncodeKeepUDPHeaderToImpl(
    ByteContainer& out,
    uint16_t session_id,
    const TargetAddress& src,
    size_t payload_len)
{
    if (payload_len > std::numeric_limits<uint16_t>::max()) {
        out.clear();
        return false;
    }
    // 预估地址字节数
    size_t addr_reserve = 3 + 4;  // NetworkType(1) + Port(2) + AddrType(1) + IPv4(4)
    InitFrameBase(out, session_id, SessionStatus::KEEP,
                  kOptionData, addr_reserve + payload_len);

    // NetworkType = UDP
    out.push_back(static_cast<uint8_t>(NetworkType::UDP));
    // PortThenAddress
    if (!AppendAddress(out, src)) {
        out.clear();
        return false;
    }

    return FinalizeFrameHeader(out, payload_len, true);
}

bool EncodeKeepUDPHeaderTo(
    memory::ByteVector& out,
    uint16_t session_id,
    const TargetAddress& src,
    size_t payload_len)
{
    return EncodeKeepUDPHeaderToImpl(out, session_id, src, payload_len);
}

}  // namespace acpp::mux
