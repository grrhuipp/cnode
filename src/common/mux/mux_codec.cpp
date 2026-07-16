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

AddressType FromMuxAddrType(uint8_t t) noexcept {
    switch (t) {
        case 1: return AddressType::IPv4;
        case 2: return AddressType::Domain;
        case 3: return AddressType::IPv6;
        default: return AddressType::Invalid;
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

    AddressType addr_type = FromMuxAddrType(addr_raw);

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

    (void)addr_type;  // 已通过 addr_raw 分支处理
    return true;
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
        return true;
    }
    if (addr_raw == 2) {
        uint8_t domain_len = r.ReadU8();
        if (!r.Ok()) return false;
        std::string domain = r.ReadString(domain_len);
        if (!r.Ok()) return false;
        target = TargetAddress(std::string_view(domain), port);
        return true;
    }
    if (addr_raw == 3) {
        net::ip::address_v6::bytes_type bytes{};
        if (!r.ReadBytes(std::span<uint8_t>(bytes.data(), bytes.size()))) return false;
        target = TargetAddress(net::ip::make_address_v6(bytes), port);
        return true;
    }
    return false;
}

// ============================================================================
// DecodeFrame
// ============================================================================

std::optional<FrameHeader> DecodeFrame(const uint8_t* data, size_t len) {
    // 至少需要 2 字节 MetaLen
    if (len < 2) return std::nullopt;

    ByteReader r(data, len);

    uint16_t meta_len = r.ReadU16BE();
    if (!r.Ok()) return std::nullopt;

    // MetaLen 最小为 4（SessionID:2 + Status:1 + Option:1）
    if (meta_len < 4) {
        FrameHeader bad;
        bad.frame_size = 0;  // 非法帧
        return bad;
    }

    // 确保元数据全部可读
    if (len < static_cast<size_t>(2 + meta_len)) return std::nullopt;

    // 在元数据范围内创建子 reader
    ByteReader meta(data + 2, meta_len);

    uint16_t session_id = meta.ReadU16BE();
    uint8_t  status_raw = meta.ReadU8();
    uint8_t  option     = meta.ReadU8();
    if (!meta.Ok()) {
        FrameHeader bad; bad.frame_size = 0; return bad;
    }

    // 验证 Status 合法性
    if (status_raw < 1 || status_raw > 4) {
        FrameHeader bad; bad.frame_size = 0; return bad;
    }
    auto status = static_cast<SessionStatus>(status_raw);

    FrameHeader h;
    h.session_id = session_id;
    h.status     = status;
    h.option     = option;

    // 地址解析：New 帧，或 Keep 帧且元数据 > 4 且第 5 字节 == 0x02（UDP）
    bool read_address = false;
    if (status == SessionStatus::NEW) {
        read_address = true;
    } else if (status == SessionStatus::KEEP) {
        // Keep 帧仅 UDP 子会话携带地址：第 5 字节 = NetworkType = 0x02
        if (meta.Remaining() > 0) {
            auto peek = meta.Peek();
            if (peek && *peek == static_cast<uint8_t>(NetworkType::UDP)) {
                read_address = true;
            }
        }
    }

    if (read_address && meta.Remaining() > 0) {
        uint8_t net_raw = meta.ReadU8();
        if (!meta.Ok()) { FrameHeader bad; bad.frame_size = 0; return bad; }

        if (net_raw != 1 && net_raw != 2) {
            FrameHeader bad; bad.frame_size = 0; return bad;
        }

        h.network    = static_cast<NetworkType>(net_raw);
        h.has_target = true;

        if (!ParsePortThenAddress(meta, h.target)) {
            FrameHeader bad; bad.frame_size = 0; return bad;
        }

        // GlobalID：仅 New UDP 帧；元数据中地址之后恰好还剩 8 字节
        if (status == SessionStatus::NEW &&
            h.network == NetworkType::UDP &&
            meta.Remaining() >= 8)
        {
            auto gid_span = meta.ReadBytes(8);
            if (meta.Ok()) {
                h.has_global_id = true;
                std::memcpy(h.global_id.data(), gid_span.data(), 8);
            }
        }
    }

    // 计算帧总大小（元数据部分已固定，再加可选 DataLen+Payload）
    size_t frame_size = 2 + meta_len;  // MetaLen(2) + 元数据

    if (option & kOptionData) {
        // 需要再读 2 字节 DataLen
        if (len < frame_size + 2) return std::nullopt;  // DataLen 未到达
        uint16_t data_len =
            (static_cast<uint16_t>(data[frame_size]) << 8) |
             static_cast<uint16_t>(data[frame_size + 1]);
        frame_size += 2 + data_len;
        if (len < frame_size) return std::nullopt;      // Payload 未到达

        h.has_data = true;
        h.data_len = data_len;
        h.data_offset = frame_size - data_len;
    }

    h.frame_size = frame_size;
    return h;
}

std::optional<FrameHeader> DecodeFramePrefix(
    const uint8_t* data,
    size_t contiguous_len,
    size_t total_len) {
    if (!data || total_len < 2 || contiguous_len < 2) return std::nullopt;

    uint16_t meta_len =
        (static_cast<uint16_t>(data[0]) << 8) |
         static_cast<uint16_t>(data[1]);

    if (meta_len < 4) {
        FrameHeader bad;
        bad.frame_size = 0;
        return bad;
    }

    if (total_len < static_cast<size_t>(2 + meta_len)) return std::nullopt;
    if (contiguous_len < static_cast<size_t>(2 + meta_len)) return std::nullopt;

    ByteReader meta(data + 2, meta_len);

    uint16_t session_id = meta.ReadU16BE();
    uint8_t  status_raw = meta.ReadU8();
    uint8_t  option     = meta.ReadU8();
    if (!meta.Ok()) {
        FrameHeader bad; bad.frame_size = 0; return bad;
    }

    if (status_raw < 1 || status_raw > 4) {
        FrameHeader bad; bad.frame_size = 0; return bad;
    }
    auto status = static_cast<SessionStatus>(status_raw);

    FrameHeader h;
    h.session_id = session_id;
    h.status     = status;
    h.option     = option;

    bool read_address = false;
    if (status == SessionStatus::NEW) {
        read_address = true;
    } else if (status == SessionStatus::KEEP) {
        if (meta.Remaining() > 0) {
            auto peek = meta.Peek();
            if (peek && *peek == static_cast<uint8_t>(NetworkType::UDP)) {
                read_address = true;
            }
        }
    }

    if (read_address && meta.Remaining() > 0) {
        uint8_t net_raw = meta.ReadU8();
        if (!meta.Ok()) { FrameHeader bad; bad.frame_size = 0; return bad; }

        if (net_raw != 1 && net_raw != 2) {
            FrameHeader bad; bad.frame_size = 0; return bad;
        }

        h.network    = static_cast<NetworkType>(net_raw);
        h.has_target = true;

        if (!ParsePortThenAddress(meta, h.target)) {
            FrameHeader bad; bad.frame_size = 0; return bad;
        }

        if (status == SessionStatus::NEW &&
            h.network == NetworkType::UDP &&
            meta.Remaining() >= 8)
        {
            auto gid_span = meta.ReadBytes(8);
            if (meta.Ok()) {
                h.has_global_id = true;
                std::memcpy(h.global_id.data(), gid_span.data(), 8);
            }
        }
    }

    size_t frame_size = 2 + meta_len;

    if (option & kOptionData) {
        if (total_len < frame_size + 2) return std::nullopt;
        if (contiguous_len < frame_size + 2) return std::nullopt;
        uint16_t data_len =
            (static_cast<uint16_t>(data[frame_size]) << 8) |
             static_cast<uint16_t>(data[frame_size + 1]);
        frame_size += 2 + data_len;
        if (total_len < frame_size) return std::nullopt;

        h.has_data = true;
        h.data_len = data_len;
        h.data_offset = frame_size - data_len;
    }

    h.frame_size = frame_size;
    return h;
}

std::optional<FrameHeader> DecodeFrame(
    const buf::MultiBuffer& data,
    size_t offset,
    size_t len) {
    if (len < 2) return std::nullopt;

    MultiBufferFrameReader r(data, offset, len);
    uint16_t meta_len = r.ReadU16BE();
    if (!r.Ok()) return std::nullopt;

    if (meta_len < 4) {
        FrameHeader bad;
        bad.frame_size = 0;
        return bad;
    }

    if (len < static_cast<size_t>(2 + meta_len)) return std::nullopt;

    MultiBufferFrameReader meta(data, offset + 2, meta_len);
    uint16_t session_id = meta.ReadU16BE();
    uint8_t status_raw = meta.ReadU8();
    uint8_t option = meta.ReadU8();
    if (!meta.Ok()) {
        FrameHeader bad; bad.frame_size = 0; return bad;
    }

    if (status_raw < 1 || status_raw > 4) {
        FrameHeader bad; bad.frame_size = 0; return bad;
    }
    auto status = static_cast<SessionStatus>(status_raw);

    FrameHeader h;
    h.session_id = session_id;
    h.status = status;
    h.option = option;

    bool read_address = false;
    if (status == SessionStatus::NEW) {
        read_address = true;
    } else if (status == SessionStatus::KEEP) {
        if (meta.Remaining() > 0) {
            auto peek = meta.Peek();
            if (peek && *peek == static_cast<uint8_t>(NetworkType::UDP)) {
                read_address = true;
            }
        }
    }

    if (read_address && meta.Remaining() > 0) {
        uint8_t net_raw = meta.ReadU8();
        if (!meta.Ok()) { FrameHeader bad; bad.frame_size = 0; return bad; }
        if (net_raw != 1 && net_raw != 2) {
            FrameHeader bad; bad.frame_size = 0; return bad;
        }

        h.network = static_cast<NetworkType>(net_raw);
        h.has_target = true;

        if (!ParsePortThenAddress(meta, h.target)) {
            FrameHeader bad; bad.frame_size = 0; return bad;
        }

        if (status == SessionStatus::NEW &&
            h.network == NetworkType::UDP &&
            meta.Remaining() >= 8) {
            if (meta.ReadBytes(std::span<uint8_t>(h.global_id.data(), h.global_id.size())) &&
                meta.Ok()) {
                h.has_global_id = true;
            }
        }
    }

    size_t frame_size = 2 + meta_len;
    if (option & kOptionData) {
        if (len < frame_size + 2) return std::nullopt;
        MultiBufferFrameReader data_len_reader(data, offset + frame_size, 2);
        const uint16_t data_len = data_len_reader.ReadU16BE();
        if (!data_len_reader.Ok()) return std::nullopt;
        frame_size += 2 + data_len;
        if (len < frame_size) return std::nullopt;

        h.has_data = true;
        h.data_len = data_len;
        h.data_offset = frame_size - data_len;
    }

    h.frame_size = frame_size;
    return h;
}

// ============================================================================
// 内部：将 PortThenAddress 写入 buf
// ============================================================================
template <class ByteContainer>
static bool AppendAddress(ByteContainer& buf, const TargetAddress& addr) {
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
        uint8_t dlen = static_cast<uint8_t>(
            std::min(addr.host.size(), size_t{255}));
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
    if (len > std::numeric_limits<uint16_t>::max()) {
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
