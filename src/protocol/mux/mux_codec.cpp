#include "acppnode/protocol/mux/mux_codec.hpp"
#include "acppnode/common/byte_reader.hpp"

#include <cstring>

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
        default: return AddressType::IPv4;
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
        boost::asio::ip::address_v4::bytes_type bytes;
        std::memcpy(bytes.data(), span.data(), 4);
        auto addr = boost::asio::ip::make_address_v4(bytes);
        target.type         = AddressType::IPv4;
        target.host         = addr.to_string();
        target.resolved_addr = addr;
        target.port         = port;

    } else if (addr_raw == 2) {
        // Domain: 1 字节长度 + N 字节域名
        uint8_t domain_len = r.ReadU8();
        if (!r.Ok()) return false;
        std::string domain = r.ReadString(domain_len);
        if (!r.Ok()) return false;
        target.type = AddressType::Domain;
        target.host = std::move(domain);
        target.port = port;

    } else if (addr_raw == 3) {
        // IPv6: 16 字节
        auto span = r.ReadBytes(16);
        if (!r.Ok()) return false;
        boost::asio::ip::address_v6::bytes_type bytes;
        std::memcpy(bytes.data(), span.data(), 16);
        auto addr = boost::asio::ip::make_address_v6(bytes);
        target.type         = AddressType::IPv6;
        target.host         = addr.to_string();
        target.resolved_addr = addr;
        target.port         = port;

    } else {
        return false;
    }

    (void)addr_type;  // 已通过 addr_raw 分支处理
    return true;
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
            meta.Remaining() == 8)
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
    }

    h.frame_size = frame_size;
    return h;
}

// ============================================================================
// 内部：将 PortThenAddress 写入 buf（vector append）
// ============================================================================
static void AppendAddress(std::vector<uint8_t>& buf, const TargetAddress& addr) {
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
            boost::system::error_code ec;
            auto a = boost::asio::ip::make_address_v4(addr.host, ec);
            if (!ec) {
                auto bytes = a.to_bytes();
                buf.insert(buf.end(), bytes.begin(), bytes.end());
            } else {
                // fallback: 4 零字节（不应发生）
                buf.insert(buf.end(), 4, 0);
            }
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
            boost::system::error_code ec;
            auto a = boost::asio::ip::make_address_v6(addr.host, ec);
            if (!ec) {
                auto bytes = a.to_bytes();
                buf.insert(buf.end(), bytes.begin(), bytes.end());
            } else {
                buf.insert(buf.end(), 16, 0);
            }
        }
        break;
    }
    }
}

// ============================================================================
// 内部：构建通用帧（不含地址，不含数据）
// 返回 buf，MetaLen 位于 [0..1]，元数据从 [2] 开始
// ============================================================================
static std::vector<uint8_t> MakeFrameBase(
    uint16_t session_id,
    SessionStatus status,
    uint8_t option,
    size_t reserve_extra = 0)
{
    std::vector<uint8_t> buf;
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
    return buf;
}

static void InitFrameBase(
    std::vector<uint8_t>& buf,
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

// 回填 MetaLen（= buf.size() - 2）并追加 DataLen + Payload
static void FinalizeFrame(
    std::vector<uint8_t>& buf,
    const uint8_t* payload, size_t payload_len)
{
    // 回填 MetaLen
    uint16_t meta_len = static_cast<uint16_t>(buf.size() - 2);
    buf[0] = static_cast<uint8_t>(meta_len >> 8);
    buf[1] = static_cast<uint8_t>(meta_len & 0xFF);

    if (payload && payload_len > 0) {
        // DataLen
        buf.push_back(static_cast<uint8_t>(payload_len >> 8));
        buf.push_back(static_cast<uint8_t>(payload_len & 0xFF));
        // Payload
        buf.insert(buf.end(), payload, payload + payload_len);
    }
}

// ============================================================================
// EncodeKeepAlive
// ============================================================================
void EncodeKeepAliveTo(std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(6);
    out.push_back(0x00);
    out.push_back(0x04);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(static_cast<uint8_t>(SessionStatus::KEEPALIVE));
    out.push_back(0x00);
}

std::vector<uint8_t> EncodeKeepAlive() {
    std::vector<uint8_t> buf;
    EncodeKeepAliveTo(buf);
    return buf;
}

// ============================================================================
// EncodeEnd
// ============================================================================
void EncodeEndTo(std::vector<uint8_t>& out, uint16_t session_id, bool error) {
    uint8_t option = error ? kOptionError : 0x00;
    InitFrameBase(out, session_id, SessionStatus::END, option);
    FinalizeFrame(out, nullptr, 0);
}

std::vector<uint8_t> EncodeEnd(uint16_t session_id, bool error) {
    auto buf = MakeFrameBase(session_id, SessionStatus::END,
                             error ? kOptionError : 0x00);
    FinalizeFrame(buf, nullptr, 0);
    return buf;
}

// ============================================================================
// EncodeKeepData（TCP 数据）
// ============================================================================
void EncodeKeepDataTo(
    std::vector<uint8_t>& out,
    uint16_t session_id,
    const uint8_t* data, size_t len)
{
    InitFrameBase(out, session_id, SessionStatus::KEEP, kOptionData, len);
    FinalizeFrame(out, data, len);
}

std::vector<uint8_t> EncodeKeepData(
    uint16_t session_id,
    const uint8_t* data, size_t len)
{
    auto buf = MakeFrameBase(session_id, SessionStatus::KEEP, kOptionData, len);
    FinalizeFrame(buf, data, len);
    return buf;
}

// ============================================================================
// EncodeKeepUDP（UDP 回包，携带源地址）
// ============================================================================
void EncodeKeepUDPTo(
    std::vector<uint8_t>& out,
    uint16_t session_id,
    const TargetAddress& src,
    const uint8_t* data, size_t len)
{
    // 预估地址字节数
    size_t addr_reserve = 3 + 16;  // NetworkType(1) + Port(2) + AddrType(1) + IPv6(16)
    InitFrameBase(out, session_id, SessionStatus::KEEP,
                  kOptionData, addr_reserve + len);

    // NetworkType = UDP
    out.push_back(static_cast<uint8_t>(NetworkType::UDP));
    // PortThenAddress
    AppendAddress(out, src);

    FinalizeFrame(out, data, len);
}

std::vector<uint8_t> EncodeKeepUDP(
    uint16_t session_id,
    const TargetAddress& src,
    const uint8_t* data, size_t len)
{
    std::vector<uint8_t> buf;
    EncodeKeepUDPTo(buf, session_id, src, data, len);
    return buf;
}

}  // namespace acpp::mux
