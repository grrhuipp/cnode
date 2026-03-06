#include "acppnode/transport/proxy_protocol.hpp"
#include "acppnode/infra/log.hpp"

#include <charconv>
#include <cstdio>
#include <cstring>

namespace acpp {

namespace {

bool PrefixMatches(const uint8_t* data, size_t len, const uint8_t* prefix, size_t prefix_len) {
    return len <= prefix_len && std::memcmp(data, prefix, len) == 0;
}

ProxyProtocolResult MakeIncomplete() {
    ProxyProtocolResult result;
    result.status = ProxyProtocolParseStatus::Incomplete;
    return result;
}

ProxyProtocolResult MakeInvalid() {
    ProxyProtocolResult result;
    result.status = ProxyProtocolParseStatus::Invalid;
    return result;
}

}  // namespace

// ============================================================================
// PROXY Protocol v1 格式：
//   "PROXY TCP4 192.168.1.1 10.0.0.1 12345 80\r\n"
//   "PROXY TCP6 ::1 ::1 12345 80\r\n"
//   "PROXY UNKNOWN\r\n"
//
// PROXY Protocol v2 格式（二进制）：
//   [12字节签名][版本+命令][族+协议][长度][地址]
// ============================================================================

// ----------------------------------------------------------------------------
// 自动检测 v1/v2
// ----------------------------------------------------------------------------
ProxyProtocolResult ProxyProtocolParser::Parse(const uint8_t* data, size_t len) {
    if (len == 0) {
        return {};
    }

    if (PrefixMatches(data, len, kSignatureV2, sizeof(kSignatureV2))) {
        if (len < sizeof(kSignatureV2)) {
            return MakeIncomplete();
        }
    }

    static constexpr char kProxyPrefix[] = "PROXY ";
    if (PrefixMatches(data, len, reinterpret_cast<const uint8_t*>(kProxyPrefix), sizeof(kProxyPrefix) - 1)) {
        if (len < sizeof(kProxyPrefix) - 1) {
            return MakeIncomplete();
        }
    }

    // v2：以固定 12 字节签名开头
    if (len >= 12 && std::memcmp(data, kSignatureV2, 12) == 0) {
        LOG_ACCESS_DEBUG("[ProxyProtocol] detected v2 binary header ({} bytes)", len);
        auto r = ParseV2(data, len);
        if (r.success()) {
            LOG_ACCESS_DEBUG("[ProxyProtocol] v2 parsed: src={}:{} consumed={}",
                      r.src_ip, r.src_port, r.consumed);
        } else if (r.incomplete()) {
            LOG_ACCESS_DEBUG("[ProxyProtocol] v2 parse incomplete");
        } else {
            LOG_ACCESS_DEBUG("[ProxyProtocol] v2 parse failed (incomplete or invalid)");
        }
        return r;
    }

    // v1：以 "PROXY " 开头
    if (len >= 6 && std::memcmp(data, "PROXY ", 6) == 0) {
        LOG_ACCESS_DEBUG("[ProxyProtocol] detected v1 text header");
        auto r = ParseV1(data, len);
        if (r.success()) {
            LOG_ACCESS_DEBUG("[ProxyProtocol] v1 parsed: src={}:{} consumed={}",
                      r.src_ip, r.src_port, r.consumed);
        } else if (r.incomplete()) {
            LOG_ACCESS_DEBUG("[ProxyProtocol] v1 parse incomplete");
        } else {
            LOG_ACCESS_DEBUG("[ProxyProtocol] v1 parse failed (malformed or incomplete)");
        }
        return r;
    }

    // 不是 PROXY Protocol，返回 success=false
    return {};
}

// ----------------------------------------------------------------------------
// v1 解析（文本格式）
// ----------------------------------------------------------------------------
ProxyProtocolResult ProxyProtocolParser::ParseV1(const uint8_t* data, size_t len) {
    // 找 \r\n 结尾
    const uint8_t* crlf = nullptr;
    for (size_t i = 0; i + 1 < len; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            crlf = data + i;
            break;
        }
    }

    if (!crlf) {
        // 数据不完整，等待更多数据
        return MakeIncomplete();
    }

    // 把首行转成 string_view 来解析
    std::string_view line(reinterpret_cast<const char*>(data),
                          static_cast<size_t>(crlf - data));

    // 跳过 "PROXY "
    if (line.size() < 6) return MakeInvalid();
    line.remove_prefix(6);

    // 解析协议族："TCP4"/"TCP6"/"UNKNOWN"
    auto sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) return MakeInvalid();
    std::string_view family = line.substr(0, sp1);
    line.remove_prefix(sp1 + 1);

    if (family == "UNKNOWN") {
        // UNKNOWN：连接合法但不携带地址信息，回退到直连 IP
        ProxyProtocolResult r;
        r.status   = ProxyProtocolParseStatus::Success;
        r.consumed = static_cast<size_t>(crlf - data) + 2;  // +2 for \r\n
        return r;
    }

    if (family != "TCP4" && family != "TCP6") return MakeInvalid();

    // src_ip
    auto sp2 = line.find(' ');
    if (sp2 == std::string_view::npos) return MakeInvalid();
    std::string src_ip(line.substr(0, sp2));
    line.remove_prefix(sp2 + 1);

    // dst_ip（忽略）
    auto sp3 = line.find(' ');
    if (sp3 == std::string_view::npos) return MakeInvalid();
    line.remove_prefix(sp3 + 1);

    // src_port
    auto sp4 = line.find(' ');
    if (sp4 == std::string_view::npos) return MakeInvalid();
    std::string_view src_port_sv = line.substr(0, sp4);

    uint16_t src_port = 0;
    auto [ptr, ec] = std::from_chars(
        src_port_sv.data(), src_port_sv.data() + src_port_sv.size(), src_port);
    if (ec != std::errc{}) return MakeInvalid();

    ProxyProtocolResult r;
    r.status   = ProxyProtocolParseStatus::Success;
    r.src_ip   = std::move(src_ip);
    r.src_port = src_port;
    r.consumed = static_cast<size_t>(crlf - data) + 2;
    return r;
}

// ----------------------------------------------------------------------------
// v2 解析（二进制格式）
//
// 头部布局（16 字节固定）：
//   [0..11]  签名 (12B)
//   [12]     版本 (高 4 位) + 命令 (低 4 位)
//   [13]     地址族 (高 4 位) + 协议 (低 4 位)
//   [14..15] 附加长度 (大端 uint16)
//
// 命令：0=LOCAL, 1=PROXY
// 地址族：0=UNSPEC, 1=INET(IPv4), 2=INET6(IPv6), 3=UNIX
// 协议：0=UNSPEC, 1=STREAM(TCP), 2=DGRAM(UDP)
//
// 附加数据（INET）：src(4B)+dst(4B)+src_port(2B)+dst_port(2B) = 12B
// 附加数据（INET6）：src(16B)+dst(16B)+src_port(2B)+dst_port(2B) = 36B
// ----------------------------------------------------------------------------
ProxyProtocolResult ProxyProtocolParser::ParseV2(const uint8_t* data, size_t len) {
    constexpr size_t kHeaderSize = 16;
    if (len < kHeaderSize) return MakeIncomplete();

    const uint8_t ver_cmd = data[12];
    const uint8_t fam_proto = data[13];
    const uint16_t extra_len =
        static_cast<uint16_t>((data[14] << 8) | data[15]);

    const size_t total = kHeaderSize + extra_len;
    if (len < total) return MakeIncomplete();

    const uint8_t version = (ver_cmd >> 4) & 0x0F;
    const uint8_t command = ver_cmd & 0x0F;

    if (version != 2) return MakeInvalid();

    ProxyProtocolResult r;
    r.consumed = total;
    r.status   = ProxyProtocolParseStatus::Success;

    // LOCAL 命令（健康检查等）：不携带地址，直接通过
    if (command == 0x00) {
        return r;
    }

    // 只处理 PROXY 命令
    if (command != 0x01) return MakeInvalid();

    const uint8_t family = (fam_proto >> 4) & 0x0F;
    // const uint8_t proto = fam_proto & 0x0F;  // TCP/UDP，此处不需要区分

    const uint8_t* addr = data + kHeaderSize;

    if (family == 0x01) {
        // IPv4：src(4) + dst(4) + src_port(2) + dst_port(2) = 12B
        if (extra_len < 12) return MakeInvalid();
        // 手动格式化避免跨平台 inet_ntop 依赖
        r.src_ip = std::to_string(addr[0]) + '.' +
                   std::to_string(addr[1]) + '.' +
                   std::to_string(addr[2]) + '.' +
                   std::to_string(addr[3]);
        r.src_port = static_cast<uint16_t>((addr[8] << 8) | addr[9]);

    } else if (family == 0x02) {
        // IPv6：src(16) + dst(16) + src_port(2) + dst_port(2) = 36B
        if (extra_len < 36) return MakeInvalid();

        // 格式化 IPv6（简单的全展开形式，不做 :: 压缩）
        char buf[40];
        std::snprintf(buf, sizeof(buf),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr[0], addr[1], addr[2],  addr[3],
            addr[4], addr[5], addr[6],  addr[7],
            addr[8], addr[9], addr[10], addr[11],
            addr[12],addr[13],addr[14], addr[15]);
        r.src_ip   = buf;
        r.src_port = static_cast<uint16_t>((addr[32] << 8) | addr[33]);

    }
    // UNIX 套接字（family==3）：不携带网络地址，保持 src_ip 为空

    return r;
}

}  // namespace acpp
