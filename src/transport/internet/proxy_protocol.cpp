#include "transport/internet/proxy_protocol.hpp"
#include "common/ip_address.hpp"
#include "infra/log.hpp"
#include "common/ip_utils.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string_view>


namespace {

constexpr uint8_t kSignatureV2[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

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

void LogProxySource(std::string_view version, const ProxyProtocolResult& result) {
    if (!Log::ShouldLog(LogLevel::DEBUG)) return;
    std::optional<iputil::AddressText> numeric;
    std::string_view source = "-";
    if (result.src_addr) {
        numeric.emplace(*result.src_addr);
        source = numeric->View();
    }
    LOG_NET_DEBUG("PROXY protocol {} parsed src={}:{} consumed={}",
                  version, source, result.src_port, result.consumed);
}

bool ParsePort(std::string_view text, uint16_t& port) {
    uint32_t value = 0;
    const char* first = text.data();
    const char* last = text.data() + text.size();
    auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc{} || ptr != last || value > 65535) {
        return false;
    }
    port = static_cast<uint16_t>(value);
    return true;
}

// ============================================================================
// PROXY Protocol v1 格式：
//   "PROXY TCP4 192.168.1.1 10.0.0.1 12345 80\r\n"
//   "PROXY UNKNOWN\r\n"
//
// PROXY Protocol v2 格式（二进制）：
//   [12字节签名][版本+命令][族+协议][长度][地址]
// ============================================================================

// ----------------------------------------------------------------------------
// v1 解析（文本格式）
// ----------------------------------------------------------------------------
ProxyProtocolResult ParseV1(const uint8_t* data, size_t len) {
    // Spec §2.1: the whole line, CRLF included, fits in 107 bytes; without a
    // CRLF by then the receiver declares the line invalid.
    constexpr size_t kMaxV1LineBytes = 107;
    const std::string_view text(
        reinterpret_cast<const char*>(data), std::min(len, kMaxV1LineBytes));
    const size_t crlf_offset = text.find("\r\n");
    if (crlf_offset == std::string_view::npos) {
        return len >= kMaxV1LineBytes ? MakeInvalid() : MakeIncomplete();
    }
    const size_t consumed = crlf_offset + 2;
    std::string_view line = text.substr(0, crlf_offset);

    if (line.size() < 6) return MakeInvalid();
    line.remove_prefix(6);

    // Spec §2.1: after "UNKNOWN" the sender may omit the rest of the line and
    // the receiver ignores whatever precedes the CRLF.
    if (line == "UNKNOWN" || line.starts_with("UNKNOWN ")) {
        ProxyProtocolResult r;
        r.status   = ProxyProtocolParseStatus::Success;
        r.consumed = consumed;
        return r;
    }

    auto sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) return MakeInvalid();
    std::string_view family = line.substr(0, sp1);
    line.remove_prefix(sp1 + 1);
    if (family != "TCP4" && family != "TCP6") return MakeInvalid();

    auto sp2 = line.find(' ');
    if (sp2 == std::string_view::npos) return MakeInvalid();
    std::string_view src_ip = line.substr(0, sp2);
    const auto src_addr = iputil::ParseLiteral(src_ip);
    if (!src_addr ||
        (family == "TCP4" && !src_addr->is_v4()) ||
        (family == "TCP6" && !src_addr->is_v6())) {
        return MakeInvalid();
    }
    line.remove_prefix(sp2 + 1);

    auto sp3 = line.find(' ');
    if (sp3 == std::string_view::npos) return MakeInvalid();
    std::string_view dst_ip = line.substr(0, sp3);
    const auto dst_addr = iputil::ParseLiteral(dst_ip);
    if (!dst_addr ||
        (family == "TCP4" && !dst_addr->is_v4()) ||
        (family == "TCP6" && !dst_addr->is_v6())) {
        return MakeInvalid();
    }
    line.remove_prefix(sp3 + 1);

    auto sp4 = line.find(' ');
    if (sp4 == std::string_view::npos) return MakeInvalid();
    uint16_t src_port = 0;
    if (!ParsePort(line.substr(0, sp4), src_port)) return MakeInvalid();
    line.remove_prefix(sp4 + 1);

    uint16_t dst_port = 0;
    if (!ParsePort(line, dst_port)) return MakeInvalid();

    ProxyProtocolResult r;
    r.status   = ProxyProtocolParseStatus::Success;
    r.src_addr = iputil::NormalizeAddress(*src_addr);
    r.src_port = src_port;
    r.consumed = consumed;
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
// 附加数据（INET）： src(4B)+dst(4B)+src_port(2B)+dst_port(2B) = 12B
// 附加数据（INET6）：src(16B)+dst(16B)+src_port(2B)+dst_port(2B) = 36B
// ----------------------------------------------------------------------------
ProxyProtocolResult ParseV2(const uint8_t* data, size_t len) {
    constexpr size_t kHeaderSize = 16;
    if (len < kHeaderSize) return MakeIncomplete();

    const uint8_t version = (data[12] >> 4) & 0x0F;
    const uint8_t command = data[12] & 0x0F;
    const uint8_t family = (data[13] >> 4) & 0x0F;
    const uint8_t transport = data[13] & 0x0F;
    // Spec §2.2: other versions and commands, and for PROXY other families and
    // transport protocols, must be rejected (LOCAL ignores the protocol block).
    // Decide before waiting for the declared address block.
    if (version != 2 || command > 0x01 ||
        (command == 0x01 && (family > 0x03 || transport > 0x02))) {
        return MakeInvalid();
    }

    const uint16_t extra_len =
        static_cast<uint16_t>((data[14] << 8) | data[15]);
    const size_t total = kHeaderSize + extra_len;
    if (total > kProxyHeaderMaxBytes) return MakeInvalid();
    if (len < total) return MakeIncomplete();
    ProxyProtocolResult r;
    r.consumed = total;
    r.status   = ProxyProtocolParseStatus::Success;

    // LOCAL (health checks) carries no address: keep the real peer.
    if (command == 0x00) {
        return r;
    }

    const uint8_t* addr = data + kHeaderSize;

    if (family == 0x01) {
        // IPv4：src(4) + dst(4) + src_port(2) + dst_port(2) = 12B
        if (extra_len < 12) return MakeInvalid();
        net::ip::address_v4::bytes_type bytes{addr[0], addr[1], addr[2], addr[3]};
        r.src_addr = iputil::NormalizeAddress(net::ip::address_v4(bytes));
        r.src_port = static_cast<uint16_t>((addr[8] << 8) | addr[9]);

    } else if (family == 0x02) {
        // IPv6：src(16) + dst(16) + src_port(2) + dst_port(2) = 36B
        if (extra_len < 36) return MakeInvalid();
        net::ip::address_v6::bytes_type bytes{};
        std::copy_n(addr, bytes.size(), bytes.begin());
        r.src_addr = iputil::NormalizeAddress(net::ip::address_v6(bytes));
        r.src_port = static_cast<uint16_t>((addr[32] << 8) | addr[33]);
    }
    // UNSPEC and UNIX carry no network source: keep the real peer.

    return r;
}

}  // namespace

ProxyProtocolResult ParseProxyProtocolHeader(std::span<const uint8_t> bytes) {
    const uint8_t* data = bytes.data();
    const size_t len = bytes.size();
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

    if (len >= sizeof(kSignatureV2) && std::memcmp(data, kSignatureV2, sizeof(kSignatureV2)) == 0) {
        LOG_NET_DEBUG("PROXY protocol v2 binary header detected ({} bytes)", len);
        auto r = ParseV2(data, len);
        if (r.success()) {
            LogProxySource("v2", r);
        } else if (r.incomplete()) {
            LOG_NET_DEBUG("PROXY protocol v2 header incomplete");
        } else {
            LOG_NET_DEBUG("PROXY protocol v2 parsing failed > incomplete or invalid header");
        }
        return r;
    }

    if (len >= 6 && std::memcmp(data, "PROXY ", 6) == 0) {
        LOG_NET_DEBUG("PROXY protocol v1 text header detected");
        auto r = ParseV1(data, len);
        if (r.success()) {
            LogProxySource("v1", r);
        } else if (r.incomplete()) {
            LOG_NET_DEBUG("PROXY protocol v1 header incomplete");
        } else {
            LOG_NET_DEBUG("PROXY protocol v1 parsing failed > malformed or incomplete header");
        }
        return r;
    }

    return {};
}

size_t EncodeProxyProtocolHeader(
    uint8_t version,
    const tcp::endpoint& src,
    const tcp::endpoint& dst,
    std::span<uint8_t, 108> out) noexcept {
    const auto src_addr = iputil::NormalizeAddress(src.address());
    const auto dst_addr = iputil::NormalizeAddress(dst.address());
    const uint16_t src_port = src.port();
    const uint16_t dst_port = dst.port();

    if (version == 1) {
        if (src_addr.is_v4() && dst_addr.is_v4()) {
            const iputil::AddressText src_text(src_addr);
            const iputil::AddressText dst_text(dst_addr);
            const auto src_view = src_text.View();
            const auto dst_view = dst_text.View();
            const int written = std::snprintf(
                reinterpret_cast<char*>(out.data()),
                out.size(),
                "PROXY TCP4 %.*s %.*s %u %u\r\n",
                static_cast<int>(src_view.size()), src_view.data(),
                static_cast<int>(dst_view.size()), dst_view.data(),
                static_cast<unsigned int>(src_port),
                static_cast<unsigned int>(dst_port));
            return (written > 0 && static_cast<size_t>(written) < out.size())
                ? static_cast<size_t>(written)
                : 0;
        }
        const auto src_v6 = src_addr.is_v6()
            ? src_addr.to_v6()
            : net::ip::make_address_v6(net::ip::v4_mapped, src_addr.to_v4());
        const auto dst_v6 = dst_addr.is_v6()
            ? dst_addr.to_v6()
            : net::ip::make_address_v6(net::ip::v4_mapped, dst_addr.to_v4());
        const iputil::AddressText src_text(src_v6);
        const iputil::AddressText dst_text(dst_v6);
        const auto src_view = src_text.View();
        const auto dst_view = dst_text.View();
        const int written = std::snprintf(
            reinterpret_cast<char*>(out.data()),
            out.size(),
            "PROXY TCP6 %.*s %.*s %u %u\r\n",
            static_cast<int>(src_view.size()), src_view.data(),
            static_cast<int>(dst_view.size()), dst_view.data(),
            static_cast<unsigned int>(src_port),
            static_cast<unsigned int>(dst_port));
        return (written > 0 && static_cast<size_t>(written) < out.size())
            ? static_cast<size_t>(written)
            : 0;
    }

    if (version == 2) {
        std::memcpy(out.data(), kSignatureV2, sizeof(kSignatureV2));
        out[12] = 0x21;  // v2 + PROXY command
        if (src_addr.is_v4() && dst_addr.is_v4()) {
            out[13] = 0x11;  // AF_INET + STREAM
            out[14] = 0x00;
            out[15] = 12;
            const auto src_bytes = src_addr.to_v4().to_bytes();
            const auto dst_bytes = dst_addr.to_v4().to_bytes();
            std::memcpy(out.data() + 16, src_bytes.data(), 4);
            std::memcpy(out.data() + 20, dst_bytes.data(), 4);
            out[24] = static_cast<uint8_t>(src_port >> 8);
            out[25] = static_cast<uint8_t>(src_port & 0xff);
            out[26] = static_cast<uint8_t>(dst_port >> 8);
            out[27] = static_cast<uint8_t>(dst_port & 0xff);
            return 28;
        }
        const auto src_v6 = src_addr.is_v6()
            ? src_addr.to_v6()
            : net::ip::make_address_v6(net::ip::v4_mapped, src_addr.to_v4());
        const auto dst_v6 = dst_addr.is_v6()
            ? dst_addr.to_v6()
            : net::ip::make_address_v6(net::ip::v4_mapped, dst_addr.to_v4());
        out[13] = 0x21;  // AF_INET6 + STREAM
        out[14] = 0x00;
        out[15] = 36;
        const auto src_bytes = src_v6.to_bytes();
        const auto dst_bytes = dst_v6.to_bytes();
        std::memcpy(out.data() + 16, src_bytes.data(), 16);
        std::memcpy(out.data() + 32, dst_bytes.data(), 16);
        out[48] = static_cast<uint8_t>(src_port >> 8);
        out[49] = static_cast<uint8_t>(src_port & 0xff);
        out[50] = static_cast<uint8_t>(dst_port >> 8);
        out[51] = static_cast<uint8_t>(dst_port & 0xff);
        return 52;
    }

    return 0;
}

