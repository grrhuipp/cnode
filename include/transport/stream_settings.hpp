#pragma once

#include "common/asio_types.hpp"
#include "common/binary_text_codec.hpp"
#include "common/byte_reader.hpp"
#include "common/domain_name.hpp"
#include <openssl/mem.h>
#include "common/constants.hpp"
#include "transport/http_headers.hpp"
#include "transport/outbound_bind.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <vector>

namespace transport {

inline constexpr std::size_t kRealityKeySize = 32;
inline constexpr std::size_t kRealityMldsa65PublicKeySize = 1952;
inline constexpr std::size_t kRealityMldsa65SignatureSize = 3309;

using RealityKey = std::array<uint8_t, kRealityKeySize>;
using RealityMldsa65PublicKey = std::array<uint8_t, kRealityMldsa65PublicKeySize>;

enum class RealityKeyError {
    InvalidFormat,
};

[[nodiscard]] tl::expected<RealityKey, RealityKeyError>
ParseRealityKey(std::string_view value) noexcept;

[[nodiscard]] tl::expected<RealityKey, RealityKeyError>
ParseRealityMldsa65Seed(std::string_view value) noexcept;

[[nodiscard]] tl::expected<RealityMldsa65PublicKey, RealityKeyError>
ParseRealityMldsa65PublicKey(std::string_view value) noexcept;

[[nodiscard]] std::optional<std::string>
NormalizeRealityFingerprint(std::string_view value);

inline constexpr std::size_t kRealityShortIdSize = 8;
using RealityShortId = std::array<uint8_t, kRealityShortIdSize>;

enum class RealityShortIdError {
    InvalidFormat,
};

[[nodiscard]] inline tl::expected<RealityShortId, RealityShortIdError>
ParseRealityShortId(std::string_view value) noexcept {
    if (value.size() % 2 != 0 || value.size() > kRealityShortIdSize * 2) {
        return tl::unexpected(RealityShortIdError::InvalidFormat);
    }

    RealityShortId parsed{};
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const int high = common::HexDigitValue(value[i]);
        const int low = common::HexDigitValue(value[i + 1]);
        if (high < 0 || low < 0) {
            return tl::unexpected(RealityShortIdError::InvalidFormat);
        }
        parsed[i / 2] = static_cast<uint8_t>((high << 4) | low);
    }
    return parsed;
}

using RealityClientVersion = std::array<uint8_t, 4>;

enum class RealityClientVersionError {
    InvalidFormat,
};

[[nodiscard]] inline tl::expected<
    std::optional<RealityClientVersion>, RealityClientVersionError>
ParseRealityClientVersion(std::string_view value) noexcept {
    if (value.empty()) {
        return std::optional<RealityClientVersion>{};
    }

    RealityClientVersion version{};
    size_t part = 0;
    size_t start = 0;
    while (true) {
        if (part >= 3) {
            return tl::unexpected(RealityClientVersionError::InvalidFormat);
        }
        const size_t dot = value.find('.', start);
        const size_t end = dot == std::string_view::npos ? value.size() : dot;
        if (end == start) {
            return tl::unexpected(RealityClientVersionError::InvalidFormat);
        }
        uint32_t parsed = 0;
        for (char ch : value.substr(start, end - start)) {
            if (ch < '0' || ch > '9') {
                return tl::unexpected(RealityClientVersionError::InvalidFormat);
            }
            parsed = parsed * 10u + static_cast<uint32_t>(ch - '0');
            if (parsed > 255u) {
                return tl::unexpected(RealityClientVersionError::InvalidFormat);
            }
        }
        version[part++] = static_cast<uint8_t>(parsed);
        if (dot == std::string_view::npos) {
            break;
        }
        start = dot + 1;
    }
    return std::optional<RealityClientVersion>{version};
}

[[nodiscard]] inline uint32_t RealityClientVersionValue(
    std::span<const uint8_t, 4> version) noexcept {
    return common::LoadU32BE(version.data());
}

[[nodiscard]] inline bool IsRealityServerNameAllowed(
    std::span<const std::string> allowed,
    std::string_view requested) noexcept {
    return std::ranges::any_of(allowed, [requested](const std::string& name) {
        return common::DnsHostnamesEqual(name, requested);
    });
}

enum class StreamEndpointRole {
    Inbound,
    Outbound,
};

struct XHttpDownloadSettings;
class TransportSecurity;

// ============================================================================
// 传输模式（仅配置边界解析名称，运行时只持有枚举）
// ============================================================================
enum class NetworkMode : uint8_t {
    Tcp = 0,
    Ws  = 1,
    HttpUpgrade = 2,
    Grpc = 3,
    Http = 4,
    XHttp = 5,
    Unsupported = 255,
};

enum class SecurityMode : uint8_t {
    None = 0,
    Tls  = 1,
    Reality = 2,
    Unsupported = 255,
};

[[nodiscard]] std::string_view NetworkModeName(NetworkMode mode) noexcept;
[[nodiscard]] std::string_view SecurityModeName(SecurityMode mode) noexcept;
[[nodiscard]] SecurityMode ParseSecurityMode(std::string_view security) noexcept;

// ============================================================================
// WebSocket 传输配置
// ============================================================================
struct WsConfig {
    std::string path = std::string(common::kRootPath);
    HttpHeaders headers;

    // 默认从 X-Forwarded-For 的首个 IP 提取客户端地址（覆盖 TCP 对端）。
    // 只在源站限制为可信代理且代理覆盖客户端自带 header 时可信。
    // 显式设为空字符串可禁用；也可选择其他 HTTP header。
    std::string real_ip_header = "X-Forwarded-For";

};

// ============================================================================
// HTTPUpgrade 传输配置
// ============================================================================
struct HttpUpgradeConfig {
    std::string path = std::string(common::kRootPath);
    std::string host;
    HttpHeaders headers;

    // 与 WS 相同，只在明确配置后信任指定 header。
    std::string real_ip_header;

};

// ============================================================================
// V2Ray HTTP / h2 传输配置
// ============================================================================
struct HttpConfig {
    std::string path = std::string(common::kRootPath);
    std::string host;
    std::string method;
    HttpHeaders headers;

    // 明确配置后才信任指定 header 覆盖 TCP 层源地址。
    std::string real_ip_header;

    // network == "h2" 时强制使用 HTTP/2；network == "http" 时按生态习惯：
    // TLS 默认 HTTP/2，显式 ALPN=http/1.1 时使用 HTTP/1.1，明文使用 HTTP/1.1。
    bool force_http2 = false;

    std::optional<uint32_t> initial_window_size;

};

// ============================================================================
// gRPC 传输配置
// ============================================================================
struct GrpcConfig {
    std::string authority;
    std::string service_name;
    std::string user_agent;
    bool multi_mode = false;
    std::optional<uint32_t> initial_window_size;
    // Derived by stream-settings normalization from RequestPath().
    std::string request_path;

    [[nodiscard]] std::string RequestPath() const;
};

// ============================================================================
// XHTTP / SplitHTTP 传输配置
// ============================================================================
// Xray-core accepts exactly these modes; "" means auto.
enum class XHttpMode : uint8_t {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
};

[[nodiscard]] constexpr std::string_view XHttpModeName(XHttpMode mode) noexcept {
    switch (mode) {
    case XHttpMode::PacketUp: return "packet-up";
    case XHttpMode::StreamUp: return "stream-up";
    case XHttpMode::StreamOne: return "stream-one";
    case XHttpMode::Auto: break;
    }
    return "auto";
}

struct XHttpConfig {
    std::string path = std::string(common::kRootPath);
    std::string host;
    XHttpMode mode = XHttpMode::Auto;
    HttpHeaders headers;
    std::shared_ptr<const XHttpDownloadSettings> download_settings;

    bool no_grpc_header = false;
    bool no_sse_header = false;
    // Derived by stream-settings normalization from NormalizedPath().
    std::string normalized_path;
    // Runtime identity of this inbound configuration generation, never parsed
    // from the wire. Separates equal session ids on different listeners.
    std::string session_namespace;

    [[nodiscard]] std::string NormalizedPath() const;
    [[nodiscard]] bool IsStreamOne() const noexcept { return mode == XHttpMode::StreamOne; }
    [[nodiscard]] bool AcceptsStreamOne() const noexcept {
        return mode == XHttpMode::Auto || mode == XHttpMode::StreamOne ||
               mode == XHttpMode::StreamUp;
    }
    [[nodiscard]] bool AcceptsPacketUp() const noexcept {
        return mode == XHttpMode::Auto || mode == XHttpMode::PacketUp;
    }
    [[nodiscard]] bool AcceptsStreamUp() const noexcept {
        return mode == XHttpMode::Auto || mode == XHttpMode::StreamUp;
    }
};

enum class TlsVersion : uint8_t {
    V1_2 = 2,
    V1_3 = 3,
};

[[nodiscard]] inline bool IsValidTlsAlpn(
    std::span<const std::string> protocols) noexcept {
    for (std::size_t i = 0; i < protocols.size(); ++i) {
        if (protocols[i].empty() || protocols[i].size() > 255) {
            return false;
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (protocols[j] == protocols[i]) return false;
        }
    }
    return true;
}

// Contents of configured certificate, key and CA files. Read in the cold
// configuration path to prepare immutable SSL_CTX snapshots; handshakes never
// reload files or rebuild a context per Worker.
struct TlsPemMaterial {
    std::string certificate_chain;
    std::string private_key;  // Wiped when the last owner releases it.
    std::string trusted_ca;

    TlsPemMaterial() = default;
    ~TlsPemMaterial();
    TlsPemMaterial(const TlsPemMaterial&) = delete;
    TlsPemMaterial& operator=(const TlsPemMaterial&) = delete;
};

// ============================================================================
// TLS 配置
// ============================================================================
struct TlsConfig {
    // 端点身份：服务端证书，或 mTLS 客户端证书
    std::string cert_file;              // 证书链文件路径
    std::string key_file;               // 私钥文件路径
    std::string ca_file;                // CA 证书（可选，用于客户端验证）
    // Loaded from the three paths above by LoadTlsPemMaterial; null when none
    // is configured.
    std::shared_ptr<const TlsPemMaterial> pem;

    // 客户端配置
    std::string server_name;            // 客户端 SNI / 自签证书默认域名
    bool allow_insecure = false;        // 是否允许不验证证书
    std::vector<std::string> alpn;      // ALPN 协议列表

    // 通用协议版本策略
    TlsVersion min_version = TlsVersion::V1_2;
    TlsVersion max_version = TlsVersion::V1_3;

    [[nodiscard]] bool HasCertificatePair() const noexcept {
        return !cert_file.empty() && !key_file.empty();
    }
};

// Cold path only (configuration load). Reads every configured file into
// |config.pem|; throws std::invalid_argument naming the unreadable file.
void LoadTlsPemMaterial(TlsConfig& config);

// ============================================================================
// REALITY 安全层配置
// ============================================================================
struct RealityConfig {
    // 服务端字段
    std::string dest_host;
    uint16_t dest_port = 0;
    uint8_t xver = 0;
    std::vector<std::string> server_names;
    std::optional<RealityKey> private_key;
    std::vector<RealityShortId> short_ids;
    std::optional<RealityClientVersion> min_client_version;
    std::optional<RealityClientVersion> max_client_version;
    uint64_t max_time_diff = 0;
    std::optional<RealityKey> mldsa65_seed;

    // 客户端字段
    std::string fingerprint;
    std::string server_name;
    std::optional<RealityKey> public_key;
    RealityShortId short_id{};
    std::string spider_x;
    std::shared_ptr<const RealityMldsa65PublicKey> mldsa65_verify;

    RealityConfig() = default;
    RealityConfig(const RealityConfig&) = default;
    RealityConfig& operator=(const RealityConfig&) = default;
    RealityConfig(RealityConfig&&) noexcept = default;
    RealityConfig& operator=(RealityConfig&&) noexcept = default;
    ~RealityConfig() noexcept {
        if (private_key) {
            OPENSSL_cleanse(private_key->data(), private_key->size());
        }
        for (auto& id : short_ids) {
            OPENSSL_cleanse(id.data(), id.size());
        }
        if (mldsa65_seed) {
            OPENSSL_cleanse(mldsa65_seed->data(), mldsa65_seed->size());
        }
        OPENSSL_cleanse(short_id.data(), short_id.size());
    }

    [[nodiscard]] bool IsClient() const noexcept { return public_key.has_value(); }
    [[nodiscard]] bool HasDest() const noexcept { return !dest_host.empty() && dest_port != 0; }
    [[nodiscard]] bool operator==(const RealityConfig& other) const noexcept {
        const auto opt_key_eq = [](const std::optional<RealityKey>& a,
                                   const std::optional<RealityKey>& b) noexcept {
            if (a.has_value() != b.has_value()) return false;
            return !a || CRYPTO_memcmp(a->data(), b->data(), a->size()) == 0;
        };
        const auto short_ids_eq = [](const std::vector<RealityShortId>& a,
                                     const std::vector<RealityShortId>& b) noexcept {
            if (a.size() != b.size()) return false;
            uint8_t diff = 0;
            for (size_t i = 0; i < a.size(); ++i) {
                diff |= static_cast<uint8_t>(
                    CRYPTO_memcmp(a[i].data(), b[i].data(), a[i].size()) != 0);
            }
            return diff == 0;
        };
        const bool verify_equal =
            (mldsa65_verify == nullptr) == (other.mldsa65_verify == nullptr) &&
            (!mldsa65_verify || *mldsa65_verify == *other.mldsa65_verify);
        return dest_host == other.dest_host &&
               dest_port == other.dest_port &&
               xver == other.xver &&
               server_names == other.server_names &&
               opt_key_eq(private_key, other.private_key) &&
               short_ids_eq(short_ids, other.short_ids) &&
               min_client_version == other.min_client_version &&
               max_client_version == other.max_client_version &&
               max_time_diff == other.max_time_diff &&
               opt_key_eq(mldsa65_seed, other.mldsa65_seed) &&
               fingerprint == other.fingerprint &&
               server_name == other.server_name &&
               public_key == other.public_key &&
               CRYPTO_memcmp(short_id.data(), other.short_id.data(), short_id.size()) == 0 &&
               spider_x == other.spider_x &&
               verify_equal;
    }
};

// ============================================================================
// StreamSettings - 传输层 + 安全层组合配置
//
// network × security 自由组合；REALITY 按 Xray 生态约束只与 raw/tcp、grpc、
// xhttp 组合。network_mode 决定下方哪一个传输子配置生效，security_mode
// 决定 tls 或 reality 是否生效；其余子配置保持默认值且不被读取。
// ============================================================================
struct StreamSettings {

    TlsConfig tls;
    RealityConfig reality;
    WsConfig  ws;
    HttpUpgradeConfig http_upgrade;
    HttpConfig http;
    GrpcConfig grpc;
    XHttpConfig xhttp;

    NetworkMode  network_mode  = NetworkMode::Tcp;
    SecurityMode security_mode = SecurityMode::None;
    // Explicit outbound Host/:authority of the ws/httpupgrade/grpc/xhttp
    // layer; empty means derive it from the dial address.
    std::string configured_http_host;
    // Configuration-prepared, read-only security shared by all Workers.
    // Not part of wire configuration identity; rebuild on config changes.
    std::shared_ptr<const TransportSecurity> prepared_security;

    bool IsTls() const noexcept { return security_mode == SecurityMode::Tls; }
    bool IsReality() const noexcept { return security_mode == SecurityMode::Reality; }
    bool IsTlsLike() const noexcept { return IsTls() || IsReality(); }
    bool IsWs() const noexcept { return network_mode == NetworkMode::Ws; }
    bool IsHttpUpgrade() const noexcept { return network_mode == NetworkMode::HttpUpgrade; }
    bool IsHttp() const noexcept { return network_mode == NetworkMode::Http; }
    bool IsGrpc() const noexcept { return network_mode == NetworkMode::Grpc; }
    bool IsXHttp() const noexcept { return network_mode == NetworkMode::XHttp; }
    bool IsUnsupported() const noexcept {
        return network_mode == NetworkMode::Unsupported ||
               security_mode == SecurityMode::Unsupported;
    }

    [[nodiscard]] std::string_view NetworkName() const noexcept {
        return IsHttp() && http.force_http2 ? "h2" : NetworkModeName(network_mode);
    }

};

struct XHttpDownloadSettings {
    std::string address;
    uint16_t port = 0;
    OutboundBind send_through;
    StreamSettings stream_settings;
};

struct OutboundStreamDefaults {
    bool require_tls = false;
    std::string_view fallback_server_name;
    bool allow_insecure = false;
    std::span<const std::string> alpn;
};

// Cold-path value transformations. The source remains unchanged, including
// when normalization or default construction fails to allocate.
[[nodiscard]] StreamSettings NormalizeStreamSettings(const StreamSettings& source);
// The one network-name classification (case-insensitive) used by normalization;
// lets builders select the transport sub-config before normalizing once.
[[nodiscard]] NetworkMode ParseNetworkMode(std::string_view network) noexcept;
// Concrete XHTTP client mode; auto follows Xray-core: downloadSettings →
// stream-up, REALITY → stream-one, TLS without an http/1.1-only ALPN →
// stream-up, otherwise packet-up. Never returns XHttpMode::Auto.
[[nodiscard]] XHttpMode ResolveXHttpOutboundMode(const StreamSettings& settings) noexcept;

[[nodiscard]] StreamSettings NormalizeOutboundStreamSettings(
    const StreamSettings& source, const OutboundStreamDefaults& defaults = {});

}  // namespace transport


