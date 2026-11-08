#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>


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

