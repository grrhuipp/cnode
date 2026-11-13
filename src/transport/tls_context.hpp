#pragma once

#include "transport/stream_settings.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

// SslContext 工厂共用的 TLS 上下文配置（协议版本、ALPN、PEM 证书、客户端校验身份）
// 与自签证书及其后台续期。只在配置加载期或冷路径调用，不进入握手热路径。

namespace transport {

// Built from trusted configuration before accepting connections. No SNI-driven
// generation, mutable certificate cache, or request-path key rotation.
class AutoSignCertificate {
public:
    [[nodiscard]] static std::unique_ptr<AutoSignCertificate> Create(std::string_view identity);
    AutoSignCertificate(const AutoSignCertificate&) = delete;
    AutoSignCertificate& operator=(const AutoSignCertificate&) = delete;
    [[nodiscard]] X509* Certificate() const noexcept { return certificate_.get(); }
    [[nodiscard]] EVP_PKEY* Key() const noexcept { return key_.get(); }
private:
    AutoSignCertificate() = default;
    bssl::UniquePtr<X509> certificate_;
    bssl::UniquePtr<EVP_PKEY> key_;
};

// One registration per prepared configuration, not per Worker or handshake.
// A single bounded background scheduler signs and publishes immutable contexts.
// 续期只按启动时的 TlsConfig 快照重建同一种自签服务端上下文。

class AutoSignContextRenewal {
public:
    using Clock = std::chrono::system_clock;
    static std::shared_ptr<AutoSignContextRenewal> Start(
        bssl::UniquePtr<SSL_CTX> initial, TlsConfig config);
    [[nodiscard]] SSL_CTX* Acquire(Clock::time_point now = Clock::now()) const noexcept;
private:
    friend class AutoSignRenewalScheduler;
    struct Snapshot {
        bssl::UniquePtr<SSL_CTX> context;
        Clock::time_point expires;
    };
    static_assert(std::atomic<const Snapshot*>::is_always_lock_free);
    AutoSignContextRenewal(bssl::UniquePtr<SSL_CTX> initial, TlsConfig config);
    bool Publish(bssl::UniquePtr<SSL_CTX> context);
    // Runs on the scheduler thread only; null when signing or setup fails.
    [[nodiscard]] bssl::UniquePtr<SSL_CTX> Rebuild() const;
    // Atomic invariant: Publish() constructs an immutable Snapshot at a fixed
    // heap address owned by history_ under publish_mutex_, then publishes it
    // with memory_order_release; Acquire() loads with memory_order_acquire.
    // Reclamation waits until ~AutoSignContextRenewal(), while active SSL
    // connections hold BoringSSL's own SSL_CTX reference count.
    mutable std::mutex publish_mutex_;
    std::vector<std::unique_ptr<const Snapshot>> history_;
    std::atomic<const Snapshot*> current_{nullptr};
    const TlsConfig config_;
    std::atomic<Clock::time_point> next_attempt_{Clock::time_point::min()};
};

[[nodiscard]] bool ConfigureTlsServerIdentity(
    SSL* ssl, std::string_view identity);

[[nodiscard]] bool ConfigureTlsProtocolVersions(
    SSL_CTX* context,
    TlsVersion min_version,
    TlsVersion max_version) noexcept;

[[nodiscard]] bool EncodeTlsAlpnProtocols(
    std::span<const std::string> protocols,
    std::vector<unsigned char>& wire);

// Client ALPN is a context property: configured once at load time.
[[nodiscard]] bool ConfigureTlsClientAlpn(
    SSL_CTX* context, std::span<const std::string> protocols);

// 服务端 ALPN 按 |protocols| 的服务端偏好选择；无交集时以致命告警拒绝（h2 服务端
// 对仅支持 http/1.1 的客户端不选 ALPN）。空列表表示不安装选择回调。
[[nodiscard]] bool ConfigureTlsServerAlpn(
    SSL_CTX* context, std::span<const std::string> protocols);

// Installs the PEM certificate chain (leaf first) and its private key, the
// in-memory equivalent of SSL_CTX_use_certificate_chain_file plus
// SSL_CTX_use_PrivateKey_file. Logs the failing step.
[[nodiscard]] bool ConfigureTlsCertificatePem(
    SSL_CTX* context, const TlsPemMaterial& pem);

}  // namespace transport
