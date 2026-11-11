#include "transport/internet/tls_context.hpp"
#include "transport/internet/tls_stream.hpp"
#include "transport/internet/stream_settings.hpp"
#include "transport/internet/transport_security.hpp"
#include "common/domain_name.hpp"
#include "common/ip_utils.hpp"
#include "common/unsafe.hpp"
#include "infra/log.hpp"
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <format>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

// ============================================================================
// SslContext 工厂
// ============================================================================

namespace {

[[nodiscard]] bool AlpnWireContains(
    const unsigned char* wire, unsigned int size, std::string_view protocol) noexcept {
    for (unsigned int offset = 0; offset < size;) {
        const unsigned int length = wire[offset++];
        if (size - offset < length) return false;
        if (std::string_view(unsafe::ptr_cast<const char>(wire + offset), length) == protocol) {
            return true;
        }
        offset += length;
    }
    return false;
}

// RFC 7301 §3.2: without a common protocol the server answers with a fatal
// no_application_protocol alert. Like Go crypto/tls (the Xray server), an
// h2 server still accepts an http/1.1-only client without selecting ALPN.
int SelectServerAlpnCallback(
    SSL* /*ssl*/,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg) {
    const auto& configured = *static_cast<const std::vector<unsigned char>*>(arg);
    unsigned char* selected = nullptr;
    const int rc = SSL_select_next_proto(
        &selected,
        outlen,
        configured.data(),
        static_cast<unsigned int>(configured.size()),
        in,
        inlen);
    if (rc == OPENSSL_NPN_NEGOTIATED) {
        *out = selected;
        return SSL_TLSEXT_ERR_OK;
    }
    const bool http11_fallback =
        AlpnWireContains(configured.data(), static_cast<unsigned int>(configured.size()), "h2") &&
        AlpnWireContains(in, inlen, "http/1.1");
    return http11_fallback ? SSL_TLSEXT_ERR_NOACK : SSL_TLSEXT_ERR_ALERT_FATAL;
}

std::string ResolveAutoSignDefaultName(const TlsConfig& config) {
    if (config.server_name.empty()) {
        return "localhost";
    }
    return config.server_name;
}

// 启动与续期共用的唯一自签服务端上下文构建：为配置域名签发一年期证书。
[[nodiscard]] bssl::UniquePtr<SSL_CTX> CreateAutoSignServerContext(const TlsConfig& config) {
    const std::string default_name = ResolveAutoSignDefaultName(config);
    auto material = transport::internet::AutoSignCertificate::Create(default_name);
    if (!material) {
        LOG_ERROR("failed to generate default self-signed TLS certificate");
        return nullptr;
    }

    bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_server_method()));
    if (!context) return nullptr;

    if (!ConfigureTlsProtocolVersions(
            context.get(), config.min_version, config.max_version)) {
        LOG_ERROR("invalid auto-sign TLS protocol version policy");
        return nullptr;
    }

    if (SSL_CTX_use_certificate(context.get(), material->Certificate()) != 1 ||
        SSL_CTX_use_PrivateKey(context.get(), material->Key()) != 1) {
        LOG_ERROR("failed to install default self-signed TLS certificate");
        return nullptr;
    }

    LOG_INFO("TLS auto-sign certificate created (domain={} validity=one year renewal=30 days before expiry)",
             default_name);
    if (!ConfigureTlsServerAlpn(context.get(), config.alpn)) {
        LOG_ERROR("invalid auto-sign TLS ALPN policy");
        return nullptr;
    }
    return context;
}

}  // namespace

std::unique_ptr<SslContext> SslContext::CreateServer(const TlsConfig& config) {
    bssl::UniquePtr<SSL_CTX> owner(SSL_CTX_new(TLS_server_method()));
    SSL_CTX* ctx = owner.get();
    if (!ctx) {
        LOG_ERROR("failed to create TLS server context");
        return nullptr;
    }

    if (!ConfigureTlsProtocolVersions(
            ctx, config.min_version, config.max_version)) {
        LOG_ERROR("invalid TLS server protocol version policy");
        return nullptr;
    }

    if (!config.pem) {
        LOG_ERROR("TLS certificate files were not loaded with the configuration");
        return nullptr;
    }
    if (!ConfigureTlsCertificatePem(ctx, *config.pem)) {
        LOG_ERROR("failed to load TLS certificate from {}", config.cert_file);
        return nullptr;
    }

    if (!ConfigureTlsServerAlpn(ctx, config.alpn)) {
        LOG_ERROR("invalid TLS server ALPN policy");
        return nullptr;
    }
    return std::unique_ptr<SslContext>(new SslContext(std::move(owner)));
}

std::unique_ptr<SslContext> SslContext::CreateServerAutoSign(const TlsConfig& config) {
    auto initial = CreateAutoSignServerContext(config);
    if (!initial) return nullptr;
    return std::unique_ptr<SslContext>(new SslContext(
        AutoSignContextRenewal::Start(std::move(initial), config)));
}

std::unique_ptr<SslContext> SslContext::CreateQuicServer(
    const TlsConfig& config, std::span<const std::string> alpn) {
    if (alpn.empty()) {
        LOG_ERROR("QUIC TLS server requires at least one ALPN protocol");
        return nullptr;
    }
    if (!config.HasCertificatePair() || !config.pem) {
        LOG_ERROR("QUIC TLS server requires a loaded certificate and private key");
        return nullptr;
    }

    bssl::UniquePtr<SSL_CTX> owner(SSL_CTX_new(TLS_server_method()));
    SSL_CTX* ctx = owner.get();
    if (!ctx) {
        LOG_ERROR("failed to create QUIC TLS server context");
        return nullptr;
    }
    // RFC 9001 §4.2: QUIC negotiates TLS 1.3 only. A configured minimum below
    // 1.3 narrows to 1.3; a configured maximum below 1.3 leaves no version.
    if (!ConfigureTlsProtocolVersions(ctx, config.min_version, config.max_version) ||
        !ConfigureTlsProtocolVersions(ctx, TlsVersion::V1_3, config.max_version)) {
        LOG_ERROR("QUIC TLS server requires tls maxVersion 1.3");
        return nullptr;
    }
    if (!ConfigureTlsCertificatePem(ctx, *config.pem)) {
        LOG_ERROR("failed to load QUIC TLS certificate from {}", config.cert_file);
        return nullptr;
    }
    if (!ConfigureTlsServerAlpn(ctx, alpn)) {
        LOG_ERROR("invalid QUIC TLS server ALPN policy");
        return nullptr;
    }
    return std::unique_ptr<SslContext>(new SslContext(std::move(owner)));
}

std::shared_ptr<SSL_CTX> SslContext::AcquireNative() const noexcept {
    return renewal_ ? renewal_->Acquire() : native_owner_;
}

bool ConfigureTlsServerAlpn(
    SSL_CTX* context, std::span<const std::string> protocols) {
    if (protocols.empty()) return true;
    auto wire = std::make_unique<std::vector<unsigned char>>();
    if (!EncodeTlsAlpnProtocols(protocols, *wire)) return false;
    static const int index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr,
        [](void*, void* ptr, CRYPTO_EX_DATA*, int, long, void*) {
            delete static_cast<std::vector<unsigned char>*>(ptr);
        });
    if (index < 0 ||
        SSL_CTX_set_ex_data(context, index, wire.get()) != 1) {
        return false;
    }
    SSL_CTX_set_alpn_select_cb(
        context, SelectServerAlpnCallback, wire.release());
    return true;
}

// ============================================================================
// TransportSecurity 实现
// ============================================================================

namespace {

[[nodiscard]] std::unique_ptr<SslContext> CreateSecurityContext(
    const StreamSettings& settings, StreamEndpointRole role) {
    if (role == StreamEndpointRole::Inbound) {
        if (settings.IsReality()) {
            return SslContext::CreateServerReality(settings.reality, settings.tls);
        }
        return settings.tls.HasCertificatePair()
            ? SslContext::CreateServer(settings.tls)
            : SslContext::CreateServerAutoSign(settings.tls);
    }
    return settings.IsReality()
        ? SslContext::CreateClientReality(settings.reality, settings.tls)
        : SslContext::CreateClient(settings.tls);
}

}  // namespace

TransportSecurity::TransportSecurity(
    const StreamSettings& settings, StreamEndpointRole role) : role_(role) {
    if (settings.prepared_security && settings.prepared_security->role_ == role) {
        context_ = settings.prepared_security->context_;
        xhttp_download_ = settings.prepared_security->xhttp_download_;
        return;
    }
    if (settings.IsTlsLike()) {
        context_ = CreateSecurityContext(settings, role);
        if (!context_) {
            throw std::invalid_argument(std::format(
                "cannot build {} {} context",
                settings.IsReality() ? "REALITY" : "TLS",
                role == StreamEndpointRole::Inbound ? "server" : "client"));
        }
    }
    if (role == StreamEndpointRole::Outbound && settings.IsXHttp() &&
        settings.xhttp.download_settings) {
        xhttp_download_ = std::make_shared<TransportSecurity>(
            settings.xhttp.download_settings->stream_settings,
            StreamEndpointRole::Outbound);
    }
}

TransportSecurity::~TransportSecurity() = default;

void TransportSecurity::Prepare(StreamSettings& settings, StreamEndpointRole role) {
    // Build independently first; a failed replacement leaves the published
    // configuration intact. Avoid inheriting a stale prepared context when a
    // caller updates TLS/REALITY fields in a copied settings object.
    auto source = settings;
    source.prepared_security.reset();
    settings.prepared_security = std::make_shared<TransportSecurity>(source, role);
}

// ============================================================================
// AutoSignCertificate & AutoSignContextRenewal
// ============================================================================

namespace transport::internet {
namespace {

bssl::UniquePtr<EVP_PKEY> GenerateEcP256Key() {
    bssl::UniquePtr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    EVP_PKEY* generated = nullptr;
    if (!pctx ||
        EVP_PKEY_keygen_init(pctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx.get(), &generated) <= 0) {
        EVP_PKEY_free(generated);
        return nullptr;
    }
    return bssl::UniquePtr<EVP_PKEY>(generated);
}

bool PushGeneralName(GENERAL_NAMES* names, int type, ASN1_STRING* value) {
    GENERAL_NAME* name = GENERAL_NAME_new();
    if (!name) {
        ASN1_STRING_free(value);
        return false;
    }
    GENERAL_NAME_set0_value(name, type, value);
    if (sk_GENERAL_NAME_push(names, name) == 0) {
        GENERAL_NAME_free(name);
        return false;
    }
    return true;
}

bool PushDnsName(GENERAL_NAMES* names, std::string_view value) {
    if (value.empty() ||
        value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    for (const unsigned char ch : value) {
        if (ch <= 0x20 || ch > 0x7e) return false;
    }
    ASN1_IA5STRING* dns_name = ASN1_IA5STRING_new();
    if (!dns_name ||
        ASN1_STRING_set(
            dns_name, value.data(), static_cast<int>(value.size())) != 1) {
        if (dns_name) ASN1_IA5STRING_free(dns_name);
        return false;
    }
    return PushGeneralName(names, GEN_DNS, dns_name);
}

bool AddSubjectAlternativeNames(X509* certificate, const std::string& identity) {
    GENERAL_NAMES* names = GENERAL_NAMES_new();
    if (!names) return false;

    ASN1_OCTET_STRING* ip_address = a2i_IPADDRESS(identity.c_str());
    bool built = false;
    if (ip_address) {
        built = PushGeneralName(names, GEN_IPADD, ip_address);
    } else {
        built = PushDnsName(names, identity);
        if (built && identity.starts_with("*.")) {
            built = PushDnsName(names, std::string_view(identity).substr(2));
        }
    }

    bssl::UniquePtr<X509_EXTENSION> extension(built
        ? X509V3_EXT_i2d(NID_subject_alt_name, 0, names)
        : nullptr);
    const bool added = extension && X509_add_ext(certificate, extension.get(), -1) == 1;
    GENERAL_NAMES_free(names);
    return added;
}

}  // namespace

std::unique_ptr<AutoSignCertificate> AutoSignCertificate::Create(std::string_view identity) {
    // RFC 5280's commonName limit is 64 characters, not a DNS SAN limit.
    // DNS identities belong in SAN; a descriptive CN covers longer names.
    if (identity.empty() || identity.find('\0') != std::string_view::npos) return {};
    if (identity.ends_with('.')) identity.remove_suffix(1);
    if (identity.empty() || identity.ends_with('.')) return {};
    const std::string name_text(identity);
    const std::string_view cn = identity.size() <= 64
        ? identity : std::string_view("cnode self-signed certificate");
    auto material = std::unique_ptr<AutoSignCertificate>(new AutoSignCertificate);
    material->key_ = GenerateEcP256Key();
    material->certificate_.reset(X509_new());
    if (!material->key_ || !material->certificate_) {
        ERR_clear_error();
        return {};
    }
    X509* x509 = material->certificate_.get();
    X509_NAME* name = X509_get_subject_name(x509);
    // These credentials are regenerated on configuration reload/restart,
    // never in response to untrusted ClientHello traffic.
    constexpr long kValiditySeconds = 365L * 24 * 60 * 60;
    if (X509_set_version(x509, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) != 1 ||
        !X509_gmtime_adj(X509_get_notBefore(x509), -300) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), kValiditySeconds) ||
        X509_set_pubkey(x509, material->key_.get()) != 1 ||
        !name ||
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(cn.data()),
            static_cast<int>(cn.size()), -1, 0) != 1 ||
        X509_set_issuer_name(x509, name) != 1 ||
        !AddSubjectAlternativeNames(x509, name_text) ||
        X509_sign(x509, material->key_.get(), EVP_sha256()) <= 0) {
        ERR_clear_error();
        return {};
    }
    return material;
}

}  // namespace transport::internet

class AutoSignRenewalScheduler {
public:
    static AutoSignRenewalScheduler& Instance() {
        static AutoSignRenewalScheduler scheduler;
        return scheduler;
    }
    void Add(const std::shared_ptr<AutoSignContextRenewal>& state) {
        std::lock_guard lock(mutex_);
        if (failed_) throw std::runtime_error("auto-sign renewal scheduler stopped");
        std::erase_if(states_, [](const auto& entry) { return entry.expired(); });
        // Configuration-controlled registrations only. Refuse overload instead
        // of retaining an unbounded signing queue or spawning extra threads.
        if (states_.size() >= kCapacity)
            throw std::runtime_error("auto-sign context renewal capacity exhausted");
        states_.push_back(state);
        Notify();
    }
    ~AutoSignRenewalScheduler() {
        thread_.request_stop();
        Notify();
        if (thread_.joinable()) thread_.join();
        ::close(timer_);
        ::close(wake_);
    }
private:
    AutoSignRenewalScheduler() {
        wake_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        timer_ = ::timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (wake_ < 0 || timer_ < 0) {
            const auto error = errno;
            if (wake_ >= 0) ::close(wake_);
            if (timer_ >= 0) ::close(timer_);
            throw std::system_error(error, std::generic_category(), "auto-sign event descriptors");
        }
        try {
            thread_ = std::jthread([this](std::stop_token stop) {
                try {
                    Run(stop);
                } catch (const std::exception& error) {
                    LOG_ERROR("TLS auto-sign renewal scheduler stopped > {}", error.what());
                    std::lock_guard lock(mutex_);
                    failed_ = true;
                }
            });
        } catch (...) {
            ::close(timer_);
            ::close(wake_);
            throw;
        }
    }
    void Notify() noexcept {
        const uint64_t value = 1;
        while (::write(wake_, &value, sizeof(value)) < 0 && errno == EINTR) {}
        // EAGAIN means the event counter is already readable.
    }
    void Wait(AutoSignContextRenewal::Clock::time_point next) {
        if (next <= AutoSignContextRenewal::Clock::now()) return;
        itimerspec timeout{};
        if (next != AutoSignContextRenewal::Clock::time_point::max()) {
            const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(next.time_since_epoch());
            timeout.it_value.tv_sec = seconds.count();
            timeout.it_value.tv_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(
                next.time_since_epoch() - seconds).count();
        }
        if (::timerfd_settime(timer_, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
                              &timeout, nullptr) != 0) {
            // Linux also reports an unread clock-change cancellation when
            // rearming; the new timer is armed, but rescan the due set first.
            if (errno == ECANCELED) return;
            throw std::system_error(errno, std::generic_category(), "auto-sign timer arm");
        }
        pollfd events[]{{wake_, POLLIN, 0}, {timer_, POLLIN, 0}};
        int ready;
        do { ready = ::poll(events, 2, -1); } while (ready < 0 && errno == EINTR);
        if (ready < 0) throw std::system_error(errno, std::generic_category(), "auto-sign event wait");
        for (const auto& event : events) {
            if (event.revents & (POLLERR | POLLHUP | POLLNVAL))
                throw std::runtime_error("auto-sign event descriptor failed");
            if (event.revents & POLLIN) {
                uint64_t count;
                ssize_t bytes;
                do { bytes = ::read(event.fd, &count, sizeof(count)); } while (bytes < 0 && errno == EINTR);
                // A real wall-clock discontinuity cancels the absolute timer.
                // Recompute the nearest certificate's deadline, without polling.
                if (bytes < 0 && errno != EAGAIN && errno != ECANCELED)
                    throw std::system_error(errno, std::generic_category(), "auto-sign event read");
            }
        }
    }
    void Run(std::stop_token stop) {
        using Clock = AutoSignContextRenewal::Clock;
        while (!stop.stop_requested()) {
            std::unique_lock lock(mutex_);
            std::erase_if(states_, [](const auto& entry) { return entry.expired(); });
            auto next = Clock::time_point::max();
            std::shared_ptr<AutoSignContextRenewal> due;
            const auto now = Clock::now();
            for (const auto& weak : states_) {
                if (auto state = weak.lock()) {
                    const auto attempt_at = state->next_attempt_.load(std::memory_order_acquire);
                    if (attempt_at <= now) {
                        due = std::move(state);
                        break;
                    }
                    next = std::min(next, attempt_at);
                }
            }
            lock.unlock();
            if (!due) {
                Wait(next);
                continue;
            }
            bool renewed = false;
            try {
                renewed = due->Publish(due->Rebuild());
            } catch (const std::exception& error) {
                LOG_ERROR("TLS auto-sign renewal failed > {}", error.what());
            } catch (...) {
                LOG_ERROR("TLS auto-sign renewal failed > unknown exception");
            }
            const auto minimum_retry = Clock::now() + std::chrono::minutes(1);
            if (!renewed) {
                // Existing connections retain their own SSL_CTX. New handshakes
                // fail closed after notAfter if renewal cannot recover.
                due->next_attempt_.store(minimum_retry, std::memory_order_release);
                LOG_ERROR("TLS auto-sign renewal unavailable; retrying in one minute");
            } else if (due->next_attempt_.load(std::memory_order_acquire) < minimum_retry) {
                due->next_attempt_.store(minimum_retry, std::memory_order_release);
            }
        }
    }
    static constexpr size_t kCapacity = 4096;
    std::mutex mutex_;
    int wake_ = -1;
    int timer_ = -1;
    bool failed_ = false;
    std::vector<std::weak_ptr<AutoSignContextRenewal>> states_;
    std::jthread thread_;
};

AutoSignContextRenewal::AutoSignContextRenewal(std::shared_ptr<SSL_CTX> initial, TlsConfig config)
    : config_(std::move(config)) {
    if (!Publish(std::move(initial)))
        throw std::invalid_argument("auto-sign certificate has invalid validity");
}

bool AutoSignContextRenewal::Publish(std::shared_ptr<SSL_CTX> context) {
    if (!context) return false;
    const X509* certificate = SSL_CTX_get0_certificate(context.get());
    int64_t expires_seconds = 0;
    if (!certificate || ASN1_TIME_to_posix(X509_get0_notAfter(certificate), &expires_seconds) != 1)
        return false;
    const auto expires = Clock::time_point(std::chrono::seconds(expires_seconds));
    if (expires <= Clock::now()) return false;
    const auto previous = current_.load(std::memory_order_acquire);
    if (previous && expires <= previous->expires) return false;
    current_.store(std::make_shared<const Snapshot>(Snapshot{std::move(context), expires}),
                   std::memory_order_release);
    next_attempt_.store(expires - std::chrono::hours(24 * 30), std::memory_order_release);
    return true;
}

std::shared_ptr<AutoSignContextRenewal> AutoSignContextRenewal::Start(
    std::shared_ptr<SSL_CTX> initial, TlsConfig config) {
    auto state = std::shared_ptr<AutoSignContextRenewal>(
        new AutoSignContextRenewal(std::move(initial), std::move(config)));
    AutoSignRenewalScheduler::Instance().Add(state);
    return state;
}

std::shared_ptr<SSL_CTX> AutoSignContextRenewal::Acquire(Clock::time_point now) const noexcept {
    const auto snapshot = current_.load(std::memory_order_acquire);
    if (!snapshot || now >= snapshot->expires) return {};
    return snapshot->context;
}

std::shared_ptr<SSL_CTX> AutoSignContextRenewal::Rebuild() const {
    return CreateAutoSignServerContext(config_);
}

// ============================================================================
// TLS Client Context & PEM Material
// ============================================================================

namespace {

// Real chains and CA bundles are far smaller; the bound keeps a mistyped path
// to a device or an unrelated large file from stalling configuration load.
constexpr std::size_t kMaxTlsPemFileBytes = 1024 * 1024;

struct FileDescriptor {
    int fd = -1;
    FileDescriptor() = default;
    explicit FileDescriptor(int value) noexcept : fd(value) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    ~FileDescriptor() {
        if (fd >= 0) ::close(fd);
    }
};

// The private key passes through here, so the file is read unbuffered into one
// allocation sized up front: no stdio/stream buffer and no growth copy keeps
// key bytes outside the returned string, and every error path wipes it.
std::string ReadTlsPemFile(const std::string& path, std::string_view kind) {
    const auto fail = [&](std::string_view reason) {
        return std::invalid_argument(
            std::format("cannot read TLS {} file '{}': {}", kind, path, reason));
    };
    if (path.find('\0') != std::string::npos) {
        throw std::invalid_argument(
            std::format("cannot open TLS {} file '{}'", kind, path));
    }
    FileDescriptor file(::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (file.fd < 0) {
        throw std::invalid_argument(
            std::format("cannot open TLS {} file '{}'", kind, path));
    }
    struct stat st{};
    if (::fstat(file.fd, &st) != 0) throw fail("read error");
    if (!S_ISREG(st.st_mode)) throw fail("not a regular file");
    if (st.st_size < 0) throw fail("read error");
    if (st.st_size == 0) throw fail("empty");
    if (static_cast<unsigned long long>(st.st_size) > kMaxTlsPemFileBytes) {
        throw fail("larger than 1 MiB");
    }

    std::string contents(static_cast<std::size_t>(st.st_size), '\0');
    std::size_t offset = 0;
    bool read_error = false;
    while (offset < contents.size()) {
        const ssize_t count = ::read(
            file.fd, contents.data() + offset, contents.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            read_error = true;
            break;
        }
        if (count == 0) break;
        offset += static_cast<std::size_t>(count);
    }
    // One byte more than announced means the file changed while being read.
    char probe = 0;
    ssize_t extra = 0;
    if (!read_error && offset == contents.size()) {
        do {
            extra = ::read(file.fd, &probe, 1);
        } while (extra < 0 && errno == EINTR);
        if (extra < 0) read_error = true;
    }
    OPENSSL_cleanse(&probe, sizeof(probe));
    if (read_error || offset != contents.size() || extra != 0) {
        OPENSSL_cleanse(contents.data(), contents.size());
        throw fail(read_error ? "read error" : "changed while reading");
    }
    return contents;
}

uint16_t ToOpenSslVersion(TlsVersion version) noexcept {
    switch (version) {
        case TlsVersion::V1_2:
            return TLS1_2_VERSION;
        case TlsVersion::V1_3:
            return TLS1_3_VERSION;
    }
    return 0;
}

[[nodiscard]] bssl::UniquePtr<BIO> PemReader(const std::string& pem) {
    return bssl::UniquePtr<BIO>(BIO_new_mem_buf(
        pem.data(), static_cast<ossl_ssize_t>(pem.size())));
}

int RejectEncryptedPemPassword(char*, int, int, void*) noexcept {
    return -1;
}

// PEM readers report the end of input as PEM_R_NO_START_LINE; anything else
// is a malformed block. Clears the queue so no stale error reaches later
// SSL_get_error calls on this thread.
[[nodiscard]] bool ConsumePemEndOfInput() noexcept {
    const uint32_t error = ERR_peek_last_error();
    ERR_clear_error();
    return ERR_GET_LIB(error) == ERR_LIB_PEM &&
        ERR_GET_REASON(error) == PEM_R_NO_START_LINE;
}

// In-memory SSL_CTX_load_verify_locations: like X509_load_cert_crl_file it
// reads every PEM_X509_INFO block (including TRUSTED CERTIFICATE and CRLs);
// a bundle without any certificate or CRL is rejected.
[[nodiscard]] bool ConfigureTlsTrustedCaPem(SSL_CTX* context, const std::string& pem) {
    ERR_clear_error();
    auto reader = PemReader(pem);
    X509_STORE* store = SSL_CTX_get_cert_store(context);
    if (!reader || !store) {
        ERR_clear_error();
        return false;
    }
    struct InfoStackFree {
        void operator()(STACK_OF(X509_INFO)* infos) const noexcept {
            sk_X509_INFO_pop_free(infos, X509_INFO_free);
        }
    };
    std::unique_ptr<STACK_OF(X509_INFO), InfoStackFree> infos(
        PEM_X509_INFO_read_bio(reader.get(), nullptr, &RejectEncryptedPemPassword, nullptr));
    if (!infos) {
        ERR_clear_error();
        return false;
    }
    size_t loaded = 0;
    for (size_t i = 0; i < sk_X509_INFO_num(infos.get()); ++i) {
        const X509_INFO* info = sk_X509_INFO_value(infos.get(), i);
        if (info->x509) {
            if (X509_STORE_add_cert(store, info->x509) != 1) {
                const uint32_t err = ERR_peek_last_error();
                if (ERR_GET_LIB(err) == ERR_LIB_X509 &&
                    ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                    ERR_clear_error();
                    ++loaded;
                } else {
                    ERR_clear_error();
                    return false;
                }
            } else {
                ++loaded;
            }
        }
        if (info->crl) {
            if (X509_STORE_add_crl(store, info->crl) != 1) {
                ERR_clear_error();
                return false;
            }
            ++loaded;
        }
    }
    ERR_clear_error();
    return loaded != 0;
}

}  // namespace

TlsPemMaterial::~TlsPemMaterial() {
    OPENSSL_cleanse(private_key.data(), private_key.size());
}

void LoadTlsPemMaterial(TlsConfig& config) {
    if (config.cert_file.empty() && config.key_file.empty() &&
        config.ca_file.empty()) {
        config.pem.reset();
        return;
    }
    auto material = std::make_shared<TlsPemMaterial>();
    if (!config.cert_file.empty()) {
        material->certificate_chain =
            ReadTlsPemFile(config.cert_file, "certificate");
    }
    if (!config.key_file.empty()) {
        material->private_key = ReadTlsPemFile(config.key_file, "private key");
    }
    if (!config.ca_file.empty()) {
        material->trusted_ca = ReadTlsPemFile(config.ca_file, "CA");
    }
    config.pem = std::move(material);
}

bool ConfigureTlsCertificatePem(SSL_CTX* context, const TlsPemMaterial& pem) {
    ERR_clear_error();
    auto chain = PemReader(pem.certificate_chain);
    if (!chain) {
        ERR_clear_error();
        return false;
    }
    bssl::UniquePtr<X509> leaf(
        PEM_read_bio_X509_AUX(chain.get(), nullptr, &RejectEncryptedPemPassword, nullptr));
    if (!leaf || SSL_CTX_use_certificate(context, leaf.get()) != 1) {
        ERR_clear_error();
        LOG_ERROR("TLS certificate file does not start with a valid PEM certificate");
        return false;
    }
    while (bssl::UniquePtr<X509> intermediate{
               PEM_read_bio_X509(chain.get(), nullptr, &RejectEncryptedPemPassword, nullptr)}) {
        if (SSL_CTX_add1_chain_cert(context, intermediate.get()) != 1) {
            ERR_clear_error();
            LOG_ERROR("failed to install TLS certificate chain");
            return false;
        }
    }
    if (!ConsumePemEndOfInput()) {
        LOG_ERROR("TLS certificate file contains a malformed PEM block");
        return false;
    }

    auto key_reader = PemReader(pem.private_key);
    bssl::UniquePtr<EVP_PKEY> key(key_reader
        ? PEM_read_bio_PrivateKey(key_reader.get(), nullptr, &RejectEncryptedPemPassword, nullptr)
        : nullptr);
    if (!key || SSL_CTX_use_PrivateKey(context, key.get()) != 1) {
        ERR_clear_error();
        LOG_ERROR("TLS private key file does not contain a valid PEM private key");
        return false;
    }
    if (SSL_CTX_check_private_key(context) != 1) {
        ERR_clear_error();
        LOG_ERROR("TLS private key does not match certificate");
        return false;
    }
    ERR_clear_error();
    return true;
}

bool ConfigureTlsProtocolVersions(
    SSL_CTX* context,
    TlsVersion min_version,
    TlsVersion max_version) noexcept {
    const uint16_t minimum = ToOpenSslVersion(min_version);
    const uint16_t maximum = ToOpenSslVersion(max_version);
    return context && minimum != 0 && maximum != 0 && minimum <= maximum &&
        SSL_CTX_set_min_proto_version(context, minimum) == 1 &&
        SSL_CTX_set_max_proto_version(context, maximum) == 1;
}

bool EncodeTlsAlpnProtocols(
    std::span<const std::string> protocols,
    std::vector<unsigned char>& wire) {
    wire.clear();
    if (!IsValidTlsAlpn(protocols)) return false;

    std::size_t wire_size = 0;
    for (const auto& protocol : protocols) {
        wire_size += 1 + protocol.size();
    }
    wire.reserve(wire_size);
    for (const auto& protocol : protocols) {
        wire.push_back(static_cast<unsigned char>(protocol.size()));
        wire.insert(wire.end(), protocol.begin(), protocol.end());
    }
    return true;
}

bool ConfigureTlsClientAlpn(
    SSL_CTX* context, std::span<const std::string> protocols) {
    std::vector<unsigned char> wire;
    // SSL_new copies the context list, so no handshake encodes it again.
    return EncodeTlsAlpnProtocols(protocols, wire) &&
        (wire.empty() || SSL_CTX_set_alpn_protos(context, wire.data(), wire.size()) == 0);
}

bool ConfigureTlsServerIdentity(
    SSL* ssl, std::string_view identity) {
    if (!ssl || identity.empty() || identity.find('\0') != std::string_view::npos) {
        return false;
    }

    if (const auto address = iputil::ParseLiteral(identity)) {
        X509_VERIFY_PARAM* parameters = SSL_get0_param(ssl);
        if (!parameters) return false;
        if (address->is_v4()) {
            const auto bytes = address->to_v4().to_bytes();
            return X509_VERIFY_PARAM_set1_ip(parameters, bytes.data(), bytes.size()) == 1;
        }
        const auto bytes = address->to_v6().to_bytes();
        return X509_VERIFY_PARAM_set1_ip(parameters, bytes.data(), bytes.size()) == 1;
    }
    if (!domain::IsValidDnsHostname(identity, domain::TrailingDotPolicy::Allow)) return false;
    identity = domain::WithoutTrailingRootDot(identity);
    std::array<char, 256> identity_text{};
    if (identity.size() >= identity_text.size()) return false;
    std::memcpy(identity_text.data(), identity.data(), identity.size());

    if (SSL_set_tlsext_host_name(ssl, identity_text.data()) != 1) {
        return false;
    }
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    return SSL_set1_host(ssl, identity_text.data()) == 1;
}

std::unique_ptr<SslContext> SslContext::CreateClient(const TlsConfig& config) {
    bssl::UniquePtr<SSL_CTX> owner(SSL_CTX_new(TLS_client_method()));
    SSL_CTX* ctx = owner.get();
    if (!ctx) {
        LOG_ERROR("failed to create TLS client context");
        return nullptr;
    }

    if (!ConfigureTlsProtocolVersions(
            ctx, config.min_version, config.max_version)) {
        LOG_ERROR("invalid TLS client protocol version policy");
        return nullptr;
    }
    if (!ConfigureTlsClientAlpn(ctx, config.alpn)) {
        LOG_ERROR("invalid TLS client ALPN policy");
        return nullptr;
    }

    if (config.cert_file.empty() != config.key_file.empty()) {
        LOG_ERROR("TLS client certificate and private key must be configured together");
        return nullptr;
    }
    if ((config.HasCertificatePair() || !config.ca_file.empty()) && !config.pem) {
        LOG_ERROR("TLS client files were not loaded with the configuration");
        return nullptr;
    }
    if (config.HasCertificatePair() &&
        !ConfigureTlsCertificatePem(ctx, *config.pem)) {
        LOG_ERROR("failed to load TLS client certificate from {}", config.cert_file);
        return nullptr;
    }

    if (config.allow_insecure && !config.ca_file.empty()) {
        LOG_ERROR("TLS client CA cannot be used when certificate verification is disabled");
        return nullptr;
    }
    if (config.allow_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        const bool trust_loaded = config.ca_file.empty()
            ? SSL_CTX_set_default_verify_paths(ctx) == 1
            : ConfigureTlsTrustedCaPem(ctx, config.pem->trusted_ca);
        if (!trust_loaded) {
            LOG_ERROR("failed to load TLS client trust store from {}",
                      config.ca_file.empty() ? "system defaults"
                                             : config.ca_file);
            return nullptr;
        }
    }

    return std::unique_ptr<SslContext>(new SslContext(std::move(owner)));
}

SslContext::~SslContext() = default;
