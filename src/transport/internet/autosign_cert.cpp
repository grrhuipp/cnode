#include "autosign_cert.hpp"
#include "infra/log.hpp"

#include <openssl/asn1.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cerrno>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace transport::internet {
namespace {

EVP_PKEY* GenerateEcP256Key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* generated = nullptr;
    if (!pctx ||
        EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx, &generated) <= 0) {
        if (pctx) EVP_PKEY_CTX_free(pctx);
        if (generated) EVP_PKEY_free(generated);
        return nullptr;
    }
    EVP_PKEY_CTX_free(pctx);
    return generated;
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

    X509_EXTENSION* extension = built
        ? X509V3_EXT_i2d(NID_subject_alt_name, 0, names)
        : nullptr;
    const bool added = extension && X509_add_ext(certificate, extension, -1) == 1;
    if (extension) X509_EXTENSION_free(extension);
    GENERAL_NAMES_free(names);
    return added;
}

}  // namespace

AutoSignCertificate::~AutoSignCertificate() {
    X509_free(certificate_);
    EVP_PKEY_free(key_);
}

std::unique_ptr<AutoSignCertificate> AutoSignCertificate::Create(std::string_view identity) {
    // RFC 5280's commonName limit is 64 characters, not a DNS SAN limit.
    // DNS identities belong in SAN; a descriptive CN covers longer names.
    if (identity.empty() || identity.find('\0') != std::string_view::npos) return {};
    if (identity.ends_with('.')) identity.remove_suffix(1);
    if (identity.empty() || identity.ends_with('.')) return {};
    const std::string name_text(identity);
    const std::string_view cn = identity.size() <= 64
        ? identity : std::string_view("acppnode self-signed certificate");
    auto material = std::unique_ptr<AutoSignCertificate>(new AutoSignCertificate);
    material->key_ = GenerateEcP256Key();
    material->certificate_ = X509_new();
    if (!material->key_ || !material->certificate_) {
        ERR_clear_error();
        return {};
    }
    X509* x509 = material->certificate_;
    X509_NAME* name = X509_get_subject_name(x509);
    // These credentials are regenerated on configuration reload/restart,
    // never in response to untrusted ClientHello traffic.
    constexpr long kValiditySeconds = 365L * 24 * 60 * 60;
    if (X509_set_version(x509, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) != 1 ||
        !X509_gmtime_adj(X509_get_notBefore(x509), -300) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), kValiditySeconds) ||
        X509_set_pubkey(x509, material->key_) != 1 ||
        !name ||
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(cn.data()),
            static_cast<int>(cn.size()), -1, 0) != 1 ||
        X509_set_issuer_name(x509, name) != 1 ||
        !AddSubjectAlternativeNames(x509, name_text) ||
        X509_sign(x509, material->key_, EVP_sha256()) <= 0) {
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
                renewed = due->Publish(due->builder_());
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

AutoSignContextRenewal::AutoSignContextRenewal(std::shared_ptr<SSL_CTX> initial, Builder builder)
    : builder_(std::move(builder)) {
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
    std::shared_ptr<SSL_CTX> initial, Builder builder) {
    auto state = std::shared_ptr<AutoSignContextRenewal>(
        new AutoSignContextRenewal(std::move(initial), std::move(builder)));
    AutoSignRenewalScheduler::Instance().Add(state);
    return state;
}

std::shared_ptr<SSL_CTX> AutoSignContextRenewal::Acquire(Clock::time_point now) const noexcept {
    const auto snapshot = current_.load(std::memory_order_acquire);
    if (!snapshot || now >= snapshot->expires) return {};
    return snapshot->context;
}
