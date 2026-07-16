#pragma once

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <chrono>
#include <list>
#include <string>
#include <unordered_map>

namespace acpp::transport::internet {

struct AutoSignMaterial {
    X509* cert = nullptr;
    EVP_PKEY* key = nullptr;
};

class AutoSignState {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr size_t kMaxCachedCerts = 256;
    static constexpr auto kRotateInterval = std::chrono::minutes(5);

    // Owned by one Worker-local TLS context; not thread-safe by design.
    AutoSignState() = default;
    ~AutoSignState();

    AutoSignState(const AutoSignState&) = delete;
    AutoSignState& operator=(const AutoSignState&) = delete;

    [[nodiscard]] AutoSignMaterial GetOrCreate(const std::string& cn);
    [[nodiscard]] AutoSignMaterial GetOrCreate(const std::string& cn, Clock::time_point now);

private:
    struct CachedCert {
        X509* cert = nullptr;
        std::list<std::string>::iterator lru_it;
    };

    bool EnsureKey(Clock::time_point now);
    void ClearCertCache();

    EVP_PKEY* pkey_ = nullptr;
    Clock::time_point key_created_at_{};
    std::unordered_map<std::string, CachedCert> cert_cache_;
    std::list<std::string> cert_lru_;
    long next_serial_ = 1;
};

}  // namespace acpp::transport::internet
