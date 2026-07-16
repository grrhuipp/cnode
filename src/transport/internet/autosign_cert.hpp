#pragma once

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <chrono>
#include <list>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace acpp::transport::internet {

[[nodiscard]] std::string NormalizeAutoSignCertificateName(std::string_view name);

struct AutoSignMaterial {
    X509* cert = nullptr;
    EVP_PKEY* key = nullptr;
};

class AutoSignState {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr size_t kMaxCachedCerts = 256;
    static constexpr auto kRotateInterval = std::chrono::minutes(5);

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

    bool EnsureKeyLocked(Clock::time_point now);
    void ClearCertCacheLocked();

    EVP_PKEY* pkey_ = nullptr;
    Clock::time_point key_created_at_{};
    std::mutex mu_;
    std::unordered_map<std::string, CachedCert> cert_cache_;
    std::list<std::string> cert_lru_;
    long next_serial_ = 1;
};

AutoSignState& GetAutoSignState();

}  // namespace acpp::transport::internet
