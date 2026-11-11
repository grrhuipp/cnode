#include <gtest/gtest.h>

#include "transport/internet/tls_context.hpp"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
using Renewal = ::AutoSignContextRenewal;
using namespace std::chrono_literals;

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}
std::shared_ptr<SSL_CTX> Context(long validity_seconds) {
    auto certificate = ::transport::internet::AutoSignCertificate::Create("renewal.example");
    if (!certificate || !X509_gmtime_adj(X509_get_notAfter(certificate->Certificate()), validity_seconds) ||
        X509_sign(certificate->Certificate(), certificate->Key(), EVP_sha256()) <= 0)
        throw std::runtime_error("test certificate construction failed");
    std::shared_ptr<SSL_CTX> context(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    if (!context || SSL_CTX_use_certificate(context.get(), certificate->Certificate()) != 1 ||
        SSL_CTX_use_PrivateKey(context.get(), certificate->Key()) != 1)
        throw std::runtime_error("test SSL_CTX construction failed");
    return context;
}
::TlsConfig RenewalConfig(std::string server_name) {
    ::TlsConfig config;
    config.server_name = std::move(server_name);
    return config;
}
template<class Predicate> bool Await(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(1ms);
    }
    return true;
}
}

TEST(AutosignContext, Contract) {
    // An actual certificate inside the 30-day renewal window is immediately
    // due. No clock changes, production timeouts, or 30-day sleeps are needed.
    constexpr long kTenDays = 10L * 24 * 60 * 60;
    const auto after_ten_days = Renewal::Clock::now() + std::chrono::hours(24 * 11);

    // 调度器按登记顺序处理到期项：先登记的失败续期在后续成功续期发布之前必已尝试。
    // 版本区间为空，使重建在签发后的上下文配置阶段失败。
    auto old = Context(kTenDays);
    auto failing_config = RenewalConfig("failing.example");
    failing_config.min_version = ::TlsVersion::V1_3;
    failing_config.max_version = ::TlsVersion::V1_2;
    auto failing = Renewal::Start(old, failing_config);

    auto initial = Context(kTenDays);
    SSL* established = SSL_new(initial.get());
    ASSERT_FALSE((!Require(established != nullptr, "old SSL must retain its certificate snapshot")));
    auto renewal = Renewal::Start(initial, RenewalConfig("renewal.example"));
    ASSERT_FALSE((!Require(Await([&] { return renewal->Acquire().get() != initial.get(); }),
                 "due certificate must publish a renewed immutable snapshot")));
    auto replacement = renewal->Acquire();
    ASSERT_FALSE((!Require(replacement && SSL_get_SSL_CTX(established) == initial.get() &&
                    SSL_CTX_get0_certificate(replacement.get()) != SSL_get_certificate(established),
                 "publishing renewal must not mutate established SSL's old context")));
    SSL_free(established);
    ASSERT_FALSE((!Require(renewal->Acquire(after_ten_days) == replacement,
                 "renewal must rebuild a one-year certificate from the configuration snapshot")));
    for (int i = 0; i < 1000; ++i) {
        ASSERT_FALSE((!Require(renewal->Acquire() == replacement, "snapshot acquisition must not invoke signing")));
    }

    ASSERT_FALSE((!Require(failing->Acquire() == old,
                 "renew failure must retain a still-valid previous certificate")));
    ASSERT_FALSE((!Require(!failing->Acquire(after_ten_days),
                 "expired certificate must fail closed even when renewal failed")));
    ASSERT_FALSE((!Require(!renewal->Acquire(Renewal::Clock::now() + std::chrono::hours(24 * 366)),
                 "snapshot validity must be enforced at notAfter")));
}
