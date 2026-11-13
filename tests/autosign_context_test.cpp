#include <gtest/gtest.h>

#include "transport/tls_context.hpp"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
using Renewal = ::transport::AutoSignContextRenewal;
using namespace std::chrono_literals;

bssl::UniquePtr<SSL_CTX> Context(long validity_seconds) {
    auto certificate = ::transport::AutoSignCertificate::Create("renewal.example");
    if (!certificate || !X509_gmtime_adj(X509_get_notAfter(certificate->Certificate()), validity_seconds) ||
        X509_sign(certificate->Certificate(), certificate->Key(), EVP_sha256()) <= 0)
        throw std::runtime_error("test certificate construction failed");
    bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_server_method()));
    if (!context || SSL_CTX_use_certificate(context.get(), certificate->Certificate()) != 1 ||
        SSL_CTX_use_PrivateKey(context.get(), certificate->Key()) != 1)
        throw std::runtime_error("test SSL_CTX construction failed");
    return context;
}
::transport::TlsConfig RenewalConfig(std::string server_name) {
    ::transport::TlsConfig config;
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

TEST(AutosignContext, RenewalPublishesNewSnapshotWithoutMutatingEstablishedConnection) {
    constexpr long kTenDays = 10L * 24 * 60 * 60;
    auto initial = Context(kTenDays);
    SSL_CTX* initial_ptr = initial.get();
    std::unique_ptr<SSL, decltype(&SSL_free)> established(SSL_new(initial_ptr), SSL_free);
    ASSERT_NE(established, nullptr);
    auto renewal = Renewal::Start(std::move(initial), RenewalConfig("renewal.example"));
    ASSERT_TRUE(Await([&] { return renewal->Acquire() != initial_ptr; }));
    SSL_CTX* replacement = renewal->Acquire();
    ASSERT_NE(replacement, nullptr);
    EXPECT_EQ(SSL_get_SSL_CTX(established.get()), initial_ptr);
    EXPECT_NE(SSL_CTX_get0_certificate(replacement), SSL_get_certificate(established.get()));
    EXPECT_EQ(renewal->Acquire(Renewal::Clock::now() + std::chrono::hours(24 * 11)), replacement);
}

TEST(AutosignContext, FailedRenewalRetainsValidSnapshotButRejectsExpiredSnapshot) {
    constexpr long kTenDays = 10L * 24 * 60 * 60;
    auto old = Context(kTenDays);
    SSL_CTX* old_ptr = old.get();
    auto config = RenewalConfig("failing.example");
    config.min_version = ::transport::TlsVersion::V1_3;
    config.max_version = ::transport::TlsVersion::V1_2;
    auto failing = Renewal::Start(std::move(old), config);

    // The scheduler processes due registrations in order. A later successful
    // renewal is a barrier proving the earlier failed renewal was attempted.
    auto barrier_context = Context(kTenDays);
    SSL_CTX* barrier_ptr = barrier_context.get();
    auto barrier = Renewal::Start(std::move(barrier_context), RenewalConfig("renewal.example"));
    ASSERT_TRUE(Await([&] { return barrier->Acquire() != barrier_ptr; }));
    EXPECT_EQ(failing->Acquire(), old_ptr);
    EXPECT_EQ(failing->Acquire(Renewal::Clock::now() + std::chrono::hours(24 * 11)), nullptr);
}

TEST(AutosignContext, RenewedSnapshotFailsClosedAfterNotAfter) {
    auto initial = Context(10L * 24 * 60 * 60);
    SSL_CTX* initial_ptr = initial.get();
    auto renewal = Renewal::Start(std::move(initial), RenewalConfig("renewal.example"));
    ASSERT_TRUE(Await([&] { return renewal->Acquire() != initial_ptr; }));
    EXPECT_EQ(renewal->Acquire(Renewal::Clock::now() + std::chrono::hours(24 * 366)), nullptr);
}
