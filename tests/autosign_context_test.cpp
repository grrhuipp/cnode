#include <gtest/gtest.h>

#include "autosign_cert.hpp"
#include "autosign_context.hpp"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>
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
    constexpr long kYear = 365L * 24 * 60 * 60;
    auto initial = Context(kTenDays);
    SSL* established = SSL_new(initial.get());
    ASSERT_FALSE((!Require(established != nullptr, "old SSL must retain its certificate snapshot")));
    std::atomic<unsigned> builds{0};
    std::atomic<bool> background{false};
    const auto main_thread = std::this_thread::get_id();
    auto renewal = Renewal::Start(initial, [&] {
        background.store(std::this_thread::get_id() != main_thread);
        ++builds;
        return Context(kYear);
    });
    ASSERT_FALSE((!Require(Await([&] { return renewal->Acquire().get() != initial.get(); }),
                 "due certificate must publish a renewed immutable snapshot")));
    ASSERT_FALSE((!Require(builds == 1 && background,
                 "renewal must run once on a background thread, not a handshake thread")));
    auto replacement = renewal->Acquire();
    ASSERT_FALSE((!Require(replacement && SSL_get_SSL_CTX(established) == initial.get() &&
                    SSL_CTX_get0_certificate(replacement.get()) != SSL_get_certificate(established),
                 "publishing renewal must not mutate established SSL's old context")));
    SSL_free(established);
    for (int i = 0; i < 1000; ++i) {
        ASSERT_FALSE((!Require(renewal->Acquire() == replacement, "snapshot acquisition must not invoke signing")));
    }
    ASSERT_FALSE((!Require(builds == 1, "handshake snapshot acquisition must not enqueue renewal")));

    std::atomic<unsigned> failures{0};
    auto old = Context(kTenDays);
    auto failing = Renewal::Start(old, [&]() -> std::shared_ptr<SSL_CTX> {
        ++failures;
        throw std::runtime_error("injected renewal failure");
    });
    ASSERT_FALSE((!Require(Await([&] { return failures.load() != 0; }),
                 "due failed renewal must exercise background builder")));
    ASSERT_FALSE((!Require(failing->Acquire() == old,
                 "renew failure must retain a still-valid previous certificate")));
    ASSERT_FALSE((!Require(!failing->Acquire(Renewal::Clock::now() + std::chrono::hours(24 * 11)),
                 "expired certificate must fail closed even when renewal failed")));
    ASSERT_FALSE((!Require(!renewal->Acquire(Renewal::Clock::now() + std::chrono::hours(24 * 366)),
                 "snapshot validity must be enforced at notAfter")));
}
