#include <gtest/gtest.h>

#include "transport/tls_context.hpp"
#include <openssl/x509.h>

#include <openssl/ssl.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>

#include <poll.h>
#include <sys/syscall.h>
#include <unistd.h>

// 本测试进程独占：替换 libc poll，以便对续签调度线程的等待注入一次暂时性故障。
// 其余调用原样经系统调用转发。
namespace {
std::atomic<int> poll_calls{0};
std::atomic<int> poll_failures_remaining{0};
}  // namespace

extern "C" int poll(pollfd* fds, nfds_t count, int timeout) {
    poll_calls.fetch_add(1, std::memory_order_relaxed);
    int remaining = poll_failures_remaining.load(std::memory_order_relaxed);
    while (remaining > 0) {
        if (poll_failures_remaining.compare_exchange_weak(remaining, remaining - 1)) {
            errno = ENOMEM;
            return -1;
        }
    }
    return static_cast<int>(::syscall(SYS_poll, fds, count, timeout));
}

namespace {

using Renewal = ::transport::AutoSignContextRenewal;

std::shared_ptr<Renewal> StartRenewal(std::string server_name) {
    constexpr long kThreeHundredDays = 300L * 24 * 60 * 60;
    auto certificate = ::transport::AutoSignCertificate::Create(server_name);
    if (!certificate || !X509_gmtime_adj(X509_get_notAfter(certificate->Certificate()), kThreeHundredDays) ||
        X509_sign(certificate->Certificate(), certificate->Key(), EVP_sha256()) <= 0)
        throw std::runtime_error("test certificate construction failed");
    bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_server_method()));
    if (!context || SSL_CTX_use_certificate(context.get(), certificate->Certificate()) != 1 ||
        SSL_CTX_use_PrivateKey(context.get(), certificate->Key()) != 1)
        throw std::runtime_error("test SSL_CTX construction failed");
    ::transport::TlsConfig config;
    config.server_name = std::move(server_name);
    return Renewal::Start(std::move(context), std::move(config));
}

TEST(AutosignScheduler, TransientWaitFailureDoesNotStopRenewal) {
    poll_failures_remaining = 1;
    const int calls_before = poll_calls.load();
    auto first = StartRenewal("first.example");
    ASSERT_NE(first->Acquire(), nullptr);

    // The injected failure is consumed, then the scheduler must wait again.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (poll_calls.load() < calls_before + 2 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_EQ(poll_failures_remaining.load(), 0);
    EXPECT_GE(poll_calls.load(), calls_before + 2);

    std::shared_ptr<Renewal> second;
    EXPECT_NO_THROW(second = StartRenewal("second.example"));
    ASSERT_NE(second, nullptr);
    EXPECT_NE(second->Acquire(), nullptr);
}

}  // namespace
