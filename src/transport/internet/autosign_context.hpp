#pragma once

#include <openssl/ossl_typ.h>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>


// One registration per prepared configuration, not per Worker or handshake.
// A single bounded background scheduler signs and publishes immutable contexts.
class AutoSignContextRenewal {
public:
    using Clock = std::chrono::system_clock;
    using Builder = std::function<std::shared_ptr<SSL_CTX>()>;
    static std::shared_ptr<AutoSignContextRenewal> Start(
        std::shared_ptr<SSL_CTX> initial, Builder builder);
    [[nodiscard]] std::shared_ptr<SSL_CTX> Acquire(Clock::time_point now = Clock::now()) const noexcept;
private:
    friend class AutoSignRenewalScheduler;
    struct Snapshot {
        std::shared_ptr<SSL_CTX> context;
        Clock::time_point expires;
    };
    AutoSignContextRenewal(std::shared_ptr<SSL_CTX> initial, Builder builder);
    bool Publish(std::shared_ptr<SSL_CTX> context);
    std::atomic<std::shared_ptr<const Snapshot>> current_;
    Builder builder_;
    std::atomic<Clock::time_point> next_attempt_{Clock::time_point::min()};
};

