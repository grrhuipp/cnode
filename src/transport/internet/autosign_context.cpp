#include "autosign_context.hpp"
#include "infra/log.hpp"

#include <openssl/asn1.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <algorithm>
#include <cerrno>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <vector>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>


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

