#include "app/session_group_executor.hpp"
#include "common/error.hpp"
#include "infra/log.hpp"

#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <sys/eventfd.h>
#include <unistd.h>
#include <cerrno>
#include <atomic>
#include <algorithm>
#include <stdexcept>
#include <system_error>


struct GroupCoordinator::ReservedState {
    explicit ReservedState(net::io_context& io)
        : event(io), stopped(io, 1) {
        const int descriptor = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (descriptor < 0) throw IoSystemError(IoErrorCode(errno, std::system_category()));
        IoErrorCode error;
        event.assign(descriptor, error);
        if (error) { ::close(descriptor); throw IoSystemError(error); }
    }
    net::posix::stream_descriptor event;
    SignalChannel stopped;
    std::atomic<ReservedOperation*> incoming{nullptr};
    std::atomic<bool> started{false};
    bool stopping = false;
    bool joined = false;
    std::atomic<uint32_t> worker_count{0};
    memory::Vector<net::io_context*> workers;
};

GroupCoordinator::GroupCoordinator(net::io_context& io, size_t capacity)
    : reactor_(io), mailbox_(io, capacity),
      reserved_(std::make_unique<ReservedState>(io)) {}

GroupCoordinator::~GroupCoordinator() {
    if (reserved_->started.load(std::memory_order_relaxed) && !reserved_->joined)
        FailRuntime("group-coordinator", "reserved controls were not joined");
    DrainReserved();
}

void GroupCoordinator::EnsureStarted() {
    if (reserved_->started.load(std::memory_order_relaxed) || reserved_->joined) return;
    ArmReserved();
    reserved_->started.store(true, std::memory_order_release);
}

void GroupCoordinator::Start() {
    if (reserved_->started.load(std::memory_order_acquire)) return;
    net::post(reactor_, [self = shared_from_this()] { self->EnsureStarted(); });
}


void GroupCoordinator::RegisterWorker(net::io_context& reactor) {
    // Fixed cold-path routes only; consumers receive this coordinator directly.
    if (std::find(reserved_->workers.begin(), reserved_->workers.end(), &reactor) ==
        reserved_->workers.end()) {
        reserved_->workers.push_back(&reactor);
        reserved_->worker_count.fetch_add(1, std::memory_order_release);
    }
}

uint32_t GroupCoordinator::WorkerCount() const noexcept {
    return reserved_->worker_count.load(std::memory_order_acquire);
}


void GroupCoordinator::PostReserved(std::unique_ptr<ReservedOperation> operation) noexcept {
    auto* node = operation.release();
    auto* previous = reserved_->incoming.load(std::memory_order_relaxed);
    do { node->next = previous; }
    while (!reserved_->incoming.compare_exchange_weak(previous, node,
        std::memory_order_release, std::memory_order_relaxed));
    const uint64_t one = 1;
    ssize_t written;
    do { written = ::write(reserved_->event.native_handle(), &one, sizeof(one)); }
    while (written < 0 && errno == EINTR);
    if (written < 0 && errno != EAGAIN)
        FailRuntime("group-coordinator", "cannot notify reserved return");
}

void GroupCoordinator::DrainReserved() noexcept {
    for (;;) {
        auto* batch = reserved_->incoming.exchange(nullptr, std::memory_order_acquire);
        if (!batch) return;
        ReservedOperation* fifo = nullptr;
        while (batch) {
            auto* next = batch->next;
            batch->next = fifo;
            fifo = batch;
            batch = next;
        }
        while (fifo) {
            std::unique_ptr<ReservedOperation> operation(fifo);
            fifo = fifo->next;
            operation->Invoke();
        }
    }
}

void GroupCoordinator::ArmReserved() {
    try {
        reserved_->event.async_wait(net::posix::stream_descriptor::wait_read,
            [this](IoErrorCode error) {
                uint64_t count;
                while (::read(reserved_->event.native_handle(), &count, sizeof(count)) > 0) {}
                DrainReserved();
                if (reserved_->stopping) {
                    (void)reserved_->stopped.try_send(IoErrorCode{});
                    return;
                }
                if (error) FailRuntime("group-coordinator", "reserved return readiness failed");
                ArmReserved();
            });
    } catch (...) {
        reserved_->started.store(false, std::memory_order_release);
        throw;
    }
}

net::awaitable<void> GroupCoordinator::AsyncJoin() {
    co_await mailbox_.AsyncJoinAccepted();
    DrainReserved();
}

net::awaitable<void> GroupCoordinator::Finalize() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (reserved_->joined) co_return;
    reserved_->stopping = true;
    IoErrorCode error;
    if (reserved_->started.load(std::memory_order_relaxed)) {
        reserved_->event.cancel(error);
        co_await reserved_->stopped.async_receive(net::use_awaitable);
    }
    DrainReserved();
    reserved_->joined = true;
}
