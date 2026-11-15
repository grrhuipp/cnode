#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "common/spsc_ring.hpp"

#include <asio/post.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <sys/eventfd.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <concepts>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace common {

// A message crosses Workers as a plain copy. Whatever it owns (a Buffer, a
// key) is taken by the receiver, or released by ReleaseWorkerMessage when the
// message is dropped undelivered.
template <class Message>
concept WorkerMessage = std::is_trivially_copyable_v<Message> &&
    requires(Message& message) {
        { ReleaseWorkerMessage(message) } noexcept;
    };

// The rings and doorbells connecting the Workers of one subsystem: one SPSC
// ring per ordered Worker pair, one eventfd per Worker. Shared by all
// endpoints, so no producer touches a ring or eventfd that is gone.
template <WorkerMessage Message, size_t Slots>
class WorkerMesh final {
public:
    struct alignas(64) Door {
        int fd = -1;
        // Set by the consumer before it sleeps; a producer that clears it
        // writes the eventfd. Cleared means a drain is pending or running.
        std::atomic<bool> armed{true};
        // The endpoint stopped consuming; messages toward it are dropped.
        std::atomic<bool> closed{false};
    };
    struct alignas(64) Lane {
        SpscRing<Message, Slots> ring;
        // Set by the producer when its backlog found the ring full; the
        // consumer rings the producer after making room.
        std::atomic<bool> space_wanted{false};
    };

    explicit WorkerMesh(std::span<net::io_context* const> workers)
        : contexts(workers.begin(), workers.end())
        , doors(std::make_unique<Door[]>(workers.size()))
        // Default-initialized: ring slots are raw storage, so an idle lane
        // costs no resident memory beyond its indexes.
        , lanes(std::make_unique_for_overwrite<Lane[]>(workers.size() * workers.size())) {
        for (size_t i = 0; i < contexts.size(); ++i) {
            doors[i].fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
            if (doors[i].fd < 0) {
                const int error = errno;
                CloseDoors();
                throw IoSystemError(IoErrorCode(error, std::system_category()));
            }
        }
    }

    ~WorkerMesh() {
        // Every endpoint is gone: nothing produces or consumes any more.
        for (size_t i = 0; i < contexts.size() * contexts.size(); ++i) {
            Message message;
            while (lanes[i].ring.TryPop(message)) ReleaseWorkerMessage(message);
        }
        CloseDoors();
    }

    WorkerMesh(const WorkerMesh&) = delete;
    WorkerMesh& operator=(const WorkerMesh&) = delete;

    [[nodiscard]] size_t Size() const noexcept { return contexts.size(); }

    [[nodiscard]] std::optional<size_t> IndexOf(const net::io_context& worker) const noexcept {
        for (size_t i = 0; i < contexts.size(); ++i) {
            if (contexts[i] == &worker) return i;
        }
        return std::nullopt;
    }

    [[nodiscard]] Lane& Between(size_t from, size_t to) noexcept {
        return lanes[from * contexts.size() + to];
    }

    // After publishing toward `to`: the seq_cst fence orders the publication
    // before reading `armed`, pairing with the consumer's fence between
    // setting `armed` and its final check of the rings.
    void Ring(size_t to) noexcept {
        std::atomic_thread_fence(std::memory_order_seq_cst);
        auto& door = doors[to];
        if (!door.armed.load(std::memory_order_relaxed) ||
            !door.armed.exchange(false, std::memory_order_acq_rel)) {
            return;
        }
        const uint64_t one = 1;
        ssize_t written;
        do { written = ::write(door.fd, &one, sizeof(one)); }
        while (written < 0 && errno == EINTR);
        // EAGAIN: the counter is saturated, so the eventfd is readable anyway.
        if (written < 0 && errno != EAGAIN) {
            FailRuntime("worker-mesh", "cannot ring Worker doorbell");
        }
    }

    std::vector<net::io_context*> contexts;
    std::unique_ptr<Door[]> doors;
    std::unique_ptr<Lane[]> lanes;

private:
    void CloseDoors() noexcept {
        for (size_t i = 0; i < contexts.size(); ++i) {
            if (doors[i].fd >= 0) ::close(std::exchange(doors[i].fd, -1));
        }
    }
};

// One Worker's end of a mesh. Every member runs on that Worker's thread.
// `Receiver::Receive(size_t from, Message&) noexcept` takes each incoming
// message; what it leaves owned in the message is released afterwards.
template <class Receiver, WorkerMessage Message, size_t Slots>
class WorkerMeshEndpoint final {
public:
    using Mesh = WorkerMesh<Message, Slots>;

    WorkerMeshEndpoint(Receiver& receiver, net::io_context& io,
                       std::shared_ptr<Mesh> mesh, size_t index)
        : receiver_(receiver), io_(io), mesh_(std::move(mesh)), index_(index)
        , door_(io), backlogs_(mesh_->Size()) {
        IoErrorCode error;
        door_.assign(mesh_->doors[index_].fd, error);
        if (error) throw IoSystemError(error);
        net::post(io_, [this] { Arm(); });
    }

    ~WorkerMeshEndpoint() {
        // The mesh owns the eventfd; it outlives this endpoint.
        Shutdown();
    }

    WorkerMeshEndpoint(const WorkerMeshEndpoint&) = delete;
    WorkerMeshEndpoint& operator=(const WorkerMeshEndpoint&) = delete;

    [[nodiscard]] size_t Index() const noexcept { return index_; }
    [[nodiscard]] size_t Size() const noexcept { return mesh_->Size(); }
    [[nodiscard]] net::io_context& Context() const noexcept { return io_; }
    [[nodiscard]] std::optional<size_t> IndexOf(const net::io_context& worker) const noexcept {
        return mesh_->IndexOf(worker);
    }

    // Sends `message` to Worker `to`; a full ring keeps it, in order, until
    // the consumer makes room. Toward a stopped Worker it is released.
    void Post(size_t to, Message message) {
        if (stopping_ || mesh_->doors[to].closed.load(std::memory_order_acquire)) {
            ReleaseWorkerMessage(message);
            return;
        }
        auto& backlog = backlogs_[to];
        if (backlog.empty() && mesh_->Between(index_, to).ring.TryPush(message)) {
            mesh_->Ring(to);
            return;
        }
        try {
            backlog.push_back(message);
        } catch (...) {
            ReleaseWorkerMessage(message);
            throw;
        }
        Flush(to);
    }

    // Like Post, for messages that may be lost (datagrams): with
    // `max_backlog` messages already waiting for room toward `to`, or on
    // allocation failure, the message is released and false returned.
    bool TryPost(size_t to, Message message, size_t max_backlog) noexcept {
        if (backlogs_[to].size() >= max_backlog) {
            ReleaseWorkerMessage(message);
            return false;
        }
        try {
            Post(to, message);
        } catch (...) {
            return false;
        }
        return true;
    }

    // The Worker stops: nothing more is consumed or accepted, and the
    // endpoint no longer keeps its io_context running.
    void Stop() noexcept {
        if (stopping_) return;
        stopping_ = true;
        mesh_->doors[index_].closed.store(true, std::memory_order_release);
        IoErrorCode error;
        door_.cancel(error);
    }

    // The io_context is shutting down: drops what this Worker still holds.
    void Shutdown() noexcept {
        Stop();
        if (door_.is_open()) {
            IoErrorCode error;
            door_.cancel(error);
            (void)door_.release();
        }
        for (auto& backlog : backlogs_) {
            while (!backlog.empty()) {
                ReleaseWorkerMessage(backlog.front());
                backlog.pop_front();
            }
        }
    }

private:
    // Messages handled per wake before other handlers of the Worker run.
    static constexpr size_t kDrainBatch = 512;

    void Arm() {
        if (stopping_) return;
        door_.async_wait(net::posix::stream_descriptor::wait_read, [this](IoErrorCode error) {
            if (error || stopping_) return;
            uint64_t count;
            while (::read(door_.native_handle(), &count, sizeof(count)) > 0) {}
            Drain();
        });
    }

    [[nodiscard]] bool AnyIncoming() noexcept {
        for (size_t from = 0; from < Size(); ++from) {
            if (from != index_ && !mesh_->Between(from, index_).ring.Empty()) return true;
        }
        return false;
    }

    [[nodiscard]] bool AnyFlushable() noexcept {
        for (size_t to = 0; to < Size(); ++to) {
            if (!backlogs_[to].empty() && mesh_->Between(index_, to).ring.HasRoom()) return true;
        }
        return false;
    }

    // Handles every incoming message, then sleeps on the doorbell. A full
    // batch yields to the Worker's other handlers and continues later.
    void Drain() {
        size_t handled = 0;
        for (;;) {
            bool any = false;
            for (size_t from = 0; from < Size(); ++from) {
                if (from == index_) continue;
                auto& lane = mesh_->Between(from, index_);
                Message message;
                bool popped = false;
                while (handled < kDrainBatch && lane.ring.TryPop(message)) {
                    popped = true;
                    ++handled;
                    receiver_.Receive(from, message);
                    ReleaseWorkerMessage(message);
                    if (stopping_) return;
                }
                if (!popped) continue;
                any = true;
                // Pairs with the producer's fence between setting
                // space_wanted and rechecking for room.
                std::atomic_thread_fence(std::memory_order_seq_cst);
                if (lane.space_wanted.load(std::memory_order_relaxed) &&
                    lane.space_wanted.exchange(false, std::memory_order_acq_rel)) {
                    mesh_->Ring(from);
                }
            }
            for (size_t to = 0; to < Size(); ++to) {
                if (!backlogs_[to].empty()) Flush(to);
            }
            if (stopping_) return;
            if (handled >= kDrainBatch) {
                net::post(io_, [this] { Drain(); });
                return;
            }
            if (any) continue;
            auto& armed = mesh_->doors[index_].armed;
            armed.store(true, std::memory_order_seq_cst);
            std::atomic_thread_fence(std::memory_order_seq_cst);
            if (!AnyIncoming() && !AnyFlushable()) break;
            // Work raced in; a producer may also have rung, which only adds
            // one spurious wake.
            armed.store(false, std::memory_order_relaxed);
        }
        Arm();
    }

    void Flush(size_t to) noexcept {
        auto& backlog = backlogs_[to];
        auto& lane = mesh_->Between(index_, to);
        bool pushed = false;
        for (;;) {
            while (!backlog.empty() && lane.ring.TryPush(backlog.front())) {
                backlog.pop_front();
                pushed = true;
            }
            if (backlog.empty()) break;
            lane.space_wanted.store(true, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_seq_cst);
            if (!lane.ring.HasRoom()) break;
        }
        if (pushed) mesh_->Ring(to);
    }

    Receiver& receiver_;
    net::io_context& io_;
    std::shared_ptr<Mesh> mesh_;
    size_t index_;
    net::posix::stream_descriptor door_;
    // Messages that found the ring toward each Worker full.
    std::vector<RingDeque<Message>> backlogs_;
    bool stopping_ = false;
};

// Holds one Worker's instance of a mesh subsystem as a service of its
// io_context, whose shutdown stops the subsystem before anything it
// references is destroyed. `Subsystem` is constructed from (io_context,
// shared mesh, Worker index) and provides Stop() and Shutdown().
template <class Subsystem>
class WorkerMeshHost final : public net::execution_context::service {
public:
    static inline net::execution_context::id id;
    // Required by lookup through use_service, which follows has_service.
    explicit WorkerMeshHost(net::execution_context& context)
        : net::execution_context::service(context) {}
    WorkerMeshHost(net::execution_context& context, std::unique_ptr<Subsystem> subsystem)
        : net::execution_context::service(context), subsystem(std::move(subsystem)) {}

    std::unique_ptr<Subsystem> subsystem;

private:
    void shutdown() override {
        if (subsystem) subsystem->Shutdown();
    }
};

// Connects the io_contexts of all Workers. Call once, before they run; with
// fewer than two Workers nothing crosses Workers and nothing is installed.
template <class Subsystem>
void InstallWorkerMesh(std::span<net::io_context* const> workers) {
    if (workers.size() < 2) return;
    auto mesh = std::make_shared<typename Subsystem::Mesh>(workers);
    for (size_t i = 0; i < workers.size(); ++i) {
        (void)net::make_service<WorkerMeshHost<Subsystem>>(
            *workers[i], std::make_unique<Subsystem>(*workers[i], mesh, i));
    }
}

// The subsystem instance of `io_context`, or null when none is installed.
template <class Subsystem>
[[nodiscard]] Subsystem* FindWorkerMesh(net::io_context& io_context) noexcept {
    if (!net::has_service<WorkerMeshHost<Subsystem>>(io_context)) return nullptr;
    return net::use_service<WorkerMeshHost<Subsystem>>(io_context).subsystem.get();
}

// Stops the subsystem instance of `io_context`, if any, on its own thread.
template <class Subsystem>
void StopWorkerMesh(net::io_context& io_context) noexcept {
    if (auto* subsystem = FindWorkerMesh<Subsystem>(io_context)) subsystem->Stop();
}

}  // namespace common
