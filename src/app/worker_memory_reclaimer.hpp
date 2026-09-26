#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <stdexcept>

namespace acpp {

// Owned by Worker::RuntimeState. Start/Stop and all notifications run on its
// executor. The allocator reports only empty-FIFO transitions, not every free.
class WorkerMemoryReclaimer {
public:
    WorkerMemoryReclaimer() = default;
    WorkerMemoryReclaimer(const WorkerMemoryReclaimer&) = delete;
    WorkerMemoryReclaimer& operator=(const WorkerMemoryReclaimer&) = delete;
    ~WorkerMemoryReclaimer() { Stop(); }

    void Start(TimeoutScheduler& scheduler) {
        if (pool_) return;
        scheduler_ = &scheduler;
        pool_ = &memory::ThreadPool();
        if (!pool_->BindIdleWakeup(this, &Wakeup)) {
            pool_ = nullptr;
            scheduler_ = nullptr;
            throw std::logic_error("Worker pool already has a reclaimer");
        }
    }
    void Stop() noexcept {
        if (!pool_) return;
        pool_->UnbindIdleWakeup(this);
        scheduler_->CancelMaintenance(this);
        pool_->PurgeIdle();
        pool_ = nullptr;
        scheduler_ = nullptr;
    }

private:
    static void Wakeup(void* owner) noexcept {
        static_cast<WorkerMemoryReclaimer*>(owner)->Schedule();
    }
    static void Collect(void* owner) noexcept {
        auto& self = *static_cast<WorkerMemoryReclaimer*>(owner);
        self.pool_->Purge();
        self.Schedule();
    }
    void Schedule() noexcept {
        const auto deadline = pool_->NextPurgeDeadline();
        if (deadline == memory::ReturningThreadPool::Clock::time_point::max()) {
            scheduler_->CancelMaintenance(this);
            return;
        }
        try {
            if (scheduler_->SetMaintenanceDeadline(this, &Collect, deadline)) return;
        } catch (...) {
            // Deallocation remains noexcept, including an OOM in Asio's timer
            // initiation. Return empty mappings now rather than lose the wakeup.
        }
        scheduler_->CancelMaintenance(this);
        pool_->PurgeIdle();
    }

    memory::ReturningThreadPool* pool_ = nullptr;
    TimeoutScheduler* scheduler_ = nullptr;
};

} // namespace acpp
