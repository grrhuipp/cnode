#pragma once

#include "common/allocator.hpp"
#include "transport/internet/timeout_scheduler.hpp"

#include <stdexcept>


// Owned by Worker::RuntimeState. Start/Stop and all notifications run on its
// executor. The allocator reports only empty-FIFO transitions, not every free.
class WorkerMemoryReclaimer final : private TimeoutMaintenance,
                                    private memory::worker_memory::IdleWakeup {
public:
    WorkerMemoryReclaimer() = default;
    WorkerMemoryReclaimer(const WorkerMemoryReclaimer&) = delete;
    WorkerMemoryReclaimer& operator=(const WorkerMemoryReclaimer&) = delete;
    ~WorkerMemoryReclaimer() { Stop(); }

    void Start(TimeoutScheduler& scheduler) {
        if (pool_) return;
        scheduler_ = &scheduler;
        pool_ = &memory::ThreadMemoryPool();
        if (!pool_->BindIdleWakeup(*this)) {
            pool_ = nullptr;
            scheduler_ = nullptr;
            throw std::logic_error("Worker pool already has a reclaimer");
        }
    }
    void Stop() noexcept {
        if (!pool_) return;
        pool_->UnbindIdleWakeup(*this);
        scheduler_->CancelMaintenance(*this);
        pool_->PurgeIdle();
        pool_ = nullptr;
        scheduler_ = nullptr;
    }

private:
    void OnPoolIdle() noexcept override { Schedule(); }
    void OnMaintenance() noexcept override {
        pool_->Purge();
        Schedule();
    }
    void Schedule() noexcept {
        const auto deadline = pool_->NextPurgeDeadline();
        if (deadline == memory::worker_memory::Clock::time_point::max()) {
            scheduler_->CancelMaintenance(*this);
            return;
        }
        try {
            if (scheduler_->SetMaintenanceDeadline(*this, deadline)) return;
        } catch (...) {
            // Deallocation remains noexcept, including an OOM in Asio's timer
            // initiation. Return empty mappings now rather than lose the wakeup.
        }
        scheduler_->CancelMaintenance(*this);
        pool_->PurgeIdle();
    }

    memory::worker_memory* pool_ = nullptr;
    TimeoutScheduler* scheduler_ = nullptr;
};

