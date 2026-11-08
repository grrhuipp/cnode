#include "controller_impl.hpp"
#include "../../common/awaitable_batch.hpp"

#include "app/traffic_types.hpp"
#include "app/worker.hpp"
#include "core/naming.hpp"
#include "infra/log.hpp"
#include "common/online_device.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>

#include <cstdint>
#include <exception>
#include <iterator>
#include <format>
#include <vector>


net::awaitable<bool>
Controller::Impl::collectTraffic(PanelRuntime& panel, bool* appended_out) {
    // Do not abandon a durable append before its matching Worker commit.
    // Shutdown joins this critical section before taking its final snapshot.
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    // Only this panel loop may snapshot/commit its accounting key. The disk
    // executor never touches Worker-owned state and has bounded admission.
    bool appended = false;
    for (const auto& worker : workers_) {
        auto* w = worker.get();
        auto snapshot = co_await w->PostTask(w->SnapshotTraffic(panel.accounting_key));
        if (snapshot.empty()) continue;
        std::exception_ptr append_failure;
        try {
            co_await journal_executor_->Run([&panel, &snapshot] {
                panel.traffic_journal->Append(snapshot);
                return true;
            });
        } catch (...) {
            append_failure = std::current_exception();
        }
        if (append_failure) {
            // The snapshot token may be the last owner after a connection has
            // closed. Return it to the Worker ledger before unwinding.
            try {
                co_await w->PostTask(
                    w->RollbackTraffic(panel.accounting_key, snapshot));
            } catch (...) {
                panel.traffic_journal->Suspend();
                throw;
            }
            std::rethrow_exception(append_failure);
        }
        appended = true;
        if (appended_out) *appended_out = true;
        // A successful append is durable. A failed commit must suspend further
        // collection, otherwise the same in-memory delta could be persisted twice.
        try {
            co_await w->PostTask(w->CommitTraffic(panel.accounting_key, snapshot));
        } catch (...) {
            panel.traffic_journal->Suspend();
            throw;
        }
    }
    co_return appended;
}

net::awaitable<void> Controller::Impl::FlushTraffic() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    std::exception_ptr failure;
    for (const auto& panel : panels_) {
        try {
            co_await collectTraffic(*panel);
        } catch (const std::exception& error) {
            if (!failure) failure = std::current_exception();
            const PanelLogContext log_context{panel->config.Name, panel->config.APIHost,
                panel->config.NodeIDs.Front(), panel->config.NodeType};
            LOG_PANEL_ERROR(log_context, "Final traffic persistence failed: {}", error.what());
        } catch (...) {
            if (!failure) failure = std::current_exception();
            const PanelLogContext log_context{panel->config.Name, panel->config.APIHost,
                panel->config.NodeIDs.Front(), panel->config.NodeType};
            LOG_PANEL_ERROR(log_context, "Final traffic persistence failed: unknown error");
        }
    }
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<controller::OnlineSnapshot>
Controller::Impl::GetOnlineSnapshot(const std::string& tag) {
    ThrowIfStopping();
    std::vector<std::vector<OnlineDevice>> per_worker(workers_.size());

    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        tasks.push_back(
            [](Impl* controller, Worker* w, std::string t,
               std::vector<OnlineDevice>& out) -> net::awaitable<void> {
                controller->ThrowIfStopping();
                out = co_await w->PostTask(w->GetOnlineDevices(std::move(t)));
            }(this, workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await RunAwaitableBatch(
        io_context_.get_executor(), std::move(tasks));
    ThrowIfStopping();

    size_t total_online = 0;
    for (const auto& online : per_worker) {
        total_online += online.size();
    }

    std::vector<OnlineDevice> devices;
    devices.reserve(total_online);
    for (auto& online : per_worker) {
        devices.insert(devices.end(),
                       std::make_move_iterator(online.begin()),
                       std::make_move_iterator(online.end()));
    }
    co_return controller::BuildOnlineSnapshot(std::move(devices));
}

net::awaitable<void> Controller::Impl::userInfoMonitor(PanelRuntime& panel,
                                                       std::string tag) {
    const PanelLogContext log_context{panel.config.Name, panel.config.APIHost,
        panel.config.NodeIDs.Front(), panel.config.NodeType};

    ThrowIfStopping();
    // Drain never-attempted crash/backpressure records before collecting more;
    // otherwise a full journal of ready records could never free its capacity.
    auto& ns = panel.stats;
    controller::TrafficJournal::Batch batch;
    bool traffic_ok = false;
    bool journal_ok = true;
    try {
        batch = co_await journal_executor_->Run([&panel] {
            return panel.traffic_journal->Prepare();
        });
        if (batch.records.empty()) {
            // reset_cancellation_state in collectTraffic applies to its entire
            // coroutine thread, not just that function. Join a shielded child so a
            // durable append always reaches CommitTraffic without disabling stop
            // cancellation for this loop's subsequent panel requests.
            bool appended = false;
            try {
                co_await net::co_spawn(io_context_,
                    collectTraffic(panel, &appended),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
            } catch (const std::exception& e) {
                if (stopping_) throw;
                journal_ok = false;
                LOG_PANEL_WARN(log_context, "Traffic collection failed: operation=push reason={}", e.what());
            }
            ThrowIfStopping();
            if (appended) {
                batch = co_await journal_executor_->Run([&panel] {
                    return panel.traffic_journal->Prepare();
                });
            }
        }
        ThrowIfStopping();
        if (!batch.records.empty()) {
            co_await journal_executor_->Run([&panel, &batch] {
                panel.traffic_journal->Begin(batch);
                return true;
            });
        }
        const auto& traffic_data = batch.traffic;
        uint64_t batch_up = 0;
        uint64_t batch_down = 0;
        for (const auto& td : traffic_data) {
            batch_up += td.Upload;
            batch_down += td.Download;
        }
        if (!batch.records.empty() || journal_ok) {
            try {
                // Marked unknown durably BEFORE any network transmission. Even non-2xx
                // may follow partial server-side accounting; never retry these deltas.
                // An empty push still clears the panel's previous online-user count.
                traffic_ok = co_await panel.client->ReportUserTraffic(traffic_data);
            } catch (const std::exception& e) {
                if (stopping_) {
                    if (!traffic_ok && !batch.records.empty()) {
                        LOG_PANEL_ERROR(log_context, "Traffic accounting API acceptance unknown: records={} retained without retry; directory={}",
                                        batch.records.size(), panel.traffic_journal->Directory().string());
                    }
                    throw;
                }
                LOG_PANEL_WARN(log_context, "Traffic report failed: operation=push reason={}", e.what());
            }
        }
        if (!traffic_ok && !batch.records.empty()) {
            LOG_PANEL_ERROR(log_context, "Traffic accounting API acceptance unknown: records={} retained without retry; directory={}",
                            batch.records.size(), panel.traffic_journal->Directory().string());
        }
        if (traffic_ok) {
            ns.bytes_up += batch_up;
            ns.bytes_down += batch_down;
            if (!batch.records.empty()) {
                co_await journal_executor_->Run([&panel, &batch] {
                    panel.traffic_journal->Acknowledge(batch);
                    return true;
                });
            }
        }
        ThrowIfStopping();
        if (traffic_ok) {
            LOG_PANEL_DEBUG(log_context, "Traffic report accepted: users={}", traffic_data.size());
        }
    } catch (const std::exception& e) {
        if (stopping_) throw;
        journal_ok = false;
        LOG_PANEL_ERROR(log_context, "Traffic journal failed: operation=push reason={}", e.what());
    }

    auto online = co_await GetOnlineSnapshot(tag);
    ns.online_count = online.user_count;
    const auto& traffic_data = batch.traffic;

    ThrowIfStopping();
    bool online_ok = false;
    try {
        online_ok = co_await panel.client->ReportNodeOnlineUsers(online.entries);
        ThrowIfStopping();
    } catch (const std::exception& e) {
        if (stopping_) throw;
        LOG_PANEL_WARN(log_context, "Online report failed: operation=push reason={}", e.what());
    }

    const bool report_ok = traffic_ok && journal_ok && online_ok;
    LOG_PANEL_INFO(log_context,
        "Panel report: state={} operation=push traffic={} traffic_users={} online={} online_users={} devices={}",
        report_ok ? "ok" : "degraded",
        (traffic_ok && journal_ok) ? "ok" : "failed",
        traffic_data.size(),
        online_ok ? "ok" : "failed",
        online.user_count,
        online.entries.size());
    co_return;
}

