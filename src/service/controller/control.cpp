#include "controller_impl.hpp"
#include "../../common/awaitable_batch.hpp"

#include "acppnode/app/traffic_types.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/online_device.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>

#include <cstdint>
#include <exception>
#include <format>
#include <vector>

namespace acpp {

net::awaitable<void>
Controller::Impl::collectTraffic(PanelRuntime& panel, const std::string& tag) {
    // Do not abandon a durable append before its matching Worker commit.
    // Shutdown joins this critical section before taking its final snapshot.
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    // Only this panel loop may snapshot/commit its accounting key. The disk
    // executor never touches Worker-owned state and has bounded admission.
    for (const auto& worker : workers_) {
        auto* w = worker.get();
        auto snapshot = co_await w->PostTask(w->SnapshotTraffic(tag));
        if (snapshot.empty()) continue;
        co_await journal_executor_->Run([&panel, &snapshot] {
            panel.traffic_journal->Append(snapshot);
            return true;
        });
        // A successful append is durable. A failed commit must suspend further
        // collection, otherwise the same in-memory delta could be persisted twice.
        try {
            co_await w->PostTask(w->CommitTraffic(tag, snapshot));
        } catch (...) {
            panel.traffic_journal->Suspend();
            throw;
        }
    }
}

net::awaitable<void> Controller::Impl::FlushTraffic() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    std::exception_ptr failure;
    for (const auto& panel : panels_) {
        try {
            const auto key = std::format("panel/{}/{}/",
                panel->config.Name, panel->config.NodeIDs.Front());
            co_await collectTraffic(*panel, key);
        } catch (const std::exception& error) {
            if (!failure) failure = std::current_exception();
            LOG_ERROR("Panel {}/{} final traffic persistence failed: {}",
                      panel->config.Name, panel->config.NodeIDs.Front(), error.what());
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
    for (const auto& online : per_worker) {
        devices.insert(devices.end(), online.begin(), online.end());
    }
    co_return controller::BuildOnlineSnapshot(std::move(devices));
}

net::awaitable<void> Controller::Impl::userInfoMonitor(PanelRuntime& panel,
                                                 const std::string& tag) {
    const int node_id = panel.config.NodeIDs.Front();
    const auto& panel_name = panel.config.Name;

    ThrowIfStopping();
    // Drain never-attempted crash/backpressure records before collecting more;
    // otherwise a full journal of ready records could never free its capacity.
    auto batch = co_await journal_executor_->Run([&panel] {
        return panel.traffic_journal->Prepare();
    });
    if (batch.records.empty()) {
        // reset_cancellation_state in collectTraffic applies to its entire
        // coroutine thread, not just that function. Join a shielded child so a
        // durable append always reaches CommitTraffic without disabling stop
        // cancellation for this loop's subsequent panel requests.
        co_await net::co_spawn(io_context_,
            collectTraffic(panel, panel.node.committed->inbound->accounting_key),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
        ThrowIfStopping();
        batch = co_await journal_executor_->Run([&panel] {
            return panel.traffic_journal->Prepare();
        });
    }
    auto online = co_await GetOnlineSnapshot(tag);
    ThrowIfStopping();
    co_await journal_executor_->Run([&panel, &batch] {
        panel.traffic_journal->Begin(batch);
        return true;
    });
    const auto& traffic_data = batch.traffic;
    auto& ns = panel.stats;
    ns.online_count = traffic_data.size();
    for (const auto& td : traffic_data) {
        ns.bytes_up += td.Upload;
        ns.bytes_down += td.Download;
    }
    bool traffic_ok = false;
    try {
        // Marked unknown durably BEFORE any network transmission. Even non-2xx
        // may follow partial server-side accounting; never retry these deltas.
        // An empty push still clears the panel's previous online-user count.
        traffic_ok = co_await panel.client->ReportUserTraffic(traffic_data);
        if (traffic_ok) {
            co_await journal_executor_->Run([&panel, &batch] {
                panel.traffic_journal->Acknowledge(batch);
                return true;
            });
        }
        ThrowIfStopping();
        if (traffic_ok) {
            LOG_DEBUG("Panel {}/{} report: traffic ok | users {}",
                      panel_name, node_id, traffic_data.size());
        }
    } catch (const std::exception& e) {
        if (stopping_) throw;
        LOG_WARN("Panel {}/{} report: traffic failed | {}",
                 panel_name, node_id, e.what());
    }
    if (!traffic_ok && !batch.records.empty()) {
        LOG_ERROR("Panel {}/{} accounting: API acceptance unknown; {} records retained without retry; directory={}",
                  panel_name, node_id, batch.records.size(), panel.traffic_journal->Directory().string());
    }

    ThrowIfStopping();
    bool online_ok = false;
    try {
        online_ok = co_await panel.client->ReportNodeOnlineUsers(online.entries);
        ThrowIfStopping();
    } catch (const std::exception& e) {
        if (stopping_) throw;
        LOG_WARN("Panel {}/{} report: online failed | {}",
                 panel_name, node_id, e.what());
    }

    const bool report_ok = traffic_ok && online_ok;
    LOG_CONSOLE(
        "Panel {}/{} report: {} | traffic {}/{} | online {}/{} | devices {}",
        panel_name,
        node_id,
        report_ok ? "ok" : "degraded",
        traffic_ok ? "ok" : "failed",
        traffic_data.size(),
        online_ok ? "ok" : "failed",
        online.user_count,
        online.entries.size());
    co_return;
}

}  // namespace acpp
