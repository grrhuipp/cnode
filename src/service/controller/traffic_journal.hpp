#pragma once

#include "api/api.hpp"
#include "app/traffic_types.hpp"
#include "infra/panel_config.hpp"

#include <filesystem>
#include <mutex>
#include <vector>

namespace controller {

// UniProxy is additive and has no idempotency token. Only ready records may be
// sent. Unknown records require external reconciliation, never automatic retry.
class TrafficJournal {
public:
    static constexpr size_t kMaxBytes = 64 * 1024 * 1024;
    static constexpr size_t kMaxRecords = 1024;
    struct Batch {
        std::vector<api::UserTraffic> traffic;
        std::vector<std::filesystem::path> records;
    };

    explicit TrafficJournal(const PanelConfig& config);
    ~TrafficJournal();
    TrafficJournal(const TrafficJournal&) = delete;
    TrafficJournal& operator=(const TrafficJournal&) = delete;
    void Suspend() noexcept;
    void Append(const app::UserTrafficSnapshot& traffic);
    [[nodiscard]] Batch Prepare();
    void Begin(Batch& batch);
    void Acknowledge(const Batch& batch);
    [[nodiscard]] size_t UnknownCount();
    [[nodiscard]] const std::filesystem::path& Directory() const noexcept { return directory_; }

private:
    void CheckHealthy() const;
    void SyncDirectory();
    std::filesystem::path directory_;
    int lock_fd_ = -1;
    int directory_fd_ = -1;
    std::mutex mutex_;
    bool failed_ = false;
};

} // namespace controller
