#pragma once

#include "common/clock.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/**
 * 连接统计系统
 *
 * 设计要点：
 * 1. 使用本地累加器减少 atomic 操作
 * 2. 批量提交统计数据
 * 3. Cache line 对齐避免伪共享
 * 4. 分离热点数据和冷数据
 */

// ============================================================================
// 统计数据聚合结果
// ============================================================================
struct StatsSnapshot {
    uint64_t connections_total = 0;
    uint64_t connections_active = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    uint64_t errors = 0;

    double bytes_in_rate = 0;
    double bytes_out_rate = 0;
};

struct WorkerMemoryStats {
    size_t udp_sockets = 0;
    size_t pool_mapped_bytes = 0;
    size_t pool_direct_bytes = 0;
    size_t pool_idle_bytes = 0;
    size_t pool_chunks = 0;
};

// Sampled only on the owning Worker; passed to the control plane by value.
struct WorkerResourceStats {
    size_t udp_listeners = 0;
    size_t udp_receive_loops = 0;
    uint64_t udp_resource_drops = 0;
    size_t udp_associations = 0;
    size_t udp_closed_associations = 0;
    size_t udp_input_datagrams = 0;
    size_t udp_input_bytes = 0;
    size_t udp_reply_datagrams = 0;
    size_t udp_reply_bytes = 0;
    size_t udp_reply_senders = 0;
    size_t udp_native_dispatches = 0;
    size_t timeout_events = 0;
    size_t timeout_heap_capacity = 0;
    size_t timeout_waiters = 0;
};

struct WorkerRuntimeStatsSnapshot {
    WorkerMemoryStats memory;
    std::optional<WorkerResourceStats> resources;
    StatsSnapshot stats;
    uint32_t worker_id = 0;
    // Effective Worker load: max(physical transports, active dispatches).
    uint32_t active_connections = 0;
};

// ============================================================================
// 本地累加器（Per-Connection 或 Per-Task，无锁）
// ============================================================================
struct LocalStatsAccumulator {
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;

    void AddBytesIn(uint64_t n) { bytes_in += n; }
    void AddBytesOut(uint64_t n) { bytes_out += n; }

    void Reset() {
        bytes_in = 0;
        bytes_out = 0;
    }
};

// ============================================================================
// 优化的统计分片（64 字节对齐）
//
// 热点数据（频繁更新）和冷数据（偶尔更新）分离
// ============================================================================

// 热点数据 - 流量统计（每次 I/O 都更新）；alignas 隔离冷热数据所在缓存行
struct alignas(64) HotStatsShard {
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;

    void AddBytesIn(uint64_t n) {
        bytes_in += n;
    }

    void AddBytesOut(uint64_t n) {
        bytes_out += n;
    }

    // 批量添加（从本地累加器）
    void CommitAccumulator(const LocalStatsAccumulator& acc) {
        if (acc.bytes_in > 0) {
            bytes_in += acc.bytes_in;
        }
        if (acc.bytes_out > 0) {
            bytes_out += acc.bytes_out;
        }
    }
};

// 冷数据 - 连接统计（每个连接开始/结束时更新）
struct alignas(64) ColdStatsShard {
    uint64_t connections_total = 0;
    uint64_t connections_active = 0;
    uint64_t errors = 0;

    void OnConnectionAccepted() {
        ++connections_total;
        ++connections_active;
    }

    void OnConnectionClosed() {
        --connections_active;
    }

    void OnError() {
        ++errors;
    }
};

// ============================================================================
// 组合的统计分片
// ============================================================================
struct alignas(64) StatsShard {
    HotStatsShard hot;
    ColdStatsShard cold;

    void OnConnectionAccepted() { cold.OnConnectionAccepted(); }
    void OnConnectionClosed() { cold.OnConnectionClosed(); }
    void AddBytesIn(uint64_t bytes) { hot.AddBytesIn(bytes); }
    void AddBytesOut(uint64_t bytes) { hot.AddBytesOut(bytes); }
    void OnError() { cold.OnError(); }

    [[nodiscard]] StatsSnapshot Snapshot() const {
        StatsSnapshot snapshot;
        snapshot.connections_total = cold.connections_total;
        snapshot.connections_active = cold.connections_active;
        snapshot.bytes_in = hot.bytes_in;
        snapshot.bytes_out = hot.bytes_out;
        snapshot.errors = cold.errors;
        return snapshot;
    }

    // 批量提交
    void CommitAccumulator(const LocalStatsAccumulator& acc) {
        hot.CommitAccumulator(acc);
    }
};

// The single accepted/closed accounting of one connection or logical
// substream: accepted on construction, closed once on destruction. Moving
// transfers the pending close.
class ConnectionStatsScope {
public:
    explicit ConnectionStatsScope(StatsShard& stats) noexcept
        : stats_(&stats) {
        stats_->OnConnectionAccepted();
    }

    ~ConnectionStatsScope() noexcept {
        if (stats_) {
            stats_->OnConnectionClosed();
        }
    }

    ConnectionStatsScope(ConnectionStatsScope&& other) noexcept
        : stats_(std::exchange(other.stats_, nullptr)) {}
    ConnectionStatsScope(const ConnectionStatsScope&) = delete;
    ConnectionStatsScope& operator=(const ConnectionStatsScope&) = delete;
    ConnectionStatsScope& operator=(ConnectionStatsScope&&) = delete;

private:
    StatsShard* stats_;
};

// ============================================================================
// 优化的分片统计管理器
// ============================================================================
class ShardedStats {
public:
    // Requires at least one Worker; each Worker owns exactly one shard.
    explicit ShardedStats(uint32_t num_workers)
        : shards_(num_workers)
        , last_sample_time_(steady_clock::now()) {
        if (shards_.empty()) {
            throw std::invalid_argument("stats require at least one worker shard");
        }
    }

    // A Worker id outside the configured range has no owner shard; sharing
    // another Worker's executor-exclusive shard would race, so it throws.
    StatsShard& GetShard(uint32_t worker_id) {
        return shards_.at(worker_id);
    }

    [[nodiscard]] StatsSnapshot WithCurrentRate(StatsSnapshot snapshot) const {
        snapshot.bytes_in_rate  = current_in_rate_;
        snapshot.bytes_out_rate = current_out_rate_;
        return snapshot;
    }

    // 采样（每秒调用）
    void SampleNow(const StatsSnapshot& snapshot) {
        auto now = steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_sample_time_).count();
        if (elapsed_ms <= 0) return;

        const uint64_t delta_in = snapshot.bytes_in >= last_bytes_in_
            ? snapshot.bytes_in - last_bytes_in_
            : 0;
        const uint64_t delta_out = snapshot.bytes_out >= last_bytes_out_
            ? snapshot.bytes_out - last_bytes_out_
            : 0;

        // 写入环形缓冲区：start_time = 本周期起始（上次采样时间）
        samples_[sample_index_] = {delta_in, delta_out, last_sample_time_, true};
        sample_index_ = (sample_index_ + 1) % kWindowSize;

        // 滑动窗口：遍历所有有效采样点，累加增量 / 计算时间跨度
        uint64_t window_in  = 0;
        uint64_t window_out = 0;
        time_point oldest_start = now;
        bool has_valid = false;

        for (const auto& s : samples_) {
            if (!s.valid) continue;
            window_in  += s.bytes_in;
            window_out += s.bytes_out;
            if (s.start_time < oldest_start) oldest_start = s.start_time;
            has_valid = true;
        }

        if (has_valid) {
            // 时间窗口 = 最旧采样起始 → 本次采样结束（now）
            auto window_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - oldest_start).count();
            if (window_ms > 0) {
                current_in_rate_ = window_in  * 1000.0 / window_ms;
                current_out_rate_ = window_out * 1000.0 / window_ms;
            }
        }

        last_bytes_in_    = snapshot.bytes_in;
        last_bytes_out_   = snapshot.bytes_out;
        last_sample_time_ = now;
    }

private:
    std::vector<StatsShard> shards_;

    // 速率计算（10 秒滑动平均窗口）
    static constexpr size_t kWindowSize = 10;

    struct Sample {
        uint64_t bytes_in   = 0;
        uint64_t bytes_out  = 0;
        time_point start_time;   // 本采样周期的起始时刻（= 上次采样时间）
        bool valid = false;      // 是否已写入有效数据
    };

    std::array<Sample, kWindowSize> samples_;
    size_t sample_index_ = 0;

    uint64_t last_bytes_in_ = 0;
    uint64_t last_bytes_out_ = 0;
    time_point last_sample_time_;

    double current_in_rate_ = 0;
    double current_out_rate_ = 0;
};

// 格式化字节数
[[nodiscard]] inline std::string FormatBytes(uint64_t bytes) {
    constexpr std::string_view units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double value = static_cast<double>(bytes);

    while (value >= 1024 && unit_index < 4) {
        value /= 1024;
        unit_index++;
    }

    if (unit_index == 0) {
        return std::format("{}{}", bytes, units[unit_index]);
    }
    return std::format("{:.2f}{}", value, units[unit_index]);
}

