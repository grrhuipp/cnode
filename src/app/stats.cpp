#include "acppnode/app/stats.hpp"

#include <format>
#include <string_view>

namespace acpp {

// ============================================================================
// StatsSnapshot 实现
// ============================================================================

std::string StatsSnapshot::ToString() const {
    return std::format(
        "conn={}/{} bytes_in={} bytes_out={} "
        "in_rate={}/s out_rate={}/s err={}",
        connections_active,
        connections_total,
        FormatBytes(bytes_in),
        FormatBytes(bytes_out),
        FormatBytes(static_cast<uint64_t>(bytes_in_rate)),
        FormatBytes(static_cast<uint64_t>(bytes_out_rate)),
        errors);
}

// ============================================================================
// ShardedStats 实现
// ============================================================================

ShardedStats::ShardedStats(uint32_t num_workers)
    : shards_(num_workers)
    , last_sample_time_(steady_clock::now()) {
    // samples_ 默认初始化（valid = false），无需额外处理
}

StatsSnapshot ShardedStats::Aggregate() const {
    StatsSnapshot snapshot;
    
    for (const auto& shard : shards_) {
        // 热点数据
        snapshot.bytes_in += shard.hot.bytes_in.load(std::memory_order_relaxed);
        snapshot.bytes_out += shard.hot.bytes_out.load(std::memory_order_relaxed);
        
        // 冷数据
        snapshot.connections_total += shard.cold.connections_total.load(std::memory_order_relaxed);
        snapshot.connections_active += shard.cold.connections_active.load(std::memory_order_relaxed);
        snapshot.errors += shard.cold.errors.load(std::memory_order_relaxed);
    }
    
    snapshot.dns_queries = dns_queries_.load(std::memory_order_relaxed);
    snapshot.dns_cache_hits = dns_cache_hits_.load(std::memory_order_relaxed);
    snapshot.dns_cache_misses = dns_cache_misses_.load(std::memory_order_relaxed);
    
    return snapshot;
}

StatsSnapshot ShardedStats::AggregateWithRate() {
    // 只读取 sample_coro 每秒计算好的速率，不触发额外采样
    StatsSnapshot snapshot = Aggregate();
    snapshot.bytes_in_rate  = current_in_rate_.load(std::memory_order_relaxed);
    snapshot.bytes_out_rate = current_out_rate_.load(std::memory_order_relaxed);
    return snapshot;
}

void ShardedStats::SampleNow() {
    auto now = steady_clock::now();

    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_sample_time_).count();
    if (elapsed_ms <= 0) return;

    auto snapshot = Aggregate();

    uint64_t delta_in   = snapshot.bytes_in         - last_bytes_in_;
    uint64_t delta_out  = snapshot.bytes_out        - last_bytes_out_;
    uint64_t delta_conn = snapshot.connections_total - last_connections_;

    // 写入环形缓冲区：start_time = 本周期起始（上次采样时间）
    samples_[sample_index_] = {delta_in, delta_out, delta_conn, last_sample_time_, true};
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
            current_in_rate_.store(window_in  * 1000.0 / window_ms, std::memory_order_relaxed);
            current_out_rate_.store(window_out * 1000.0 / window_ms, std::memory_order_relaxed);
        }
    }

    last_bytes_in_    = snapshot.bytes_in;
    last_bytes_out_   = snapshot.bytes_out;
    last_connections_ = snapshot.connections_total;
    last_sample_time_ = now;
}

// ============================================================================
// 辅助函数
// ============================================================================

std::string FormatBytes(uint64_t bytes) {
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

}  // namespace acpp
