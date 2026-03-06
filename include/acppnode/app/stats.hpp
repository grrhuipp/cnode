#pragma once

#include "acppnode/common.hpp"
#include <array>
#include <vector>
#include <string>

namespace acpp {

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
// 统计数据聚合结果（与原版兼容）
// ============================================================================
struct StatsSnapshot {
    uint64_t connections_total = 0;
    uint64_t connections_active = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    uint64_t errors = 0;

    uint64_t dns_queries = 0;
    uint64_t dns_cache_hits = 0;
    uint64_t dns_cache_misses = 0;
    
    double bytes_in_rate = 0;
    double bytes_out_rate = 0;
    double connections_rate = 0;
    
    [[nodiscard]] std::string ToString() const;
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

// 热点数据 - 流量统计（每次 I/O 都更新）
struct alignas(64) HotStatsShard {
    std::atomic<uint64_t> bytes_in{0};
    std::atomic<uint64_t> bytes_out{0};
    
    // 填充到 64 字节
    char padding_[48];
    
    void AddBytesIn(uint64_t n) {
        bytes_in.fetch_add(n, std::memory_order_relaxed);
    }
    
    void AddBytesOut(uint64_t n) {
        bytes_out.fetch_add(n, std::memory_order_relaxed);
    }
    
    // 批量添加（从本地累加器）
    void CommitAccumulator(const LocalStatsAccumulator& acc) {
        if (acc.bytes_in > 0) {
            bytes_in.fetch_add(acc.bytes_in, std::memory_order_relaxed);
        }
        if (acc.bytes_out > 0) {
            bytes_out.fetch_add(acc.bytes_out, std::memory_order_relaxed);
        }
    }
};

// 冷数据 - 连接统计（每个连接开始/结束时更新）
struct alignas(64) ColdStatsShard {
    std::atomic<uint64_t> connections_total{0};
    std::atomic<uint64_t> connections_active{0};
    std::atomic<uint64_t> errors{0};

    // 填充到 64 字节（3 × atomic<uint64_t> = 24 字节有效，padding 补齐）
    char padding_[40];

    void OnConnectionAccepted() {
        connections_total.fetch_add(1, std::memory_order_relaxed);
        connections_active.fetch_add(1, std::memory_order_relaxed);
    }

    void OnConnectionClosed() {
        connections_active.fetch_sub(1, std::memory_order_relaxed);
    }

    void OnError() {
        errors.fetch_add(1, std::memory_order_relaxed);
    }
};

// ============================================================================
// 组合的统计分片（兼容原有接口）
// ============================================================================
struct alignas(64) StatsShard {
    HotStatsShard hot;
    ColdStatsShard cold;

    // 兼容原有接口
    void OnConnectionAccepted() { cold.OnConnectionAccepted(); }
    void OnConnectionClosed() { cold.OnConnectionClosed(); }
    void AddBytesIn(uint64_t bytes) { hot.AddBytesIn(bytes); }
    void AddBytesOut(uint64_t bytes) { hot.AddBytesOut(bytes); }
    void OnError() { cold.OnError(); }

    // 访问器（兼容旧代码）
    [[nodiscard]] uint64_t GetConnectionsTotal() const { return cold.connections_total.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t GetConnectionsActive() const { return cold.connections_active.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t GetBytesIn() const { return hot.bytes_in.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t GetBytesOut() const { return hot.bytes_out.load(std::memory_order_relaxed); }

    // 批量提交
    void CommitAccumulator(const LocalStatsAccumulator& acc) {
        hot.CommitAccumulator(acc);
    }
};

// ============================================================================
// 优化的分片统计管理器
// ============================================================================
class ShardedStats {
public:
    explicit ShardedStats(uint32_t num_workers);

    // 获取指定 worker 的分片
    StatsShard& GetShard(uint32_t worker_id) {
        return shards_[worker_id % shards_.size()];
    }
    
    // 快速路径：只获取热点数据分片
    HotStatsShard& GetHotShard(uint32_t worker_id) {
        return shards_[worker_id % shards_.size()].hot;
    }
    
    // 汇总所有分片
    [[nodiscard]] StatsSnapshot Aggregate() const;
    
    // 计算速率
    [[nodiscard]] StatsSnapshot AggregateWithRate();
    
    // DNS 统计
    void OnDnsQuery() { dns_queries_.fetch_add(1, std::memory_order_relaxed); }
    void OnDnsCacheHit() { dns_cache_hits_.fetch_add(1, std::memory_order_relaxed); }
    void OnDnsCacheMiss() { dns_cache_misses_.fetch_add(1, std::memory_order_relaxed); }
    
    // 采样（每秒调用）
    void SampleNow();
    
private:
    std::vector<StatsShard> shards_;
    
    // DNS 统计
    std::atomic<uint64_t> dns_queries_{0};
    std::atomic<uint64_t> dns_cache_hits_{0};
    std::atomic<uint64_t> dns_cache_misses_{0};
    
    // 速率计算（10 秒滑动平均窗口）
    static constexpr size_t kWindowSize = 10;

    struct Sample {
        uint64_t bytes_in   = 0;
        uint64_t bytes_out  = 0;
        uint64_t connections = 0;
        time_point start_time;   // 本采样周期的起始时刻（= 上次采样时间）
        bool valid = false;      // 是否已写入有效数据
    };
    
    std::array<Sample, kWindowSize> samples_;
    size_t sample_index_ = 0;
    
    uint64_t last_bytes_in_ = 0;
    uint64_t last_bytes_out_ = 0;
    uint64_t last_connections_ = 0;
    time_point last_sample_time_;
    
    std::atomic<double> current_in_rate_{0};
    std::atomic<double> current_out_rate_{0};
};

// ============================================================================
// 连接统计守卫（RAII + 批量提交）
// ============================================================================
class ConnectionGuard {
public:
    explicit ConnectionGuard(StatsShard& shard)
        : shard_(shard) {
        shard_.OnConnectionAccepted();
    }
    
    ~ConnectionGuard() {
        // 提交累积的统计
        shard_.CommitAccumulator(accumulator_);
        shard_.OnConnectionClosed();
    }
    
    // 禁止拷贝
    ConnectionGuard(const ConnectionGuard&) = delete;
    ConnectionGuard& operator=(const ConnectionGuard&) = delete;
    
    // 本地累加（无 atomic）
    void AddBytesIn(uint64_t bytes) { accumulator_.AddBytesIn(bytes); }
    void AddBytesOut(uint64_t bytes) { accumulator_.AddBytesOut(bytes); }
    
    // 手动提交（用于长连接中间汇报）
    void Commit() {
        shard_.CommitAccumulator(accumulator_);
        accumulator_.Reset();
    }
    
    // 获取累加器（用于直接访问）
    LocalStatsAccumulator& GetAccumulator() { return accumulator_; }
    
private:
    StatsShard& shard_;
    LocalStatsAccumulator accumulator_;
};

}  // namespace acpp
