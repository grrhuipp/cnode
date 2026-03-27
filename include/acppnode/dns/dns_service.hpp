#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/error.hpp"
#ifdef _MSC_VER
#include <intrin.h>
#endif
#include <unordered_map>
#include <array>
#include <mutex>
#include <shared_mutex>

namespace acpp {

// ============================================================================
// DNS 缓存统计
// ============================================================================
struct DnsCacheStats {
    uint64_t hits = 0;           // 缓存命中
    uint64_t misses = 0;         // 缓存未命中
    uint64_t entries = 0;        // 当前条目数
    uint64_t expired = 0;        // 已过期数
};

// ============================================================================
// DNS 解析结果
// ============================================================================
struct DnsResult {
    std::vector<net::ip::address> addresses;
    ErrorCode error = ErrorCode::OK;
    std::string error_msg;
    bool from_cache = false;
    uint32_t ttl = 60;  // DNS TTL

    [[nodiscard]] bool Ok() const noexcept { return error == ErrorCode::OK && !addresses.empty(); }
};

// ============================================================================
// DNS 服务接口
// ============================================================================
class IDnsService {
public:
    virtual ~IDnsService() noexcept = default;

    // 异步解析域名
    virtual cobalt::task<DnsResult> Resolve(
        const std::string& domain) = 0;

    // 获取缓存统计
    [[nodiscard]] virtual DnsCacheStats GetCacheStats() const = 0;

    // 清空缓存
    virtual void ClearCache() = 0;

    // 预热缓存（并发解析指定域名列表，不阻塞）
    virtual cobalt::task<void> Prefetch(
        const std::vector<std::string>& domains) = 0;
};

// ============================================================================
// DNS 缓存条目
// ============================================================================
struct DnsCacheEntry {
    std::vector<net::ip::address> addresses;
    time_point expire_time;
    time_point last_access;
    uint32_t ttl;
    bool negative = false;  // NXDOMAIN 负缓存
};

// DnsSpinlock 已移除，使用 std::shared_mutex 替代（见 DnsCache::Shard）。
// shared_mutex 允许 Get() 路径并发读（shared_lock），
// Put()/PutNegative()/Clear() 使用独占写（unique_lock）。

// ============================================================================
// DNS 缓存（分片 Spinlock + LRU）
// 
// 设计：
// - 256 分片，每分片独立 spinlock + hashmap + LRU list
// - 分片大幅降低锁竞争
// - 每个分片独立进行 LRU 淘汰
// ============================================================================
class DnsCache {
public:
    explicit DnsCache(size_t max_size, uint32_t min_ttl, uint32_t max_ttl);

    // 查询缓存
    std::optional<DnsCacheEntry> Get(const std::string& domain);

    // 添加缓存
    void Put(const std::string& domain, 
             const std::vector<net::ip::address>& addresses,
             uint32_t ttl);

    // 添加负缓存
    void PutNegative(const std::string& domain,
                     uint32_t ttl = 60);

    // 清空
    void Clear();

    // 统计
    DnsCacheStats GetStats() const;

private:
    static constexpr size_t kNumShards = 256;

    struct CacheKeyRef {
        std::string_view domain;
    };

    struct CacheKeyHash {
        [[nodiscard]] size_t operator()(CacheKeyRef key) const noexcept {
            return std::hash<std::string_view>{}(key.domain);
        }
    };

    struct CacheKeyEq {
        [[nodiscard]] bool operator()(CacheKeyRef a,
                                      CacheKeyRef b) const noexcept {
            return a.domain == b.domain;
        }
    };

    struct CacheNode {
        std::string domain;
        DnsCacheEntry entry;

        CacheNode(std::string d, DnsCacheEntry e)
            : domain(std::move(d)), entry(std::move(e)) {}

        [[nodiscard]] CacheKeyRef Key() const noexcept {
            return CacheKeyRef{domain};
        }
    };

    // 分片结构
    //   lock：读写锁，Get 用 shared_lock（并发读），Put/Clear 用 unique_lock（独占写）
    //   lru_list：节点持有真实 key/entry，hash 索引只保留 string_view，避免域名字符串存两份
    struct alignas(64) Shard {
        using NodeList = memory::ThreadLocalList<CacheNode>;

        mutable std::shared_mutex lock;
        NodeList lru_list;
        memory::ThreadLocalUnorderedMap<CacheKeyRef, NodeList::iterator,
            CacheKeyHash, CacheKeyEq> cache;
        size_t max_entries = 0;

        size_t Evict();  // 调用方须持有 unique_lock
    };

    Shard& GetShard(CacheKeyRef cache_key) const {
        size_t hash = CacheKeyHash{}(cache_key);
        return shards_[hash & (kNumShards - 1)];
    }

    mutable std::array<Shard, kNumShards> shards_;
    uint32_t min_ttl_;
    uint32_t max_ttl_;

    // 全局统计（atomic）
    mutable std::atomic<uint64_t> hits_{0};
    mutable std::atomic<uint64_t> misses_{0};
    std::atomic<uint64_t> expired_{0};
    std::atomic<uint64_t> total_entries_{0};  // 总条目数（避免遍历统计）
};

// ============================================================================
// 基于 UDP 的异步 DNS 服务实现
//
// 设计约束：
// - 一个 Worker / 线程对应一个 DnsService 实例
// - 实例之间不共享 inflight、socket、事务号或缓存状态
// - Resolve 路径按线程亲和假设设计，优先减少调度和锁开销
// ============================================================================
class DnsService final : public IDnsService {
public:
    struct Config {
        std::vector<std::string> servers = {"8.8.8.8", "1.1.1.1"};
        uint32_t timeout_sec = 5;
        size_t cache_size = 10000;
        uint32_t min_ttl = 60;
        uint32_t max_ttl = 3600;
    };

    DnsService(net::any_io_executor executor, const Config& config);
    ~DnsService() override;

    cobalt::task<DnsResult> Resolve(
        const std::string& domain) override;

    DnsCacheStats GetCacheStats() const override;
    void ClearCache() override;

    // 预热缓存
    cobalt::task<void> Prefetch(
        const std::vector<std::string>& domains) override;

private:
    struct ResolveKey {
        std::string domain;

        bool operator==(const ResolveKey& other) const noexcept {
            return domain == other.domain;
        }
    };

    struct ResolveKeyHash {
        size_t operator()(const ResolveKey& key) const noexcept {
            return std::hash<std::string>{}(key.domain);
        }
    };

    struct InflightResolve {
        DnsResult result;
        bool completed = false;
        memory::ThreadLocalVector<std::shared_ptr<net::steady_timer>> waiters;
    };

    struct ParsedResponse {
        std::vector<net::ip::address> addresses;
        ErrorCode error = ErrorCode::OK;
        std::string error_msg;
        uint32_t ttl = 60;
        bool negative_cacheable = false;

        [[nodiscard]] bool Ok() const noexcept {
            return error == ErrorCode::OK && !addresses.empty();
        }
    };

    // 内部解析实现
    cobalt::task<DnsResult> DoResolve(
        const std::string& domain);

    // 发送 DNS 查询并等待响应
    cobalt::task<DnsResult> QueryServer(
        const net::ip::udp::endpoint& server,
        const std::string& domain,
        bool query_aaaa);

    // 构建 DNS 查询报文
    memory::ByteVector BuildQuery(const std::string& domain,
                                  uint16_t txid,
                                  bool query_aaaa);

    // 解析 DNS 响应报文
    ParsedResponse ParseResponse(
        std::span<const uint8_t> response,
        uint16_t expected_txid,
        uint32_t& out_ttl);

    net::any_io_executor executor_;
    Config config_;
    std::shared_ptr<DnsCache> cache_;
    memory::ThreadLocalVector<net::ip::udp::endpoint> servers_;
    memory::ThreadLocalUnorderedMap<ResolveKey, std::shared_ptr<InflightResolve>, ResolveKeyHash>
        inflight_resolves_;

    // 事务 ID 生成器（atomic，无锁）
    std::atomic<uint16_t> txid_counter_{1};
};

// ============================================================================
// 创建 DNS 服务的工厂函数
// ============================================================================
std::unique_ptr<IDnsService> CreateDnsService(
    net::any_io_executor executor,
    const DnsService::Config& config);

}  // namespace acpp
