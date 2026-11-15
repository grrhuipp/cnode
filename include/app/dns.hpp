#pragma once

#include "common/asio_types.hpp"
#include "common/defaults.hpp"
#include "common/error.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// DNS 公开契约：配置、结果与 DNSWorker。缓存、上游 UDP/TCP 交换与
// 在途合并是 DNSWorker 私有实现，见 src/app/dns_internal.hpp。
namespace app {

struct DnsConfig {
    std::vector<udp::endpoint> servers;
    uint32_t timeout_sec = common::kDnsTimeout;
    size_t cache_size = common::kDnsCacheSize;
    uint32_t min_ttl = common::kDnsMinTTL;
    uint32_t max_ttl = common::kDnsMaxTTL;
};

struct DnsCacheStats {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t entries = 0;
    uint64_t capacity = 0;
};

struct DnsResult : common::ResultStatus {
    std::vector<net::ip::address> addresses;
    bool from_cache = false;
    uint32_t ttl = common::kDnsMinTTL;

    [[nodiscard]] bool Ok() const noexcept {
        return common::ResultStatus::Ok() && !addresses.empty();
    }
};

// The single owner of DNS sockets, cache, inflight queries and timers in
// production, on the main control Worker's io_context (no additional thread).
// Clients submit owned names through a bounded mailbox and only receive values;
// no live DNS state is exposed across threads.
class DNSWorker final {
public:
    DNSWorker(net::io_context& main_context,
              const DnsConfig& config, size_t mailbox_capacity);
    ~DNSWorker();

    DNSWorker(const DNSWorker&) = delete;
    DNSWorker& operator=(const DNSWorker&) = delete;

    // Copies domain at task creation; the caller's view is not retained.
    net::awaitable<DnsResult> Resolve(std::string_view domain);
    net::awaitable<DnsCacheStats> GetCacheStats();

    // Main/control executor only. Both operations are idempotent. AsyncJoin
    // requests stop and waits for admitted requests and actual upstream I/O
    // completion; keep this owner and its executor alive until it returns.
    void RequestStop() noexcept;
    net::awaitable<void> AsyncJoin();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace app
