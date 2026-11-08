#pragma once

#include "app/dns/config.hpp"
#include "app/dns/dns.hpp"
#include "app/dns/stats.hpp"

#include <cstddef>
#include <memory>
#include <string>

namespace app::dns {

// The single owner of DNS sockets, cache, inflight queries and timers in
// production, on the main control Worker's io_context (no additional thread).
// Clients submit owned names through a bounded mailbox and only receive values;
// no live DNS state is exposed across threads.
class DNSWorker final {
public:
    DNSWorker(net::io_context& main_context,
              const Config& config, size_t mailbox_capacity);
    ~DNSWorker();

    DNSWorker(const DNSWorker&) = delete;
    DNSWorker& operator=(const DNSWorker&) = delete;

    net::awaitable<DnsResult> Resolve(std::string domain);
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

}  // namespace app::dns
