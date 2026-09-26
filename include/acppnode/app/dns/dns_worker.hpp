#pragma once

#include "acppnode/app/dns/dns.hpp"

#include <cstddef>
#include <memory>
#include <string>

namespace acpp::app::dns {

// The single owner of DNS sockets, cache, inflight queries and timers in
// production, on the main control Worker's io_context (no additional thread).
// Clients submit owned names through a bounded mailbox and only receive values;
// no live DNS state is exposed across threads.
class DNSWorker final {
public:
    DNSWorker(net::io_context& main_context,
              const DNS::Config& config, size_t mailbox_capacity);
    ~DNSWorker();

    DNSWorker(const DNSWorker&) = delete;
    DNSWorker& operator=(const DNSWorker&) = delete;

    net::awaitable<DnsResult> Resolve(std::string domain);
    net::awaitable<DnsCacheStats> GetCacheStats();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::app::dns
