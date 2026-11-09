#pragma once

#include "common/asio_types.hpp"
#include "common/defaults.hpp"
#include "common/error.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace app::dns {

class DNSWorker;

struct Config {
    std::vector<udp::endpoint> servers;
    uint32_t timeout_sec = 5;
    size_t cache_size = defaults::kDnsCacheSize;
    uint32_t min_ttl = 60;
    uint32_t max_ttl = 3600;
};

struct DnsCacheStats {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t entries = 0;
    uint64_t capacity = 0;
};

struct DnsResult : ResultStatus {
    std::vector<net::ip::address> addresses;
    bool from_cache = false;
    uint32_t ttl = 60;

    [[nodiscard]] bool Ok() const noexcept {
        return ResultStatus::Ok() && !addresses.empty();
    }
};
class DNS final {
public:
    // Client only: all resolution state and sockets belong to DNSWorker.
    explicit DNS(DNSWorker& worker) noexcept : worker_(worker) {}

    DNS(const DNS&) = delete;
    DNS& operator=(const DNS&) = delete;

    // Copies domain at task creation. The DNSWorker must outlive the task.
    net::awaitable<DnsResult> Resolve(std::string_view domain);

private:
    DNSWorker& worker_;
};

}  // namespace app::dns
