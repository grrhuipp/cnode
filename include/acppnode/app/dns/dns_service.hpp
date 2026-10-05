#pragma once

#include "acppnode/app/dns/config.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/dns/stats.hpp"

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>

namespace acpp::app::dns {

// The single owner of DNS sockets, cache, inflight queries and timers in
// production, on its service strand in the shared io_context (no additional thread).
// Clients submit owned requests and receive owned results through bounded,
// thread-safe channels; no live DNS state is exposed across strands.
class DNSServiceError final : public std::runtime_error {
public:
    explicit DNSServiceError(ErrorCode code)
        : std::runtime_error(std::string(ErrorCodeToString(code))), code_(code) {}

    [[nodiscard]] ErrorCode Code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

class DNSService final {
public:
    DNSService(net::any_io_executor executor,
               const Config& config, size_t request_capacity);
    ~DNSService();

    DNSService(const DNSService&) = delete;
    DNSService& operator=(const DNSService&) = delete;

    // Runs the sole request receiver on the DNS owner strand. The runtime must
    // start and join this task exactly once.
    net::awaitable<void> Run();
    net::awaitable<DnsResult> Resolve(std::string domain);
    net::awaitable<DnsCacheStats> GetCacheStats();
    // Runtime calls once after stopping clients; joins queries and receive I/O.
    net::awaitable<void> Close();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::app::dns
