#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace acpp::app::dns {

class DNSWorker;

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

}  // namespace acpp::app::dns
