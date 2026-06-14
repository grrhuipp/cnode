#pragma once

#include "acppnode/app/dns/config.hpp"
#include "acppnode/app/dns/stats.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp::app::dns {

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
    using Config = ::acpp::app::dns::Config;

    DNS(net::io_context& io_context, const Config& config);
    ~DNS();

    DNS(const DNS&) = delete;
    DNS& operator=(const DNS&) = delete;
    DNS(DNS&&) noexcept;
    DNS& operator=(DNS&&) noexcept;

    net::awaitable<DnsResult> Resolve(std::string_view domain);

    DnsCacheStats GetCacheStats() const;
    void ClearCache();

    net::awaitable<void> Prefetch(const std::vector<std::string>& domains);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::app::dns
