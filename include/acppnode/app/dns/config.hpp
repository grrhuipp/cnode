#pragma once

#include "acppnode/common/asio_types.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace acpp::app::dns {

struct Config {
    std::vector<net::ip::address> servers;
    uint32_t timeout_sec = 5;
    size_t cache_size = 1024;
    size_t global_cache_size = 10000;
    uint32_t min_ttl = 60;
    uint32_t max_ttl = 3600;
};

}  // namespace acpp::app::dns
