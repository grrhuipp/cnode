#pragma once

#include "common/asio_types.hpp"
#include "common/defaults.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace app::dns {

struct Config {
    std::vector<udp::endpoint> servers;
    uint32_t timeout_sec = 5;
    size_t cache_size = defaults::kDnsCacheSize;
    uint32_t min_ttl = 60;
    uint32_t max_ttl = 3600;
};

}  // namespace app::dns
