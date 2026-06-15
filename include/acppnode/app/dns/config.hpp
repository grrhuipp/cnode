#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace acpp::app::dns {

struct Config {
    std::vector<std::string> servers = {"8.8.8.8", "1.1.1.1"};
    uint32_t timeout_sec = 5;
    size_t cache_size = 1024;
    size_t global_cache_size = 10000;
    uint32_t min_ttl = 60;
    uint32_t max_ttl = 3600;
};

}  // namespace acpp::app::dns
