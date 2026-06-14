#pragma once

#include <cstdint>

namespace acpp::app::dns {

struct DnsCacheStats {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t entries = 0;
    uint64_t expired = 0;
};

}  // namespace acpp::app::dns
