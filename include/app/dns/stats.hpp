#pragma once

#include <cstdint>

namespace app::dns {

struct DnsCacheStats {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t entries = 0;
    uint64_t capacity = 0;
};

}  // namespace app::dns
