#pragma once

#include <cstdint>

struct AuthFailureLimitConfig {
    bool enabled = false;
    uint32_t failure_limit = 10;
    uint32_t window_seconds = 60;
    uint32_t ban_seconds = 180;
};
