#pragma once

#include "common/allocator.hpp"

#include <cstdint>

namespace transport::internet {

[[nodiscard]] memory::ByteVector EncodeInitialWindowSetting(
    uint32_t initial_window);

}  // namespace transport::internet
