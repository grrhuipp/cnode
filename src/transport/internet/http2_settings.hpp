#pragma once

#include "acppnode/common/allocator.hpp"

#include <cstdint>

namespace acpp::transport::internet {

[[nodiscard]] memory::ByteVector EncodeInitialWindowSetting(
    uint32_t initial_window);

}  // namespace acpp::transport::internet
