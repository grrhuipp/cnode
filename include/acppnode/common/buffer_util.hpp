#pragma once

#include <cstddef>
#include <vector>
#include <cstdint>

namespace acpp {

// 释放空闲缓冲区：当 capacity 超过 keep_capacity 时，释放全部内存
inline void ReleaseIdleBuffer(std::vector<uint8_t>& buf, size_t keep_capacity) {
    if (buf.capacity() > keep_capacity) {
        std::vector<uint8_t>().swap(buf);
    }
}

}  // namespace acpp
