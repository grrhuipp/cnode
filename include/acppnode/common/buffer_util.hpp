#pragma once

#include <cstddef>
#include <vector>
#include <cstdint>

namespace acpp {

// 释放空闲缓冲区：当 capacity 超过 keep_capacity 时，释放全部内存
template <class ByteContainer>
inline void ReleaseIdleBuffer(ByteContainer& buf, size_t keep_capacity) {
    if (buf.capacity() > keep_capacity) {
        ByteContainer().swap(buf);
    }
}

}  // namespace acpp
