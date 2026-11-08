#pragma once

#include "common/allocator.hpp"
#include <memory_resource>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

namespace transport::internet::hysteria {

// ngtcp2/nghttp3 do not provide allocation sizes to free(). Prefix each block
// with its exact PMR layout so the connection's lightweight AllocationDomain
// can return slots to the current Worker's shared pool without a side table.
class QuicMemory final {
public:
    explicit QuicMemory(memory::AllocationDomain& domain) noexcept;

    [[nodiscard]] const ngtcp2_mem* Ngtcp2() const noexcept { return &ngtcp2_; }
    [[nodiscard]] const nghttp3_mem* Nghttp3() const noexcept { return &nghttp3_; }

private:
    static void* Allocate(size_t size, void* user_data);
    static void Free(void* pointer, void* user_data) noexcept;
    static void* Callocate(size_t count, size_t size, void* user_data);
    static void* Reallocate(void* pointer, size_t size, void* user_data);

    memory::AllocationDomain* domain_;
    ngtcp2_mem ngtcp2_;
    nghttp3_mem nghttp3_;
};

}  // namespace transport::internet::hysteria
