#pragma once

#include "common/allocator.hpp"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

namespace transport::internet::hysteria {

// ngtcp2/nghttp3 do not provide allocation sizes to free(). Prefix each block
// with its exact PMR layout so Free can return slots to the current Worker's
// shared pool without a side table.
class QuicMemory final {
public:
    [[nodiscard]] static const ngtcp2_mem* Ngtcp2() noexcept {
        static const ngtcp2_mem kMem{nullptr, &Allocate, &Free, &Callocate, &Reallocate};
        return &kMem;
    }

    [[nodiscard]] static const nghttp3_mem* Nghttp3() noexcept {
        static const nghttp3_mem kMem{nullptr, &Allocate, &Free, &Callocate, &Reallocate};
        return &kMem;
    }

private:
    struct alignas(std::max_align_t) AllocationHeader {
        size_t payload_size;
        size_t allocation_size;
    };

    static constexpr size_t kAlignment = alignof(std::max_align_t);

    [[nodiscard]] static bool AllocationSize(size_t payload_size, size_t& result) noexcept {
        if (payload_size > std::numeric_limits<size_t>::max() - sizeof(AllocationHeader))
            return false;
        result = sizeof(AllocationHeader) + payload_size;
        return true;
    }

    static void* Allocate(size_t size, void*) {
        try {
            size_t allocation_size = 0;
            if (!AllocationSize(size, allocation_size)) return nullptr;
            void* raw =
                memory::ThreadMemoryPool().Allocate(allocation_size, kAlignment);
            if (!raw) return nullptr;
            auto* header =
                ::new (raw) AllocationHeader{size, allocation_size};
            return header + 1;
        } catch (...) {
            return nullptr;
        }
    }

    static void Free(void* pointer, void*) noexcept {
        if (!pointer) return;
        auto* header = static_cast<AllocationHeader*>(pointer) - 1;
        const size_t allocation_size = header->allocation_size;
        header->~AllocationHeader();
        memory::ThreadMemoryPool().Deallocate(
            header, allocation_size, kAlignment);
    }

    static void* Callocate(size_t count, size_t size, void* user_data) {
        if (size != 0 && count > std::numeric_limits<size_t>::max() / size)
            return nullptr;
        const size_t bytes = count * size;
        void* pointer = Allocate(bytes, user_data);
        if (pointer) std::memset(pointer, 0, bytes);
        return pointer;
    }

    static void* Reallocate(void* pointer, size_t size, void* user_data) {
        if (!pointer) return Allocate(size, user_data);
        if (size == 0) {
            Free(pointer, user_data);
            return nullptr;
        }
        auto* old_header = static_cast<AllocationHeader*>(pointer) - 1;
        void* replacement = Allocate(size, user_data);
        if (!replacement) return nullptr;
        std::memcpy(replacement, pointer, std::min(old_header->payload_size, size));
        Free(pointer, user_data);
        return replacement;
    }
};

}  // namespace transport::internet::hysteria
