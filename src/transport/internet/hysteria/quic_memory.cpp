#include "quic_memory.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>

namespace transport::internet::hysteria {
namespace {

struct alignas(std::max_align_t) AllocationHeader {
    size_t payload_size;
    size_t allocation_size;
};

constexpr size_t kAlignment = alignof(std::max_align_t);

[[nodiscard]] bool AllocationSize(size_t payload_size, size_t& result) noexcept {
    if (payload_size > std::numeric_limits<size_t>::max() - sizeof(AllocationHeader))
        return false;
    result = sizeof(AllocationHeader) + payload_size;
    return true;
}

}  // namespace

QuicMemory::QuicMemory(memory::AllocationDomain& domain) noexcept
    : domain_(&domain)
    , ngtcp2_{this, &Allocate, &Free, &Callocate, &Reallocate}
    , nghttp3_{this, &Allocate, &Free, &Callocate, &Reallocate} {}

void* QuicMemory::Allocate(size_t size, void* user_data) {
    try {
        auto& self = *static_cast<QuicMemory*>(user_data);
        memory::ScopedAllocationDomain scope(*self.domain_);
        size_t allocation_size = 0;
        if (!AllocationSize(size, allocation_size)) return nullptr;
        void* raw =
            self.domain_->resource()->allocate(allocation_size, kAlignment);
        auto* header =
            ::new (raw) AllocationHeader{size, allocation_size};
        return header + 1;
    } catch (...) {
        return nullptr;
    }
}

void QuicMemory::Free(void* pointer, void* user_data) noexcept {
    if (!pointer) return;
    auto& self = *static_cast<QuicMemory*>(user_data);
    memory::ScopedAllocationDomain scope(*self.domain_);
    auto* header = static_cast<AllocationHeader*>(pointer) - 1;
    const size_t allocation_size = header->allocation_size;
    header->~AllocationHeader();
    self.domain_->resource()->deallocate(
        header, allocation_size, kAlignment);
}

void* QuicMemory::Callocate(size_t count, size_t size, void* user_data) {
    if (size != 0 && count > std::numeric_limits<size_t>::max() / size)
        return nullptr;
    const size_t bytes = count * size;
    void* pointer = Allocate(bytes, user_data);
    if (pointer) std::memset(pointer, 0, bytes);
    return pointer;
}

void* QuicMemory::Reallocate(void* pointer, size_t size, void* user_data) {
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

}  // namespace transport::internet::hysteria
