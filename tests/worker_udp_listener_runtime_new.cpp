#include "worker_udp_listener_runtime_fault.hpp"

#include <cstdlib>
#include <new>

void* operator new(std::size_t size) {
    return worker_udp_listener_runtime_test::AllocateStandard(size);
}
void* operator new[](std::size_t size) {
    return worker_udp_listener_runtime_test::AllocateStandard(size);
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void* operator new(std::size_t size, std::align_val_t alignment) {
    return worker_udp_listener_runtime_test::AllocateAligned(
        static_cast<std::size_t>(alignment), size);
}
void* operator new[](std::size_t size, std::align_val_t alignment) {
    return worker_udp_listener_runtime_test::AllocateAligned(
        static_cast<std::size_t>(alignment), size);
}
void operator delete(void* p, std::align_val_t) noexcept {
    worker_udp_listener_runtime_test::DeallocateAligned(p);
}
void operator delete[](void* p, std::align_val_t) noexcept {
    worker_udp_listener_runtime_test::DeallocateAligned(p);
}
void operator delete(void* p, std::size_t, std::align_val_t) noexcept {
    worker_udp_listener_runtime_test::DeallocateAligned(p);
}
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept {
    worker_udp_listener_runtime_test::DeallocateAligned(p);
}
