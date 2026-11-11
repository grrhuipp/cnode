#include "allocation_hook.hpp"

#include <new>

// Linked with -Wl,--wrap for each symbol below; __real_* resolves to mimalloc.
extern "C" {
void* __real__Znwm(std::size_t);
void* __real__Znam(std::size_t);
void* __real__ZnwmRKSt9nothrow_t(std::size_t, const std::nothrow_t&) noexcept;
void* __real__ZnamRKSt9nothrow_t(std::size_t, const std::nothrow_t&) noexcept;
void __real__ZdlPv(void*) noexcept;
void __real__ZdaPv(void*) noexcept;
void __real__ZdlPvm(void*, std::size_t) noexcept;
void __real__ZdaPvm(void*, std::size_t) noexcept;
void __real__ZdlPvRKSt9nothrow_t(void*, const std::nothrow_t&) noexcept;
void __real__ZdaPvRKSt9nothrow_t(void*, const std::nothrow_t&) noexcept;
}

namespace {

using allocation_hook::hooks;

void* Allocate(void* (*real)(std::size_t), std::size_t size) {
    if (hooks.before_new) hooks.before_new(size);
    void* pointer = real(size);
    if (hooks.after_new) hooks.after_new(pointer, size);
    return pointer;
}

void* AllocateNoThrow(void* (*real)(std::size_t, const std::nothrow_t&) noexcept,
                      std::size_t size, const std::nothrow_t& tag) noexcept {
    try {
        if (hooks.before_new) hooks.before_new(size);
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
    void* pointer = real(size, tag);
    if (pointer && hooks.after_new) hooks.after_new(pointer, size);
    return pointer;
}

void BeforeDelete(void* pointer) noexcept {
    if (hooks.before_delete) hooks.before_delete(pointer);
}

}  // namespace

extern "C" {
void* __wrap__Znwm(std::size_t size) { return Allocate(__real__Znwm, size); }
void* __wrap__Znam(std::size_t size) { return Allocate(__real__Znam, size); }
void* __wrap__ZnwmRKSt9nothrow_t(std::size_t size, const std::nothrow_t& tag) noexcept {
    return AllocateNoThrow(__real__ZnwmRKSt9nothrow_t, size, tag);
}
void* __wrap__ZnamRKSt9nothrow_t(std::size_t size, const std::nothrow_t& tag) noexcept {
    return AllocateNoThrow(__real__ZnamRKSt9nothrow_t, size, tag);
}
void __wrap__ZdlPv(void* pointer) noexcept {
    BeforeDelete(pointer);
    __real__ZdlPv(pointer);
}
void __wrap__ZdaPv(void* pointer) noexcept {
    BeforeDelete(pointer);
    __real__ZdaPv(pointer);
}
void __wrap__ZdlPvm(void* pointer, std::size_t size) noexcept {
    BeforeDelete(pointer);
    __real__ZdlPvm(pointer, size);
}
void __wrap__ZdaPvm(void* pointer, std::size_t size) noexcept {
    BeforeDelete(pointer);
    __real__ZdaPvm(pointer, size);
}
void __wrap__ZdlPvRKSt9nothrow_t(void* pointer, const std::nothrow_t& tag) noexcept {
    BeforeDelete(pointer);
    __real__ZdlPvRKSt9nothrow_t(pointer, tag);
}
void __wrap__ZdaPvRKSt9nothrow_t(void* pointer, const std::nothrow_t& tag) noexcept {
    BeforeDelete(pointer);
    __real__ZdaPvRKSt9nothrow_t(pointer, tag);
}
}
