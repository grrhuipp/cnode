#include "acppnode/infra/runtime_failure.hpp"

#include <cstdlib>
#include <new>

// Fatal infrastructure reporting must not try to recover by allocating a
// formatted log message or unwinding owners with live asynchronous operations.
namespace { bool reject_allocations = false; }
void* operator new(std::size_t bytes) {
    if (reject_allocations) throw std::bad_alloc();
    if (void* memory = std::malloc(bytes ? bytes : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }

int main() {
    reject_allocations = true;
    acpp::FailRuntime("udp-receive", "registered socket receive loop stopped");
}
