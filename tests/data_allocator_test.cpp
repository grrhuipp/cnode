#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <thread>

namespace {
using namespace acpp::memory;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class CountingResource final : public std::pmr::memory_resource {
public:
    std::atomic<std::size_t> live{0};
    std::atomic<bool> reject{false};
private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
        if (reject.exchange(false)) throw std::bad_alloc();
        auto* pointer = DataResource()->allocate(bytes, alignment);
        live.fetch_add(1);
        return pointer;
    }
    void do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment) override {
        DataResource()->deallocate(pointer, bytes, alignment);
        live.fetch_sub(1);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

void TestAlignmentAndCrossThreadRelease() {
    for (const std::size_t bytes : {0u, 1u, 31u, 8192u, 17408u, 65536u}) {
        for (std::size_t alignment = 1; alignment <= 4096; alignment *= 2) {
            auto* pointer = AllocateData(bytes, alignment);
            Require(pointer && reinterpret_cast<std::uintptr_t>(pointer) % alignment == 0,
                    "allocation alignment must be preserved");
            std::memset(pointer, 0xa5, bytes);
            bool intact = false;
            std::thread release([&] {
                intact = true;
                const auto* data = static_cast<const unsigned char*>(pointer);
                for (std::size_t i = 0; i < bytes; ++i) intact = intact && data[i] == 0xa5;
                DeallocateData(pointer, 0, alignment);
            });
            release.join();
            Require(intact, "data must remain intact until its owner releases it");
        }
    }
    Require(!AllocateData(128, 0) && !AllocateData(128, 3),
            "invalid alignment must be rejected");
    Require(!AllocateData(std::numeric_limits<std::size_t>::max()),
            "oversized allocation must fail");
}

struct Plain final : DataAllocated {
    explicit Plain(std::atomic<int>& destroyed) : destroyed(destroyed) {}
    ~Plain() { ++destroyed; }
    std::atomic<int>& destroyed;
};
struct alignas(256) Aligned final : DataAllocated {
    explicit Aligned(std::atomic<int>& destroyed) : destroyed(destroyed) {}
    ~Aligned() { ++destroyed; }
    std::atomic<int>& destroyed;
    std::array<char, 256> payload{};
};
struct Throws final : DataAllocated {
    Throws() { throw std::runtime_error("constructor failure"); }
};
struct alignas(256) AlignedThrows final : DataAllocated {
    AlignedThrows() { throw std::runtime_error("aligned constructor failure"); }
};

void TestObjectsAndSharedControlBlocks() {
    std::atomic<int> destroyed{0};
    auto* plain = new Plain(destroyed);
    auto* aligned = new Aligned(destroyed);
    Require(reinterpret_cast<std::uintptr_t>(aligned) % alignof(Aligned) == 0,
            "class aligned new must preserve alignment");
    auto shared = AllocateShared<Plain>(destroyed);
    std::thread release([&, shared = std::move(shared)]() mutable {
        delete plain;
        delete aligned;
        shared.reset();
    });
    release.join();
    Require(destroyed.load() == 3, "all object forms must support cross-thread destruction");
    for (const bool aligned_failure : {false, true}) {
        bool failed = false;
        try {
            if (aligned_failure) delete new AlignedThrows;
            else delete new Throws;
        } catch (const std::runtime_error&) { failed = true; }
        Require(failed, "constructor failure must exercise matching delete");
    }
}

void TestExplicitResourcesAndRollback() {
    CountingResource resource;
    {
        DataVector<int> values{DataAllocator<int>{&resource}};
        values.assign(32, 42);
        const auto live = resource.live.load();
        resource.reject = true;
        bool failed = false;
        try { values.reserve(4096); } catch (const std::bad_alloc&) { failed = true; }
        Require(failed && values.size() == 32 && values[0] == 42 &&
                resource.live.load() == live,
                "failed growth must preserve values and release no live storage");
        std::thread release([values = std::move(values), &resource]() mutable {
            Require(values.get_allocator().resource() == &resource,
                    "moving storage must preserve its explicit resource");
            values.clear();
            values.shrink_to_fit();
        });
        release.join();
    }
    Require(resource.live.load() == 0, "explicit resource must receive the final cross-thread release");
    {
        DataVector<DataString> strings{DataAllocator<DataString>{&resource}};
        strings.emplace_back(256, 'x');
        auto copy = strings;
        Require(strings[0].get_allocator().resource() == &resource &&
                copy.get_allocator().resource() == &resource &&
                copy[0].get_allocator().resource() == &resource,
                "owned nested values and copies must preserve the explicit resource");
        bool rejected_null = false;
        try { DataAllocator<int> invalid{static_cast<std::pmr::memory_resource*>(nullptr)}; }
        catch (const std::invalid_argument&) { rejected_null = true; }
        Require(rejected_null, "an explicit allocator cannot have a null resource");
    }
    Require(resource.live.load() == 0, "nested ownership must release every resource allocation");

    std::array<std::thread, 4> threads;
    for (auto& thread : threads) {
        thread = std::thread([&] {
            for (int i = 0; i < 1000; ++i) {
                DataVector<int> values{DataAllocator<int>{&resource}};
                values.assign(64, i);
            }
        });
    }
    for (auto& thread : threads) thread.join();
    Require(resource.live.load() == 0, "concurrent allocations must be fully released");
}

void TestDefaultResourceIndependence() {
    auto* previous = std::pmr::set_default_resource(std::pmr::null_memory_resource());
    try {
        ConfigureProcessAllocator();
        Require(std::pmr::get_default_resource() == std::pmr::null_memory_resource(),
                "process initialization must not change the PMR default");
        DataString string(256, 'x');
        DataUnorderedMap<DataString, int> map;
        map.emplace(string, 1);
        auto shared = AllocateShared<int>(17);
        Require(string.get_allocator().resource() == DataResource() && map.at(string) == 1 &&
                *shared == 17, "default data allocations must use their fixed upstream");
    } catch (...) {
        std::pmr::set_default_resource(previous);
        throw;
    }
    std::pmr::set_default_resource(previous);
}

void TestFaultRecoveryAndBufferTransfer() {
    const auto rejected = rejected_data_allocations.load();
    reject_next_data_allocation = true;
    Require(AllocateData(32) == nullptr && !reject_next_data_allocation.load() &&
            rejected_data_allocations.load() == rejected + 1,
            "allocation fault must be consumed exactly once");
    reject_next_data_allocation = true;
    bool failed = false;
    try { auto pointer = AllocateShared<int>(1); } catch (const std::bad_alloc&) { failed = true; }
    Require(failed, "shared control block allocation must propagate allocation failure");
    auto* buffer = acpp::buf::Buffer::New();
    Require(buffer != nullptr, "buffer must recover after an allocation failure");
    buffer->Produce(1);
    buffer->data[0] = 0x5a;
    std::thread release([buffer] { acpp::buf::Buffer::Free(buffer); });
    release.join();
}
} // namespace

int main() {
    const auto before = live_data_allocations.load();
    try {
        TestAlignmentAndCrossThreadRelease();
        TestObjectsAndSharedControlBlocks();
        TestExplicitResourcesAndRollback();
        TestDefaultResourceIndependence();
        TestFaultRecoveryAndBufferTransfer();
        Require(live_data_allocations.load() == before,
                "success, failure and cross-thread destruction must release every allocation");
        std::puts("data allocator ownership/alignment/concurrency/OOM: PASS");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
