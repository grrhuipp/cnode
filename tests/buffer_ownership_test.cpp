#include "acppnode/common/initial_payload.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <type_traits>
#include <vector>

namespace {
thread_local bool deny_allocation = false;
thread_local size_t failures = 0;
thread_local int allocation_budget = -1;
thread_local bool track_allocations = false;
thread_local std::array<void*, 2048> live_allocations{};
thread_local size_t live_count = 0;
}

void* operator new(std::size_t size) {
    if (deny_allocation || allocation_budget == 0) { ++failures; throw std::bad_alloc(); }
    if (allocation_budget > 0) --allocation_budget;
    if (void* pointer = std::malloc(size ? size : 1)) {
        if (track_allocations) {
            if (live_count == live_allocations.size()) std::abort();
            live_allocations[live_count++] = pointer;
        }
        return pointer;
    }
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept {
    for (size_t i = 0; i < live_count; ++i) {
        if (live_allocations[i] == pointer) {
            live_allocations[i] = live_allocations[--live_count];
            break;
        }
    }
    std::free(pointer);
}
void operator delete(void* pointer, std::size_t) noexcept { ::operator delete(pointer); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* pointer, const std::nothrow_t&) noexcept { ::operator delete(pointer); }

namespace {
using namespace acpp;
static_assert(alignof(buf::Buffer) <= alignof(std::max_align_t));
static_assert(!std::is_copy_constructible_v<InitialPayload>);
static_assert(!std::is_copy_assignable_v<InitialPayload>);
static_assert(!std::is_constructible_v<buf::MultiBuffer, buf::Buffer*>);
int failed = 0;

void Check(bool passed, const char* name) {
    std::printf("%s: %s\n", name, passed ? "PASS" : "FAIL");
    if (!passed) ++failed;
}

struct DrainBuffers {
    std::array<buf::BufferGuard, 64> held;
    DrainBuffers() {
        for (auto& buffer : held) {
            buffer = buf::BufferGuard{buf::Buffer::New()};
            if (!buffer) throw std::bad_alloc();
        }
    }
};

buf::BufferGuard Buffer(size_t bytes, uint8_t value = 0x42) {
    buf::BufferGuard buffer{buf::Buffer::New()};
    if (!buffer) throw std::bad_alloc();
    std::memset(buffer->Tail().data(), value, bytes);
    buffer->Produce(static_cast<uint32_t>(bytes));
    return buffer;
}

bool Matches(const InitialPayload& payload, std::span<const uint8_t> expected) {
    // Do not dereference an invalid inline view in the old implementation.
    if (payload.size() != expected.size()) return false;
    std::vector<uint8_t> actual(expected.size());
    return payload.CopyPrefixTo(actual.data(), actual.size()) == expected.size() &&
        std::equal(actual.begin(), actual.end(), expected.begin(), expected.end());
}

void InitialFailure() {
    const std::array<uint8_t, 17> prefix{0x31, 0x32};
    const std::array<uint8_t, 9000> suffix{0x51, 0x52};
    for (bool assign : {false, true}) {
        InitialPayload initial;
        initial.append(prefix);
        DrainBuffers drain;
        bool caught = false;
        failures = 0;
        deny_allocation = true;
        try {
            if (assign) initial.assign(suffix);
            else initial.append(suffix);
        } catch (const std::bad_alloc&) { caught = true; }
        deny_allocation = false;
        Check(caught && failures && Matches(initial, prefix),
              assign ? "initial assignment preserves old payload" : "initial spill preserves old payload");
    }
}

void BufferFailure() {
    buf::MultiBuffer payload;
    for (size_t i = 0; i < 8; ++i) payload.push_back(Buffer(1));
    auto extra = Buffer(5);
    bool caught = false;
    deny_allocation = true;
    try { payload.push_back(std::move(extra)); }
    catch (const std::bad_alloc&) { caught = true; }
    deny_allocation = false;
    Check(caught && payload.size() == 8 && payload.byte_size() == 8,
          "spill insertion preserves byte accounting");

    buf::MultiBuffer tail;
    tail.push_back(Buffer(33));
    const std::array<uint8_t, 9000> suffix{};
    DrainBuffers drain;
    deny_allocation = true;
    bool appended = buf::AppendSpanToMultiBuffer(suffix, tail);
    deny_allocation = false;
    Check(!appended && tail.byte_size() == 33 && tail.back()->Len() == 33,
          "failed append preserves existing tail");
}

std::vector<uint8_t> Flatten(const buf::MultiBuffer& payload) {
    std::vector<uint8_t> result;
    for (const auto* buffer : payload) {
        if (!buffer) continue;
        const auto bytes = buffer->Bytes();
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

bool Consistent(const buf::MultiBuffer& payload) {
    size_t bytes = 0;
    for (const auto* buffer : payload) {
        if (buffer) bytes += buffer->Len();
    }
    return payload.byte_size() == bytes && payload.empty() == (payload.size() == 0);
}

std::vector<uint8_t> Pattern(size_t bytes) {
    std::vector<uint8_t> result(bytes);
    for (size_t i = 0; i < bytes; ++i) result[i] = static_cast<uint8_t>((i * 31 + i / 7) % 251);
    return result;
}

buf::MultiBuffer Packet(std::span<const uint8_t> data) {
    buf::MultiBuffer result;
    if (!buf::AppendSpanToMultiBuffer(data, result)) throw std::bad_alloc();
    return result;
}

template <typename Function>
bool Inject(int budget, Function operation) {
    failures = 0;
    allocation_budget = budget;
    bool success = false;
    try { success = operation(); }
    catch (const std::bad_alloc&) {}
    allocation_budget = -1;
    return success;
}

template <typename Function>
void FaultMatrix(const char* name, Function operation) {
    bool reached_success = false;
    bool passed = true;
    int points = 0;
    for (int budget = 0; budget < 48; ++budget) {
        // Empty the real Worker recycle cache, then pin its maximum capacity.
        // Every allocation within the operation must reach ordinary new.
        buf::detail::TrimBufferRecycle(true);
        live_count = 0;
        track_allocations = true;
        {
            DrainBuffers drain;
            passed = operation(budget, reached_success) && passed;
        }
        buf::detail::TrimBufferRecycle(true);
        track_allocations = false;
        passed = live_count == 0 && passed;
        if (live_count != 0) std::printf("leaked allocations: %zu\n", live_count);
        ++points;
        if (reached_success) break;
    }
    std::printf("allocation points checked: %d\n", points);
    Check(passed && reached_success, name);
}

void InitialMatrix() {
    for (int mode = 0; mode < 3; ++mode) {
        FaultMatrix("initial append/assign is atomic and retryable", [mode](int budget, bool& complete) {
            const auto before = Pattern(mode == 0 ? 17 : 65000);
            const auto added = Pattern(mode == 2 ? 80000 : 20000);
            InitialPayload payload;
            payload.assign(before);
            const auto operation = [&] {
                if (mode == 2) payload.assign(added);
                else payload.append(added);
                return true;
            };
            complete = Inject(budget, operation);
            const bool unchanged = complete || (failures != 0 && Matches(payload, before));
            if (!complete) operation();
            auto expected = mode == 2 ? std::vector<uint8_t>{} : before;
            expected.insert(expected.end(), added.begin(), added.end());
            const bool matched = Matches(payload, expected);
            auto moved = payload.MoveToMultiBuffer();
            return unchanged && matched && payload.empty() && Flatten(moved) == expected && Consistent(moved);
        });
    }
}

void AppendMatrix() {
    FaultMatrix("span append rolls back data and pointer allocation failures", [](int budget, bool& complete) {
        const auto before = Pattern(33);
        const auto added = Pattern(90000);
        auto payload = Packet(before);
        auto* original = *payload.begin();
        complete = Inject(budget, [&] { return buf::AppendSpanToMultiBuffer(added, payload); });
        const bool unchanged = complete || (failures != 0 && Flatten(payload) == before &&
            Consistent(payload) && payload.size() == 1 && *payload.begin() == original);
        if (!complete && !buf::AppendSpanToMultiBuffer(added, payload)) return false;
        auto expected = before;
        expected.insert(expected.end(), added.begin(), added.end());
        return unchanged && Flatten(payload) == expected && Consistent(payload);
    });

    for (size_t count : {size_t{8}, size_t{16}}) {
        FaultMatrix("consumed guard is released when pointer insertion fails", [count](int budget, bool& complete) {
            buf::MultiBuffer payload;
            for (size_t i = 0; i < count; ++i) payload.push_back(Buffer(1));
            auto before = Flatten(payload);
            auto extra = Buffer(5, 0x11);
            complete = Inject(budget, [&] { payload.push_back(std::move(extra)); return true; });
            if (extra) return false;
            if (!complete) return failures != 0 && Flatten(payload) == before && Consistent(payload);
            before.insert(before.end(), 5, 0x11);
            return Flatten(payload) == before && Consistent(payload);
        });
    }
}

void TransferMatrix() {
    for (bool prefix : {false, true}) {
        FaultMatrix(prefix ? "prefix split preserves both containers on failure" :
                              "whole transfer preserves ownership and UDP metadata on failure",
            [prefix](int budget, bool& complete) {
                const auto source_bytes = Pattern(buf::Buffer::kSize + 100);
                const auto target_bytes = Pattern(buf::Buffer::kSize * 8);
                auto source = Packet(source_bytes);
                auto target = Packet(target_bytes);
                auto* original = *source.begin();
                const TargetAddress endpoint{"127.0.0.1", 1234};
                original->SetUDP(endpoint);
                const size_t bytes = prefix ? buf::Buffer::kSize + 17 : source_bytes.size();
                const auto operation = [&] {
                    if (prefix) return source.MovePrefixTo(target, bytes);
                    source.MoveTo(target, true);
                    return true;
                };
                complete = Inject(budget, operation);
                const bool unchanged = complete || (failures != 0 &&
                    Flatten(source) == source_bytes && Flatten(target) == target_bytes &&
                    Consistent(source) && Consistent(target) && *source.begin() == original &&
                    original->HasUDP() && original->UDP().SameEndpoint(endpoint));
                if (!complete && !operation()) return false;
                auto expected = target_bytes;
                expected.insert(expected.end(), source_bytes.begin(), source_bytes.begin() + bytes);
                return unchanged && Flatten(target) == expected &&
                    Flatten(source) == std::vector<uint8_t>(source_bytes.begin() + bytes, source_bytes.end()) &&
                    Consistent(source) && Consistent(target) && (prefix || !original->HasUDP());
            });
    }
}

void EdgeCases() {
    // A consumed spill prefix must not invalidate reserve's no-allocation
    // promise for active slots. This previously released a source slot first.
    buf::MultiBuffer target;
    target.reserve(16);
    for (size_t i = 0; i < 16; ++i) target.push_back(Buffer(1));
    target.drop_front(1);
    auto source = buf::MultiBuffer{Buffer(3, 0x55)};
    Check(Inject(0, [&] { source.MoveTo(target); return true; }) && source.empty() &&
          target.size() == 16 && target.byte_size() == 18 && Consistent(target),
          "reserved active slots remain allocation free after prefix consumption");

    auto bytes = Pattern(100);
    InitialPayload initial;
    initial.assign(bytes);
    initial.append(initial.span());
    auto twice = bytes;
    twice.insert(twice.end(), bytes.begin(), bytes.end());
    Check(Matches(initial, twice), "inline self append");
    initial.assign(initial.span().subspan(5, 77));
    Check(Matches(initial, std::span<const uint8_t>{bytes}.subspan(5, 77)), "self assignment");
    initial.assign(Pattern(9000));
    auto expected = Pattern(9000);
    const auto prefix = initial.PrefixSpan(33);
    expected.insert(expected.end(), prefix.begin(), prefix.end());
    initial.append(prefix);
    Check(Matches(initial, expected), "spilled self append");

    auto owned_bytes = Pattern(9000);
    auto owned = Packet(owned_bytes);
    const auto* original_buffer = *owned.begin();
    buf::MultiBuffer transferred;
    Check(Inject(0, [&] {
        InitialPayload from_stream{std::move(owned)};
        transferred = from_stream.MoveToMultiBuffer();
        return from_stream.empty();
    }) && owned.empty() && *transferred.begin() == original_buffer &&
          Flatten(transferred) == owned_bytes, "logical stream remainder transfers without allocation or payload copy");

    auto partial = Packet(bytes);
    auto into = Packet(bytes);
    const auto before = Flatten(into);
    Check(!partial.MovePrefixTo(into, 101) && Flatten(partial) == bytes && Flatten(into) == before,
          "short source does not partially transfer");
    Check(!partial.MovePrefixTo(partial, 1) && partial.MovePrefixTo(into, 0), "self and empty prefix");
    // Compact a consumed destination tail only after preparation succeeds.
    into = buf::MultiBuffer{Buffer(buf::Buffer::kSize)};
    into.DropPrefixBytes(100);
    Check(Inject(0, [&] { return partial.MovePrefixTo(into, 77); }) &&
          partial.byte_size() == 23 && into.byte_size() == buf::Buffer::kSize - 23 &&
          Consistent(partial) && Consistent(into), "prefix coalescing remains allocation free");

    const TargetAddress endpoint{"127.0.0.1", 1234};
    auto udp = buf::MultiBuffer{Buffer(1)};
    udp.back()->SetUDP(endpoint);
    Check(buf::AppendSpanToMultiBuffer(bytes, udp) && udp.size() == 2 &&
          (*udp.begin())->Len() == 1 && (*udp.begin())->UDP().SameEndpoint(endpoint) &&
          !udp.back()->HasUDP(), "span append respects UDP packet boundary");

    // Empty slots and whole-buffer transfers keep byte counts exact.
    buf::MultiBuffer sparse;
    sparse.push_back(Buffer(0));
    sparse.push_back(Buffer(3));
    sparse.push_back(Buffer(0));
    sparse.push_back(Buffer(5));
    buf::MultiBuffer moved;
    Check(sparse.MovePrefixTo(moved, 8) && !buf::HasData(sparse) && moved.byte_size() == 8 &&
          moved.size() == 2 && Consistent(sparse) && Consistent(moved), "whole prefix skips empty slots");
}
}

int main() {
    InitialFailure();
    BufferFailure();
    InitialMatrix();
    AppendMatrix();
    TransferMatrix();
    EdgeCases();
    return failed ? 1 : 0;
}
