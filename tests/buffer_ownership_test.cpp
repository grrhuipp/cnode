#include <gtest/gtest.h>

#include "common/initial_payload.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <type_traits>
#include <limits>
#include <vector>

namespace {
thread_local size_t failures = 0;
thread_local int allocation_budget = -1;
thread_local bool track_allocations = false;
thread_local std::array<void*, 2048> live_allocations{};
thread_local size_t live_count = 0;
}

void* operator new(std::size_t size) {
    if (allocation_budget == 0) { ++failures; throw std::bad_alloc(); }
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
static_assert(alignof(buf::Buffer) <= alignof(std::max_align_t));
int failed = 0;

void Check(bool passed, const char* name) {
    std::printf("%s: %s\n", name, passed ? "PASS" : "FAIL");
    std::fflush(stdout);
    if (!passed) ++failed;
}

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

class FailingResource final : public std::pmr::memory_resource {
public:
    explicit FailingResource(std::pmr::memory_resource* upstream) noexcept
        : upstream_(upstream) {}

    void RejectNextAllocation() noexcept { reject_next_ = true; }
    [[nodiscard]] size_t RejectedAllocations() const noexcept { return rejected_; }

private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (reject_next_) {
            reject_next_ = false;
            ++rejected_;
            throw std::bad_alloc();
        }
        return upstream_->allocate(bytes, alignment);
    }
    void do_deallocate(void* pointer, size_t bytes, size_t alignment) override {
        upstream_->deallocate(pointer, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }

    std::pmr::memory_resource* upstream_;
    bool reject_next_ = false;
    size_t rejected_ = 0;
};

class ScopedDefaultResource {
public:
    explicit ScopedDefaultResource(std::pmr::memory_resource* resource) noexcept
        : previous_(std::pmr::set_default_resource(resource)) {}
    ~ScopedDefaultResource() { std::pmr::set_default_resource(previous_); }
    ScopedDefaultResource(const ScopedDefaultResource&) = delete;
    ScopedDefaultResource& operator=(const ScopedDefaultResource&) = delete;

private:
    std::pmr::memory_resource* previous_;
};

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
        live_count = 0;
        track_allocations = true;
        {
            passed = operation(budget, reached_success) && passed;
        }
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
            auto moved = std::move(payload).MoveToMultiBuffer();
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

void UdpPrefixTransfer() {
    const TargetAddress source_target{
        "split-copy-target-host-name-longer-than-sso.example.com", 14321};
    const TargetAddress destination_target{
        "different-destination-target-name-longer-than-sso.example.net", 14322};
    const auto source_bytes = Pattern(91);
    constexpr size_t prefix_bytes = 23;

    for (int destination_kind = 0; destination_kind != 3; ++destination_kind) {
        auto source = Packet(source_bytes);
        auto* source_buffer = *source.begin();
        source_buffer->SetUDP(source_target);
        buf::MultiBuffer destination;
        buf::Buffer* prior_tail = nullptr;
        std::vector<uint8_t> destination_before;
        if (destination_kind != 0) {
            buf::BufferGuard tail = Buffer(31, 0x6D);
            prior_tail = tail.get();
            if (destination_kind == 2) prior_tail->SetUDP(destination_target);
            destination.push_back(std::move(tail));
            destination_before = Flatten(destination);
        }

        const bool moved = source.MovePrefixTo(destination, prefix_bytes);
        std::vector<uint8_t> expected_destination = destination_before;
        expected_destination.insert(expected_destination.end(),
            source_bytes.begin(), source_bytes.begin() + prefix_bytes);
        const std::vector<uint8_t> expected_source(
            source_bytes.begin() + prefix_bytes, source_bytes.end());
        bool metadata_ok = source_buffer->HasUDP() &&
            source_buffer->UDP().SameEndpoint(source_target) && destination.size() ==
                static_cast<size_t>(destination_kind == 0 ? 1 : 2);
        if (destination_kind != 0) {
            metadata_ok = metadata_ok && *destination.begin() == prior_tail &&
                destination.begin()[0]->Len() == 31;
            if (destination_kind == 1) metadata_ok = metadata_ok && !prior_tail->HasUDP();
            else metadata_ok = metadata_ok && prior_tail->HasUDP() &&
                prior_tail->UDP().SameEndpoint(destination_target);
        }
        auto* split = destination.back();
        metadata_ok = metadata_ok && split != prior_tail && split->Len() == prefix_bytes &&
            split->HasUDP() && split->UDP().SameEndpoint(source_target);
        Check(moved && metadata_ok && Flatten(source) == expected_source &&
              Flatten(destination) == expected_destination && Consistent(source) &&
              Consistent(destination),
              destination_kind == 0 ? "UDP prefix split preserves target to empty destination" :
              destination_kind == 1 ? "UDP prefix split does not coalesce into TCP tail" :
                                      "UDP prefix split does not coalesce into UDP tail");
    }

    bool rolled_back = false;
    bool retry_metadata = false;
    bool retry_bytes = false;
    FailingResource failing_resource{std::pmr::new_delete_resource()};
    {
        ScopedDefaultResource default_resource{&failing_resource};
        const TargetAddress long_target{
            "split-copy-target-host-name-longer-than-sso.example.com", 14321};
        auto source = Packet(source_bytes);
        auto* original = *source.begin();
        original->SetUDP(long_target);
        buf::MultiBuffer destination;
        destination.reserve(1);
        auto* const source_slot = original;

        failing_resource.RejectNextAllocation();
        const bool moved_on_failed_copy = source.MovePrefixTo(destination, prefix_bytes);
        rolled_back = !moved_on_failed_copy && failing_resource.RejectedAllocations() == 1 &&
            source.size() == 1 && *source.begin() == source_slot &&
            Flatten(source) == source_bytes && source.byte_size() == source_bytes.size() &&
            original->HasUDP() && original->UDP().SameEndpoint(long_target) &&
            destination.empty() && destination.byte_size() == 0 &&
            Consistent(source) && Consistent(destination);

        const bool retried = source.MovePrefixTo(destination, prefix_bytes);
        retry_metadata = retried && source.size() == 1 && original->HasUDP() &&
            original->UDP().SameEndpoint(long_target) && destination.size() == 1 &&
            destination.back()->HasUDP() &&
            destination.back()->UDP().SameEndpoint(long_target) &&
            destination.back()->Len() == prefix_bytes;
        retry_bytes = source.byte_size() == source_bytes.size() - prefix_bytes &&
            destination.byte_size() == prefix_bytes && Consistent(source) && Consistent(destination);
    }
    Check(rolled_back && retry_metadata && retry_bytes,
          "UDP target-copy allocation failure rolls back source and destination");
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
        transferred = std::move(from_stream).MoveToMultiBuffer();
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
    Check(sparse.MovePrefixTo(moved, 8) && sparse.byte_size() == 0 && moved.byte_size() == 8 &&
          moved.size() == 2 && Consistent(sparse) && Consistent(moved), "whole prefix skips empty slots");
}
}

TEST(BufferOwnership, Contract) {
    InitialMatrix();
    AppendMatrix();
    TransferMatrix();
    UdpPrefixTransfer();
    EdgeCases();
    { ASSERT_EQ((failed ? 1 : 0), 0); return; }
}

TEST(BufferOwnership, PartialConsumptionReturnsSpillStorageWithoutCopyingPayload) {
    ::memory::AllocationDomain domain;
    ::memory::ScopedAllocationDomain lease(domain);
    ::buf::MultiBuffer payload;
    payload.reserve(4096);
    for (size_t i = 0; i < 4096; ++i)
        payload.push_back(Buffer(1, static_cast<uint8_t>(i)));
    auto* const last = payload.back();
    const ::TargetAddress endpoint{"127.0.0.1", 1234};
    last->SetUDP(endpoint);

    EXPECT_EQ(payload.DropPrefixBytes(4096 - ::buf::MultiBuffer::kInlineCapacity),
              4096 - ::buf::MultiBuffer::kInlineCapacity);
    ASSERT_EQ(payload.size(), ::buf::MultiBuffer::kInlineCapacity);
    EXPECT_EQ(domain.OutstandingAllocations(), payload.size());
    EXPECT_TRUE(Consistent(payload));
    EXPECT_EQ(payload.back(), last);
    EXPECT_TRUE(last->UDP().SameEndpoint(endpoint));

    ::buf::MultiBuffer moved = std::move(payload);
    EXPECT_TRUE(payload.empty());
    for (size_t i = 0; i < ::buf::MultiBuffer::kInlineCapacity; ++i) {
        auto buffer = moved.pop_front();
        ASSERT_TRUE(buffer);
        ASSERT_EQ(buffer->Len(), 1);
        EXPECT_EQ(buffer->Bytes()[0], static_cast<uint8_t>(4096 - ::buf::MultiBuffer::kInlineCapacity + i));
    }
    EXPECT_TRUE(moved.empty());
    EXPECT_EQ(domain.OutstandingAllocations(), 0);
}

TEST(BufferOwnership, MovedInlineAndSpilledContainersRemainReusable) {
    memory::AllocationDomain domain;
    memory::ScopedAllocationDomain lease(domain);
    for (const size_t source_count : {0u, 1u, 8u, 9u, 16u}) {
        for (const size_t destination_count : {0u, 1u, 9u}) {
            SCOPED_TRACE(source_count);
            SCOPED_TRACE(destination_count);
            auto expected = Pattern(source_count);
            buf::MultiBuffer source;
            for (const auto byte : expected) source.push_back(Buffer(1, byte));
            if (source_count > 1) {
                source.drop_front(1);
                expected.erase(expected.begin());
            }
            buf::MultiBuffer transferred(std::move(source));
            EXPECT_TRUE(source.empty());
            EXPECT_EQ(source.byte_size(), 0u);
            for (size_t i = 0; i < 9; ++i) source.push_back(Buffer(1, 0xa5));

            buf::MultiBuffer destination;
            for (size_t i = 0; i < destination_count; ++i)
                destination.push_back(Buffer(1, 0xff));
            destination = std::move(transferred);
            EXPECT_TRUE(transferred.empty());
            EXPECT_EQ(transferred.byte_size(), 0u);
            EXPECT_EQ(Flatten(destination), expected);
            EXPECT_TRUE(Consistent(destination));
            EXPECT_EQ(Flatten(source), std::vector<uint8_t>(9, 0xa5));

            transferred.push_back(Buffer(1, 0x73));
            EXPECT_EQ(Flatten(transferred), std::vector<uint8_t>{0x73});
            source.clear();
            destination.clear();
            transferred.clear();
            EXPECT_EQ(domain.OutstandingAllocations(), 0u);
        }
    }
}

TEST(BufferOwnership, FailedFirstSpillPreservesInlinePayloadAndCanRetry) {
    FailingResource resource(std::pmr::get_default_resource());
    ScopedDefaultResource scope(&resource);
    const auto expected = Pattern(buf::MultiBuffer::kInlineCapacity);
    buf::MultiBuffer payload;
    for (const auto byte : expected) payload.push_back(Buffer(1, byte));
    std::array<buf::Buffer*, buf::MultiBuffer::kInlineCapacity> original;
    std::copy(payload.begin(), payload.end(), original.begin());

    resource.RejectNextAllocation();
    EXPECT_THROW(payload.reserve(buf::MultiBuffer::kInlineCapacity + 1), std::bad_alloc);
    EXPECT_EQ(resource.RejectedAllocations(), 1u);
    EXPECT_EQ(Flatten(payload), expected);
    EXPECT_TRUE(Consistent(payload));
    EXPECT_TRUE(std::equal(payload.begin(), payload.end(), original.begin(), original.end()));

    payload.reserve(buf::MultiBuffer::kInlineCapacity + 1);
    payload.push_back(Buffer(1, 0x91));
    auto extended = expected;
    extended.push_back(0x91);
    EXPECT_EQ(Flatten(payload), extended);
    EXPECT_TRUE(Consistent(payload));
}

TEST(BufferOwnership, CoalescingUsesExistingTailWhenMetadataAllocationIsUnavailable) {
    FailingResource resource(std::pmr::get_default_resource());
    ScopedDefaultResource scope(&resource);
    buf::MultiBuffer target, source;
    for (size_t i = 0; i < buf::MultiBuffer::kInlineCapacity; ++i)
        target.push_back(Buffer(1, static_cast<uint8_t>(i)));
    auto* const tail = target.back();
    for (size_t i = 0; i < 16; ++i)
        source.push_back(Buffer(1, static_cast<uint8_t>(0x80 + i)));
    source.push_back(Buffer(0));
    auto expected = Flatten(target);
    const auto added = Flatten(source);
    expected.insert(expected.end(), added.begin(), added.end());

    resource.RejectNextAllocation();
    ASSERT_NO_THROW(target.AppendAndCoalesce(std::move(source)));
    EXPECT_EQ(Flatten(target), expected);
    EXPECT_EQ(target.size(), buf::MultiBuffer::kInlineCapacity);
    EXPECT_EQ(target.back(), tail);
    EXPECT_TRUE(source.empty());
    EXPECT_TRUE(Consistent(target));
    EXPECT_EQ(resource.RejectedAllocations(), 0);
}

TEST(BufferOwnership, CoalescingPreparesNewSlotsBeforeChangingBytesOrUdpBoundaries) {
    FailingResource resource(std::pmr::get_default_resource());
    ScopedDefaultResource scope(&resource);
    buf::MultiBuffer target, source;
    for (size_t i = 0; i < buf::MultiBuffer::kInlineCapacity; ++i)
        target.push_back(Buffer(1, static_cast<uint8_t>(i)));
    for (uint8_t value = 0x80; value < 0x84; ++value)
        source.push_back(Buffer(value == 0x81 ? 0 : 1, value));
    auto* const datagram = *(source.begin() + 1);
    const TargetAddress endpoint{"127.0.0.1", 4321};
    datagram->SetUDP(endpoint);
    const auto before = Flatten(target);
    const auto added = Flatten(source);

    resource.RejectNextAllocation();
    EXPECT_THROW(target.AppendAndCoalesce(std::move(source)), std::bad_alloc);
    EXPECT_EQ(Flatten(target), before);
    EXPECT_EQ(Flatten(source), added);
    ASSERT_EQ(source.size(), 4);
    EXPECT_EQ(*(source.begin() + 1), datagram);
    EXPECT_TRUE(datagram->UDP().SameEndpoint(endpoint));
    EXPECT_TRUE(Consistent(target));
    EXPECT_TRUE(Consistent(source));

    target.AppendAndCoalesce(std::move(source));
    auto expected = before;
    expected.insert(expected.end(), added.begin(), added.end());
    EXPECT_EQ(Flatten(target), expected);
    ASSERT_EQ(target.size(), buf::MultiBuffer::kInlineCapacity + 2);
    EXPECT_EQ(*(target.begin() + buf::MultiBuffer::kInlineCapacity), datagram);
    EXPECT_TRUE(datagram->UDP().SameEndpoint(endpoint));
    EXPECT_FALSE(target.back()->HasUDP());
    EXPECT_EQ(target.back()->Len(), 2);
    EXPECT_TRUE(source.empty());
    EXPECT_TRUE(Consistent(target));
}

TEST(BufferOwnership, EmptyUdpMessageSurvivesTransfersAndChecksEveryTarget) {
    buf::MultiBuffer stream_empty;
    stream_empty.push_back(Buffer(0));
    stream_empty.ReleaseIfIdle();
    EXPECT_TRUE(stream_empty.empty());

    const TargetAddress first_target{"127.0.0.1", 1234};
    const TargetAddress second_target{"127.0.0.1", 4321};
    buf::MultiBuffer packet;
    ASSERT_TRUE(buf::SetUdpTarget(packet, first_target));
    const auto* original = *packet.begin();
    InitialPayload initial(std::move(packet));
    EXPECT_FALSE(initial.empty());
    EXPECT_EQ(initial.size(), 0);
    auto moved = std::move(initial).MoveToMultiBuffer();
    moved.ReleaseIfIdle();
    EXPECT_TRUE(initial.empty());
    {
        const auto info = buf::InspectUdpDatagram(moved);
        ASSERT_TRUE(info.Valid());
        EXPECT_EQ(info.payload_size, 0);
        EXPECT_TRUE(info.target->SameEndpoint(first_target));
    }
    buf::MultiBuffer destination;
    moved.MoveTo(destination);
    ASSERT_EQ(destination.size(), 1);
    EXPECT_EQ(*destination.begin(), original);
    EXPECT_TRUE(moved.empty());

    buf::MultiBuffer later;
    later.push_back(Buffer(1));
    ASSERT_TRUE(buf::SetUdpTarget(later, second_target));
    destination.AppendAndCoalesce(std::move(later));
    EXPECT_EQ(destination.size(), 2);
    EXPECT_EQ(destination.byte_size(), 1);
    EXPECT_EQ(buf::InspectUdpDatagram(destination).status, buf::UdpDatagramStatus::MixedTarget);
}

TEST(BufferOwnership, UnrepresentableWriteCapacityReturnsFailureAndAllowsReuse) {
    EXPECT_EXIT(([] {
        bool passed = true;
        for (const size_t initial_size : {size_t{32}, size_t{buf::Buffer::kSize + 1}}) {
            memory::AllocationDomain domain;
            memory::ScopedAllocationDomain lease(domain);
            {
                buf::ContiguousWriteBuffer storage;
                (void)storage.Prepare(initial_size);
                passed &= storage.TryPrepare(std::numeric_limits<size_t>::max()) == nullptr;
                passed &= storage.Empty() && storage.Data() == nullptr;
                passed &= domain.OutstandingAllocations() == 0;

                const auto expected = Pattern(
                    initial_size <= buf::Buffer::kSize ? buf::Buffer::kSize + 1 : 33);
                auto* data = storage.TryPrepare(expected.size());
                if (!data) std::_Exit(1);
                std::memcpy(data, expected.data(), expected.size());
                buf::MultiBuffer output;
                passed &= storage.TryAppendTo(expected.size(), output);
                passed &= Flatten(output) == expected && Consistent(output);
                passed &= storage.Empty() && storage.Data() == nullptr;
            }
            passed &= domain.OutstandingAllocations() == 0;
        }
        std::_Exit(passed ? 0 : 1);
    }()), ::testing::ExitedWithCode(0), "");
}

TEST(BufferOwnership, StreamInputTransfersInlineBlocksWhenMetadataAllocationIsUnavailable) {
    FailingResource resource(std::pmr::get_default_resource());
    ScopedDefaultResource scope(&resource);
    buf::MultiBuffer pending, input;
    std::array<const buf::Buffer*, buf::MultiBuffer::kInlineCapacity> original{};
    for (size_t i = 0; i < original.size(); ++i) {
        input.push_back(Buffer(buf::Buffer::kSize, static_cast<uint8_t>(i)));
        original[i] = input.back();
    }

    resource.RejectNextAllocation();
    ASSERT_NO_THROW(buf::AppendPacketStreamInput(pending, std::move(input)));
    ASSERT_EQ(pending.size(), original.size());
    EXPECT_EQ(resource.RejectedAllocations(), 0);
    EXPECT_EQ(pending.byte_size(), original.size() * buf::Buffer::kSize);
    for (size_t i = 0; i < original.size(); ++i) {
        const auto* block = *(pending.begin() + i);
        EXPECT_EQ(block, original[i]);
        const auto bytes = block->Bytes();
        EXPECT_TRUE(std::all_of(bytes.begin(), bytes.end(),
            [i](uint8_t value) { return value == static_cast<uint8_t>(i); }));
    }
    EXPECT_TRUE(Consistent(pending));
}

TEST(BufferOwnership, PacketStreamRetiresPartiallyAppendedInputOnRequiredAllocationFailure) {
    FailingResource resource(std::pmr::get_default_resource());
    ScopedDefaultResource scope(&resource);
    buf::LengthPrefixedPacketBuffer stream;
    buf::MultiBuffer input;
    for (size_t i = 0; i <= buf::MultiBuffer::kInlineCapacity; ++i)
        input.push_back(Buffer(buf::Buffer::kSize, static_cast<uint8_t>(i)));

    resource.RejectNextAllocation();
    EXPECT_THROW(stream.Append(std::move(input)), std::bad_alloc);
    EXPECT_EQ(resource.RejectedAllocations(), 1);
    EXPECT_EQ(stream.PendingBytes(), 0);
    buf::MultiBuffer output;
    EXPECT_EQ(stream.Pop(output), buf::LengthPrefixedPacketBuffer::PopResult::Invalid);
    EXPECT_TRUE(output.empty());
    EXPECT_THROW(stream.Append({}), IoSystemError);
    EXPECT_THROW(stream.Finish(), IoSystemError);
}

TEST(BufferOwnership, TruncatedPacketStreamCannotResumeAfterEof) {
    const std::array<uint8_t, 5> wire{0, 3, 0x11, 0x22, 0x33};
    for (size_t cut = 1; cut < wire.size(); ++cut) {
        SCOPED_TRACE(cut);
        buf::LengthPrefixedPacketBuffer stream;
        stream.Append(Packet(std::span(wire).first(cut)));
        buf::MultiBuffer output;
        ASSERT_EQ(stream.Pop(output), buf::LengthPrefixedPacketBuffer::PopResult::NeedMore);
        EXPECT_THROW(stream.Finish(), IoSystemError);
        EXPECT_EQ(stream.PendingBytes(), 0);
        EXPECT_THROW(stream.Append(Packet(std::span(wire).subspan(cut))), IoSystemError);
        EXPECT_EQ(stream.Pop(output), buf::LengthPrefixedPacketBuffer::PopResult::Invalid);
        EXPECT_TRUE(output.empty());
        EXPECT_THROW(stream.Finish(), IoSystemError);
        stream.Reset();
        stream.Append(Packet(wire));
        ASSERT_EQ(stream.Pop(output), buf::LengthPrefixedPacketBuffer::PopResult::Packet);
        EXPECT_EQ(Flatten(output), std::vector<uint8_t>({0x11, 0x22, 0x33}));
        stream.Finish();
    }
}

TEST(BufferOwnership, CleanPacketStreamEofRequiresExplicitResetBeforeReuse) {
    const std::array<uint8_t, 3> wire{0, 1, 0x73};
    buf::LengthPrefixedPacketBuffer stream;
    stream.Append(Packet(wire));
    buf::MultiBuffer output;
    ASSERT_EQ(stream.Pop(output), buf::LengthPrefixedPacketBuffer::PopResult::Packet);
    EXPECT_EQ(Flatten(output), std::vector<uint8_t>({0x73}));
    stream.Finish();
    stream.Finish();
    EXPECT_THROW(stream.Append({}), IoSystemError);
    EXPECT_THROW(stream.Append(Packet(wire)), IoSystemError);
    EXPECT_EQ(stream.Pop(output), buf::LengthPrefixedPacketBuffer::PopResult::Finished);
    EXPECT_TRUE(output.empty());
    stream.Reset();
    stream.Append(Packet(wire));
    ASSERT_EQ(stream.Pop(output), buf::LengthPrefixedPacketBuffer::PopResult::Packet);
    EXPECT_EQ(Flatten(output), std::vector<uint8_t>({0x73}));
    stream.Finish();
}
