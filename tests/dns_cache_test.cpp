#include <gtest/gtest.h>

#include "app/dns/cache_internal.hpp"
#include "common/allocator.hpp"

#include <array>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

thread_local int fail_after = -1;

class FailingResource final : public std::pmr::memory_resource {
public:
    explicit FailingResource(std::pmr::memory_resource* upstream) : upstream_(upstream) {}
private:
    void* do_allocate(size_t size, size_t alignment) override {
        if (fail_after >= 0 && fail_after-- == 0) throw std::bad_alloc();
        return upstream_->allocate(size, alignment);
    }
    void do_deallocate(void* pointer, size_t size, size_t alignment) override {
        upstream_->deallocate(pointer, size, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
    std::pmr::memory_resource* upstream_;
};

class FailAllocation {
public:
    explicit FailAllocation(int after) noexcept { fail_after = after; }
    ~FailAllocation() { fail_after = -1; }
};

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

using ::app::dns::DnsCache;
using ::app::dns::DnsResult;

DnsResult Answer(std::string_view address, size_t count = 1) {
    DnsResult result;
    result.addresses.assign(count, ::net::ip::make_address(address));
    result.ttl = 60;
    return result;
}

void TestFailedInsertion(bool negative) {
    const std::array domains{std::string("cached.example"), std::string(60, 'a') + ".example"};
    const auto old_answer = Answer("192.0.2.1");
    const auto new_answer = Answer("192.0.2.2", 400);
    auto candidate = new_answer;
    if (negative) {
        candidate.addresses.clear();
        candidate.error = ::ErrorCode::DNS_NO_RECORD;
    }
    int failures = 0;
    bool completed = false;
    for (int allocation = 0; allocation < 20; ++allocation) {
        DnsCache cache(1, 10, 600);
        cache.Store(domains[0], old_answer);
        bool rejected = false;
        {
            FailAllocation fault(allocation);
            try {
                cache.Store(domains[1], candidate);
            } catch (const std::bad_alloc&) {
                rejected = true;
            }
        }
        if (rejected) {
            ++failures;
            const auto old = cache.GetResult(domains[0]);
            Require(old && old->addresses.front() == old_answer.addresses.front(),
                    "failed cache insertion must retain the existing answer");
            Require(!cache.GetResult(domains[1]) && cache.GetStats().entries == 1,
                    "failed cache insertion must leave the index and count unchanged");
        } else {
            completed = true;
        }
        cache.Store(domains[1], new_answer);
        Require(cache.GetStats().entries == 1 && !cache.GetResult(domains[0]) &&
                    cache.GetResult(domains[1])->addresses.size() == new_answer.addresses.size(),
                "insertion after a fault must retain one indexed entry with correct ownership");
        cache.Store(domains[0], old_answer);
        Require(cache.GetStats().entries == 1 && cache.GetResult(domains[0]) &&
                    !cache.GetResult(domains[1]),
                "later eviction must not encounter an orphaned cache node");
        if (completed) break;
    }
    Require(failures > 0 && completed, "allocation sweep must cover failures and success");
}

void TestCapacityAndResults() {
    DnsCache cache(2, 10, 600);
    const auto answer = Answer("192.0.2.3");
    cache.Store("one.example", answer);
    cache.Store("two.example", answer);
    Require(cache.GetResult("one.example") && cache.GetResult("two.example") &&
                cache.GetStats().entries == 2,
            "a Worker cache must make its full capacity available to arbitrary domains");
    cache.Store("three.example", answer);
    Require(!cache.GetResult("one.example") && cache.GetResult("two.example") &&
                cache.GetResult("three.example") && cache.GetStats().entries == 2,
            "insertion must evict the oldest write only after reaching capacity");

    DnsResult negative;
    negative.error = ::ErrorCode::DNS_NO_RECORD;
    negative.ttl = 1;
    cache.Store("two.example", negative);
    const auto cached_negative = cache.GetResult("two.example");
    Require(cached_negative && cached_negative->error == ::ErrorCode::DNS_NO_RECORD &&
                cached_negative->addresses.empty() && cached_negative->ttl <= 10,
            "negative answers must replace positives and clamp the TTL");
    auto cached_answer = answer;
    cached_answer.ttl = 1;
    cache.Store("two.example", cached_answer);
    Require(cache.GetResult("two.example")->Ok() && cache.GetResult("two.example")->ttl <= 10,
            "positive answers must replace negatives and clamp the TTL");

    DnsResult temporary_failure;
    temporary_failure.error = ::ErrorCode::DNS_RESOLVE_FAILED;
    cache.Store("two.example", temporary_failure);
    Require(cache.GetResult("two.example").has_value(),
            "temporary failures must not replace valid cached data");
    DnsCache expired(1, 0, 600);
    cached_answer.ttl = 0;
    expired.Store("two.example", cached_answer);
    Require(!expired.GetResult("two.example") && expired.GetStats().entries == 0,
            "expired entries must be removed from both ownership and statistics");

    DnsCache disabled(0, 10, 600);
    disabled.Store("one.example", answer);
    Require(!disabled.GetResult("one.example") && disabled.GetStats().entries == 0,
            "disabled caches must retain no entries");
}

void TestFailedReplacement() {
    DnsCache cache(1, 10, 600);
    const auto original = Answer("192.0.2.1");
    const auto replacement = Answer("192.0.2.2", 400);
    cache.Store("same.example", original);
    bool failed = false;
    {
        FailAllocation fault(0);
        try {
            cache.Store("same.example", replacement);
        } catch (const std::bad_alloc&) {
            failed = true;
        }
    }
    Require(failed && cache.GetResult("same.example")->addresses.front() == original.addresses.front(),
            "failed replacement must retain the complete old answer");
}

struct NegativeEvent {
    std::string domain, reason, event;
    uint64_t hits;
};
std::vector<NegativeEvent> negative_events;

void RecordNegativeEvent(std::string_view domain, std::string_view reason,
                         uint64_t hits, std::string_view event) {
    negative_events.push_back({std::string(domain), std::string(reason), std::string(event), hits});
}

void TestNegativeEventLifecycle() {
    negative_events.clear();
    DnsResult negative;
    negative.error = ::ErrorCode::DNS_NO_RECORD;
    negative.error_msg = "NXDOMAIN";
    negative.ttl = 60;
    {
        DnsCache cache(1, 0, 600, RecordNegativeEvent);
        cache.Store("negative.example", negative);
        for (size_t i = 0; i < 128; ++i) {
            const auto result = cache.GetResult("negative.example");
            Require(result && result->error_msg == "NXDOMAIN",
                    "every suppressed hit must retain the original negative reason");
        }
        Require(negative_events.empty(), "repeated cache hits must not emit repeated diagnostics");
        cache.Store("negative.example", Answer("192.0.2.1"));
        Require(negative_events.size() == 1 && negative_events[0].event == "recovered" &&
                    negative_events[0].hits == 128 && negative_events[0].reason == "NXDOMAIN",
                "recovery must publish the exact suppressed hit count and initial reason");

        negative.error_msg = "NODATA";
        negative.ttl = 0;
        cache.Store("expired.example", negative);
        Require(!cache.GetResult("expired.example") && cache.GetStats().entries == 0,
                "expired negatives must not be served or counted as live cache entries");
        Require(negative_events.size() == 2 && negative_events.back().event == "expired",
                "expiry must publish one summary");
        Require(!cache.GetResult("expired.example") && negative_events.size() == 2,
                "repeated expired lookups must not repeat expiry diagnostics");
        cache.Store("expired.example", Answer("192.0.2.2"));
        Require(negative_events.size() == 3 && negative_events.back().event == "recovered" &&
                    negative_events.back().reason == "NODATA",
                "successful refresh after expiry must retain the old negative reason");

        negative.ttl = 60;
        cache.Store("evicted.example", negative);
        (void)cache.GetResult("evicted.example");
        cache.Store("shutdown.example", negative);
        Require(negative_events.size() == 4 && negative_events.back().event == "evicted" &&
                    negative_events.back().hits == 1 && cache.GetStats().entries == 1,
                "eviction must summarize counts and keep metadata inside the cache capacity");
    }
    Require(negative_events.size() == 5 && negative_events.back().event == "shutdown",
            "shutdown must summarize remaining live negative entries");
    negative_events.clear();
}

}  // namespace

TEST(DnsCache, Contract) {
    ::memory::ConfigureProcessAllocator();
    FailingResource resource(std::pmr::get_default_resource());
    auto* original = std::pmr::set_default_resource(&resource);
    bool passed = true;
    try {
        TestFailedInsertion(false);
        TestFailedInsertion(true);
        TestFailedReplacement();
        TestCapacityAndResults();
        TestNegativeEventLifecycle();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        passed = false;
    }
    std::pmr::set_default_resource(original);
    { ASSERT_TRUE(passed); return; }
}

TEST(DnsCache, ZeroTtlAddressesInvalidateOldAnswersAndReleaseTheirStorage) {
    ::memory::ConfigureProcessAllocator();
    ::memory::AllocationDomain domain;
    ::memory::ScopedAllocationDomain lease(domain);
    {
        DnsCache cache(2, 60, 3600);
        const auto empty_allocations = domain.OutstandingAllocations();
        cache.Store("ttl.example", Answer("192.0.2.1", 400));
        auto current = Answer("192.0.2.2");
        current.ttl = 0;
        cache.Store("ttl.example", current);
        EXPECT_FALSE(cache.GetResult("ttl.example"));
        EXPECT_EQ(cache.GetStats().entries, 0);
        EXPECT_EQ(domain.OutstandingAllocations(), empty_allocations);

        cache.Store("uncached.example", current);
        EXPECT_FALSE(cache.GetResult("uncached.example"));
        EXPECT_EQ(cache.GetStats().entries, 0);
        EXPECT_EQ(domain.OutstandingAllocations(), empty_allocations);

        DnsResult negative;
        negative.error = ErrorCode::DNS_NO_RECORD;
        negative.error_msg = "NODATA";
        negative.ttl = 0;
        cache.Store("ttl.example", negative);
        EXPECT_FALSE(cache.GetResult("ttl.example"));
        cache.Store("ttl.example", current);
        EXPECT_FALSE(cache.GetResult("ttl.example"));
        EXPECT_EQ(cache.GetStats().entries, 0);
        EXPECT_EQ(domain.OutstandingAllocations(), empty_allocations);

        const auto retained = Answer("192.0.2.3");
        cache.Store("ttl.example", retained);
        const auto cached = cache.GetResult("ttl.example");
        ASSERT_TRUE(cached);
        EXPECT_EQ(cached->addresses, retained.addresses);
    }
    EXPECT_EQ(domain.OutstandingAllocations(), 0);
}
