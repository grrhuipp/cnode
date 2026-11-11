#include <gtest/gtest.h>

#include "app/dns/dns_internal.hpp"
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
    [[nodiscard]] size_t Live() const noexcept { return live_; }
    ~FailingResource() override { EXPECT_EQ(live_, 0u); }
private:
    void* do_allocate(size_t size, size_t alignment) override {
        if (fail_after >= 0 && fail_after-- == 0) throw std::bad_alloc();
        void* pointer = upstream_->allocate(size, alignment);
        ++live_;
        return pointer;
    }
    void do_deallocate(void* pointer, size_t size, size_t alignment) override {
        --live_;
        upstream_->deallocate(pointer, size, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
    std::pmr::memory_resource* upstream_;
    size_t live_ = 0;
};

class FailAllocation {
public:
    explicit FailAllocation(int after) noexcept { fail_after = after; }
    ~FailAllocation() { fail_after = -1; }
};


using ::app::dns::DnsCache;
using ::app::dns::DnsResult;

DnsResult Answer(std::string_view address, size_t count = 1) {
    DnsResult result;
    result.addresses.assign(count, ::net::ip::make_address(address));
    result.ttl = 60;
    return result;
}

class DnsCacheInsertion : public testing::TestWithParam<bool> {};
TEST_P(DnsCacheInsertion, FailedInsertionRetainsIndexedAnswerAndAllowsLaterEviction) {
    FailingResource storage(::memory::process_resource());
    auto* resource = &storage;
    const bool negative = GetParam();
    const std::array domains{std::string("cached.example"), std::string(60, 'a') + ".example"};
    const auto old_answer = Answer("192.0.2.1");
    const auto new_answer = Answer("192.0.2.2", 400);
    auto candidate = new_answer;
    if (negative) {
        candidate.addresses.clear();
        candidate.error = ::common::ErrorCode::DNS_NO_RECORD;
    }
    int failures = 0;
    bool completed = false;
    for (int allocation = 0; allocation < 20; ++allocation) {
        DnsCache cache(1, 10, 600, nullptr, resource);
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
            ASSERT_TRUE(old);
            EXPECT_EQ(old->addresses.front(), old_answer.addresses.front());
            EXPECT_FALSE(cache.GetResult(domains[1]));
            EXPECT_EQ(cache.GetStats().entries, 1u);
        } else {
            completed = true;
        }
        cache.Store(domains[1], new_answer);
        EXPECT_EQ(cache.GetStats().entries, 1u);
        EXPECT_FALSE(cache.GetResult(domains[0]));
        const auto inserted = cache.GetResult(domains[1]);
        ASSERT_TRUE(inserted);
        EXPECT_EQ(inserted->addresses.size(), new_answer.addresses.size());
        cache.Store(domains[0], old_answer);
        EXPECT_EQ(cache.GetStats().entries, 1u);
        EXPECT_TRUE(cache.GetResult(domains[0]));
        EXPECT_FALSE(cache.GetResult(domains[1]));
        if (completed) break;
    }
    EXPECT_GT(failures, 0);
    EXPECT_TRUE(completed);
}

INSTANTIATE_TEST_SUITE_P(AnswerKind, DnsCacheInsertion, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "Negative" : "Positive";
    });

TEST(DnsCache, CapacityEvictsOldestWrite) {
    FailingResource storage(::memory::process_resource());
    auto* resource = &storage;
    DnsCache cache(2, 10, 600, nullptr, resource);
    const auto answer = Answer("192.0.2.3");
    cache.Store("one.example", answer);
    cache.Store("two.example", answer);
    EXPECT_TRUE(cache.GetResult("one.example"));
    EXPECT_TRUE(cache.GetResult("two.example"));
    EXPECT_EQ(cache.GetStats().entries, 2u);
    cache.Store("three.example", answer);
    EXPECT_FALSE(cache.GetResult("one.example"));
    EXPECT_TRUE(cache.GetResult("two.example"));
    EXPECT_TRUE(cache.GetResult("three.example"));
    EXPECT_EQ(cache.GetStats().entries, 2u);
}

TEST(DnsCache, PositiveAndNegativeReplacementClampTtlAndIgnoreTemporaryFailure) {
    DnsCache cache(2, 10, 600);
    const auto answer = Answer("192.0.2.3");
    cache.Store("two.example", answer);

    DnsResult negative;
    negative.error = ::common::ErrorCode::DNS_NO_RECORD;
    negative.ttl = 1;
    cache.Store("two.example", negative);
    const auto cached_negative = cache.GetResult("two.example");
    ASSERT_TRUE(cached_negative);
    EXPECT_EQ(cached_negative->error, ::common::ErrorCode::DNS_NO_RECORD);
    EXPECT_TRUE(cached_negative->addresses.empty());
    EXPECT_LE(cached_negative->ttl, 10u);
    auto cached_answer = answer;
    cached_answer.ttl = 1;
    cache.Store("two.example", cached_answer);
    const auto positive = cache.GetResult("two.example");
    ASSERT_TRUE(positive);
    EXPECT_TRUE(positive->Ok());
    EXPECT_LE(positive->ttl, 10u);

    DnsResult temporary_failure;
    temporary_failure.error = ::common::ErrorCode::DNS_RESOLVE_FAILED;
    cache.Store("two.example", temporary_failure);
    EXPECT_TRUE(cache.GetResult("two.example"));
}

TEST(DnsCache, ZeroCapacityAndExpiredAnswersRetainNoEntries) {
    const auto answer = Answer("192.0.2.3");
    auto cached_answer = answer;
    DnsCache expired(1, 0, 600);
    cached_answer.ttl = 0;
    expired.Store("two.example", cached_answer);
    EXPECT_FALSE(expired.GetResult("two.example"));
    EXPECT_EQ(expired.GetStats().entries, 0u);

    DnsCache disabled(0, 10, 600);
    disabled.Store("one.example", answer);
    EXPECT_FALSE(disabled.GetResult("one.example"));
    EXPECT_EQ(disabled.GetStats().entries, 0u);
}

TEST(DnsCache, FailedReplacementRetainsCompleteOldAnswer) {
    FailingResource storage(::memory::process_resource());
    auto* resource = &storage;
    DnsCache cache(1, 10, 600, nullptr, resource);
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
    EXPECT_TRUE(failed);
    const auto retained = cache.GetResult("same.example");
    ASSERT_TRUE(retained);
    EXPECT_EQ(retained->addresses, original.addresses);
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

TEST(DnsCache, NegativeDiagnosticsSummarizeRecoveryExpiryEvictionAndShutdown) {
    FailingResource storage(::memory::process_resource());
    auto* resource = &storage;
    negative_events.clear();
    struct ClearEvents {
        ~ClearEvents() { negative_events.clear(); }
    } clear_events;
    DnsResult negative;
    negative.error = ::common::ErrorCode::DNS_NO_RECORD;
    negative.error_msg = "NXDOMAIN";
    negative.ttl = 60;
    {
        DnsCache cache(1, 0, 600, RecordNegativeEvent, resource);
        cache.Store("negative.example", negative);
        for (size_t i = 0; i < 128; ++i) {
            const auto result = cache.GetResult("negative.example");
            ASSERT_TRUE(result);
            EXPECT_EQ(result->error_msg, "NXDOMAIN");
        }
        EXPECT_TRUE(negative_events.empty());
        cache.Store("negative.example", Answer("192.0.2.1"));
        ASSERT_EQ(negative_events.size(), 1u);
        EXPECT_EQ(negative_events[0].event, "recovered");
        EXPECT_EQ(negative_events[0].hits, 128u);
        EXPECT_EQ(negative_events[0].reason, "NXDOMAIN");

        negative.error_msg = "NODATA";
        negative.ttl = 0;
        cache.Store("expired.example", negative);
        EXPECT_FALSE(cache.GetResult("expired.example"));
        EXPECT_EQ(cache.GetStats().entries, 0u);
        ASSERT_EQ(negative_events.size(), 2u);
        EXPECT_EQ(negative_events.back().event, "expired");
        EXPECT_FALSE(cache.GetResult("expired.example"));
        EXPECT_EQ(negative_events.size(), 2u);
        cache.Store("expired.example", Answer("192.0.2.2"));
        ASSERT_EQ(negative_events.size(), 3u);
        EXPECT_EQ(negative_events.back().event, "recovered");
        EXPECT_EQ(negative_events.back().reason, "NODATA");

        negative.ttl = 60;
        cache.Store("evicted.example", negative);
        (void)cache.GetResult("evicted.example");
        cache.Store("shutdown.example", negative);
        ASSERT_EQ(negative_events.size(), 4u);
        EXPECT_EQ(negative_events.back().event, "evicted");
        EXPECT_EQ(negative_events.back().hits, 1u);
        EXPECT_EQ(cache.GetStats().entries, 1u);
    }
    ASSERT_EQ(negative_events.size(), 5u);
    EXPECT_EQ(negative_events.back().event, "shutdown");
    negative_events.clear();
}

}  // namespace


TEST(DnsCache, ZeroTtlAddressesInvalidateOldAnswersAndReleaseTheirStorage) {
    FailingResource resource(::memory::process_resource());
    {
        DnsCache cache(2, 60, 3600, nullptr, &resource);
        cache.Store("ttl.example", Answer("192.0.2.1", 400));
        auto current = Answer("192.0.2.2");
        current.ttl = 0;
        cache.Store("ttl.example", current);
        EXPECT_FALSE(cache.GetResult("ttl.example"));
        EXPECT_EQ(cache.GetStats().entries, 0);
        cache.Store("uncached.example", current);
        EXPECT_FALSE(cache.GetResult("uncached.example"));
        EXPECT_EQ(cache.GetStats().entries, 0);

        DnsResult negative;
        negative.error = common::ErrorCode::DNS_NO_RECORD;
        negative.error_msg = "NODATA";
        negative.ttl = 0;
        cache.Store("ttl.example", negative);
        EXPECT_FALSE(cache.GetResult("ttl.example"));
        cache.Store("ttl.example", current);
        EXPECT_FALSE(cache.GetResult("ttl.example"));
        EXPECT_EQ(cache.GetStats().entries, 0);

        const auto retained = Answer("192.0.2.3");
        cache.Store("ttl.example", retained);
        const auto cached = cache.GetResult("ttl.example");
        ASSERT_TRUE(cached);
        EXPECT_EQ(cached->addresses, retained.addresses);
    }
    EXPECT_EQ(resource.Live(), 0u);
}
