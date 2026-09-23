#include "app/dns/cache_internal.hpp"
#include "acppnode/common/allocator.hpp"

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

using acpp::app::dns::DnsCache;
using acpp::app::dns::DnsResult;

DnsResult Answer(std::string_view address, size_t count = 1) {
    DnsResult result;
    result.addresses.assign(count, acpp::net::ip::make_address(address));
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
        candidate.error = acpp::ErrorCode::DNS_NO_RECORD;
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
            const auto old = cache.Get(domains[0]);
            Require(old && old->addresses.front() == old_answer.addresses.front(),
                    "failed cache insertion must retain the existing answer");
            Require(!cache.Get(domains[1]) && cache.GetStats().entries == 1,
                    "failed cache insertion must leave the index and count unchanged");
        } else {
            completed = true;
        }
        cache.Store(domains[1], new_answer);
        Require(cache.GetStats().entries == 1 && !cache.Get(domains[0]) &&
                    cache.Get(domains[1])->addresses.size() == new_answer.addresses.size(),
                "insertion after a fault must retain one indexed entry with correct ownership");
        cache.Store(domains[0], old_answer);
        Require(cache.GetStats().entries == 1 && cache.Get(domains[0]) &&
                    !cache.Get(domains[1]),
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
    Require(cache.Get("one.example") && cache.Get("two.example") &&
                cache.GetStats().entries == 2,
            "a Worker cache must make its full capacity available to arbitrary domains");
    cache.Store("three.example", answer);
    Require(!cache.Get("one.example") && cache.Get("two.example") &&
                cache.Get("three.example") && cache.GetStats().entries == 2,
            "insertion must evict the oldest write only after reaching capacity");

    DnsResult negative;
    negative.error = acpp::ErrorCode::DNS_NO_RECORD;
    negative.from_cache = true;
    negative.ttl = 1;
    cache.Store("two.example", negative);
    const auto cached_negative = cache.Get("two.example");
    Require(cached_negative && cached_negative->negative &&
                cached_negative->addresses.empty() && cached_negative->ttl == 1,
            "L2 negative answers must replace positives without extending their remaining TTL");
    auto cached_answer = answer;
    cached_answer.from_cache = true;
    cached_answer.ttl = 1;
    cache.Store("two.example", cached_answer);
    Require(!cache.Get("two.example")->negative && cache.Get("two.example")->ttl == 1,
            "L2 positive answers must also retain their remaining TTL");

    DnsResult temporary_failure;
    temporary_failure.error = acpp::ErrorCode::DNS_RESOLVE_FAILED;
    cache.Store("two.example", temporary_failure);
    Require(cache.Get("two.example").has_value(),
            "temporary failures must not replace valid cached data");
    cached_answer.ttl = 0;
    cache.Store("two.example", cached_answer);
    Require(!cache.Get("two.example") && cache.GetStats().entries == 1,
            "expired entries must be removed from both ownership and statistics");

    DnsCache disabled(0, 10, 600);
    disabled.Store("one.example", answer);
    Require(!disabled.Get("one.example") && disabled.GetStats().entries == 0,
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
    Require(failed && cache.Get("same.example")->addresses.front() == original.addresses.front(),
            "failed replacement must retain the complete old answer");
}

}  // namespace

int main() {
    acpp::memory::ConfigureProcessAllocator();
    FailingResource resource(std::pmr::get_default_resource());
    auto* original = std::pmr::set_default_resource(&resource);
    bool passed = true;
    try {
        TestFailedInsertion(false);
        TestFailedInsertion(true);
        TestFailedReplacement();
        TestCapacityAndResults();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        passed = false;
    }
    std::pmr::set_default_resource(original);
    return passed ? 0 : 1;
}
