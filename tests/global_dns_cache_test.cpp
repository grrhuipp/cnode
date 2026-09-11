#include "app/dns/global_cache.hpp"

#include <array>
#include <atomic>
#include <barrier>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using acpp::app::dns::DnsResult;
using acpp::app::dns::GlobalDnsCache;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

DnsResult Answer(std::string_view address) {
    DnsResult result;
    result.addresses.push_back(acpp::net::ip::make_address(address));
    result.ttl = 300;
    return result;
}

void TestResultSemantics() {
    GlobalDnsCache::Configure(32, 10, 60);
    auto original = Answer("192.0.2.1");
    GlobalDnsCache::PublishResult("EXAMPLE.COM.", original);
    original.addresses.clear();
    auto cached = GlobalDnsCache::Lookup("example.com");
    Require(cached && cached->Ok() && cached->from_cache &&
                cached->addresses.front() == acpp::net::ip::make_address("192.0.2.1") &&
                cached->ttl > 0 && cached->ttl <= 60,
            "cache must canonicalize domains, clamp TTL and own its answer");
    cached->addresses.front() = acpp::net::ip::make_address("192.0.2.99");
    GlobalDnsCache::PublishResult("example.com", *cached);
    auto saved = GlobalDnsCache::Lookup("example.com");
    Require(saved && saved->addresses.front() == acpp::net::ip::make_address("192.0.2.1"),
            "lookup copies and cached answers must not mutate or refresh the snapshot");

    auto replacement = Answer("2001:db8::2");
    GlobalDnsCache::PublishResult("example.com", replacement);
    Require(saved->addresses.front() == acpp::net::ip::make_address("192.0.2.1") &&
                GlobalDnsCache::Lookup("example.com")->addresses == replacement.addresses,
            "publishing a replacement must preserve already returned answers");

    DnsResult negative;
    negative.error = acpp::ErrorCode::DNS_NO_RECORD;
    negative.error_msg = "no records";
    negative.ttl = 20;
    GlobalDnsCache::PublishResult("example.com", negative);
    auto no_record = GlobalDnsCache::Lookup("EXAMPLE.COM.");
    Require(no_record && !no_record->Ok() && no_record->from_cache &&
                no_record->error == acpp::ErrorCode::DNS_NO_RECORD &&
                no_record->error_msg == "no records" && no_record->addresses.empty(),
            "a cacheable negative answer must replace the previous positive answer");

    DnsResult transient_failure;
    transient_failure.error = acpp::ErrorCode::DNS_RESOLVE_FAILED;
    GlobalDnsCache::PublishResult("example.com", transient_failure);
    GlobalDnsCache::PublishResult("empty.example", DnsResult{});
    GlobalDnsCache::PublishResult(".", replacement);
    Require(GlobalDnsCache::Lookup("example.com")->error == acpp::ErrorCode::DNS_NO_RECORD &&
                !GlobalDnsCache::Lookup("empty.example") &&
                !GlobalDnsCache::Lookup("."),
            "transient failures, empty answers and empty canonical names must not be cached");
    GlobalDnsCache::Configure(32, 10, 60);
    Require(GlobalDnsCache::Lookup("example.com").has_value(),
            "repeated Worker initialization with identical settings must retain results");
}

void TestBounds() {
    const auto result = Answer("192.0.2.8");
    GlobalDnsCache::Configure(3, 10, 60);
    for (int i = 0; i < 100; ++i) {
        GlobalDnsCache::PublishResult("capacity-" + std::to_string(i) + ".example", result);
    }
    auto stats = GlobalDnsCache::GetStats();
    Require(stats.capacity == 3 && stats.entries <= 3,
            "small capacities must bound the entire process cache");
    GlobalDnsCache::Configure(16, 0, 0);
    GlobalDnsCache::PublishResult("expired.example", result);
    Require(!GlobalDnsCache::Lookup("expired.example"),
            "an expired result must never be returned");
    GlobalDnsCache::Configure(0, 10, 60);
    GlobalDnsCache::PublishResult("disabled.example", result);
    Require(!GlobalDnsCache::Lookup("disabled.example") &&
                GlobalDnsCache::GetStats().entries == 0,
            "disabled caching must retain no entries");
}

void TestConcurrentSnapshots() {
    GlobalDnsCache::Configure(4096, 60, 600);
    std::array<std::string, 4> domains;
    size_t found = 0;
    // Deliberately collide in one shard to exercise competing snapshot writers.
    for (size_t i = 0; found < domains.size(); ++i) {
        auto domain = "concurrent-" + std::to_string(i) + ".example";
        if (std::hash<std::string_view>{}(domain) % 256 == 0) {
            domains[found++] = std::move(domain);
        }
    }
    std::array<DnsResult, 4> results;
    for (size_t i = 0; i < results.size(); ++i) {
        results[i] = Answer("192.0.2." + std::to_string(i + 1));
    }
    std::barrier start(static_cast<std::ptrdiff_t>(domains.size() + 1));
    std::atomic<bool> failed{false};
    std::vector<std::jthread> writers;
    for (size_t i = 0; i < domains.size(); ++i) {
        writers.emplace_back([&, i] {
            start.arrive_and_wait();
            try {
                for (int iteration = 0; iteration < 200; ++iteration) {
                    GlobalDnsCache::PublishResult(domains[i], results[i]);
                }
            } catch (...) {
                failed = true;
            }
        });
    }
    start.arrive_and_wait();
    for (int iteration = 0; iteration < 200; ++iteration) {
        for (size_t i = 0; i < domains.size(); ++i) {
            const auto result = GlobalDnsCache::Lookup(domains[i]);
            if (result && (!result->Ok() || result->addresses != results[i].addresses)) {
                failed = true;
            }
        }
    }
    writers.clear();
    Require(!failed, "concurrent readers must only see complete answers");
    for (size_t i = 0; i < domains.size(); ++i) {
        auto result = GlobalDnsCache::Lookup(domains[i]);
        Require(result && result->addresses == results[i].addresses,
                "competing snapshot publications must not lose another domain's result");
    }
}

}  // namespace

int main() {
    try {
        TestResultSemantics();
        TestBounds();
        TestConcurrentSnapshots();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
