#include "acppnode/app/router/router.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/runtime_config_types.hpp"

#include <concepts>
#include <cstddef>
#include <iostream>
#include <memory>
#include <memory_resource>
#include <regex>
#include <stdexcept>

namespace {

using acpp::app::router::Router;
static_assert(std::derived_from<Router, acpp::routing::Router>);
static_assert(!std::default_initializable<Router>);
static_assert(!std::movable<Router>);

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename Exception, typename Function>
void RequireThrows(Function&& function, const char* message) {
    try {
        function();
    } catch (const Exception&) {
        return;
    }
    throw std::runtime_error(message);
}

void TestRulesAndOwnership() {
    acpp::RoutingConfig config;
    config.domain_strategy = acpp::routing::DomainStrategy::IPIfNonMatch;
    acpp::RouteRuleConfig domain;
    domain.domain_suffix = {"example.com"};
    domain.network = {"tcp"};
    domain.outbound_tag = "domain-proxy";
    acpp::RouteRuleConfig network;
    network.ip = {*acpp::RoutingIpNetwork::Parse("192.0.2.0/24"),
                  *acpp::RoutingIpNetwork::Parse("2001:db8::/32")};
    network.outbound_tag = "ip-proxy";
    config.rules = {domain, network};

    auto router = std::make_unique<Router>(config, nullptr);
    const acpp::routing::Router& query = *router;
    Require(query.DomainStrategy() == acpp::routing::DomainStrategy::IPIfNonMatch,
            "domain strategy must be available through the feature contract");

    acpp::session::Context ctx;
    ctx.content.network = acpp::Network::TCP;
    ctx.outbound.target = acpp::TargetAddress("WWW.EXAMPLE.COM.", 443);
    ctx.outbound.target.resolved_addr = acpp::net::ip::make_address("192.0.2.1");
    const auto domain_match = query.Route(ctx);
    Require(domain_match.matched && domain_match.outbound_tag == "domain-proxy" &&
                domain_match.rule_index == 0,
            "the first matching rule must win over a later IP match");

    ctx.content.network = acpp::Network::UDP;
    auto match = query.Route(ctx);
    Require(match.matched && match.outbound_tag == "ip-proxy" && match.rule_index == 1,
            "UDP must skip a TCP-only rule and retain the actual rule index");
    ctx.outbound.target = acpp::TargetAddress("2001:db8::7", 53);
    Require(query.Route(ctx).outbound_tag == "ip-proxy", "IPv6 routing must match");

    ctx.outbound.target = acpp::TargetAddress("notexample.com", 443);
    ctx.content.network = acpp::Network::TCP;
    match = query.Route(ctx);
    Require(!match.matched && match.outbound_tag.empty(),
            "a suffix boundary miss must return no decision, with no fallback");

    config.rules[0].outbound_tag = "replacement";
    config.domain_strategy = acpp::routing::DomainStrategy::AsIs;
    const Router replacement(config, nullptr);
    config.rules.clear();
    ctx.outbound.target = acpp::TargetAddress("example.com", 443);
    Require(query.Route(ctx).outbound_tag == "domain-proxy" &&
                domain_match.outbound_tag == "domain-proxy" &&
                replacement.Route(ctx).outbound_tag == "replacement" &&
                query.DomainStrategy() == acpp::routing::DomainStrategy::IPIfNonMatch,
            "routers and borrowed decisions must own independent immutable rule data");
}

class CountingPmrResource final : public std::pmr::memory_resource {
public:
    explicit CountingPmrResource(std::pmr::memory_resource& upstream) noexcept
        : upstream_(upstream) {}

    size_t OutstandingAllocations() const noexcept { return outstanding_allocations_; }
    size_t OutstandingBytes() const noexcept { return outstanding_bytes_; }
    size_t TotalAllocations() const noexcept { return total_allocations_; }

private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        void* allocation = upstream_.allocate(bytes, alignment);
        ++outstanding_allocations_;
        outstanding_bytes_ += bytes;
        ++total_allocations_;
        return allocation;
    }

    void do_deallocate(void* allocation, size_t bytes, size_t alignment) override {
        --outstanding_allocations_;
        outstanding_bytes_ -= bytes;
        upstream_.deallocate(allocation, bytes, alignment);
    }

    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }

    std::pmr::memory_resource& upstream_;
    size_t outstanding_allocations_ = 0;
    size_t outstanding_bytes_ = 0;
    size_t total_allocations_ = 0;
};

class ScopedDefaultResource final {
public:
    explicit ScopedDefaultResource(std::pmr::memory_resource& resource) noexcept
        : previous_(std::pmr::set_default_resource(&resource)) {}
    ~ScopedDefaultResource() { std::pmr::set_default_resource(previous_); }

    ScopedDefaultResource(const ScopedDefaultResource&) = delete;
    ScopedDefaultResource& operator=(const ScopedDefaultResource&) = delete;

private:
    std::pmr::memory_resource* previous_;
};

void TestInboundMetadataOwnershipAndRouting() {
    using acpp::session::Context;
    {
        acpp::memory::ThreadPoolFacade worker_pool;
        CountingPmrResource counted_worker_pool(worker_pool);
        {
            ScopedDefaultResource use_counted_worker_pool(counted_worker_pool);
            const size_t baseline_allocations = counted_worker_pool.OutstandingAllocations();
            const size_t baseline_bytes = counted_worker_pool.OutstandingBytes();
            {
                Context ctx;
                Context copy;
                {
                    acpp::proxyman::inbound::ReceiverSettings receiver{
                        .dispatch_policy = {.outbound = acpp::routing::ForceOutbound{"metadata-test"}}};
                    receiver.inbound_tag = std::string(96, 'm');
                    receiver.inbound_tags = {receiver.inbound_tag, std::string(112, 'x')};
                    receiver.protocol = std::string(104, 'p');
                    receiver.stream_settings.security = std::string(108, 's');
                    ctx.inbound.tag = receiver.inbound_tag;
                    ctx.inbound.protocol = receiver.protocol;
                    ctx.inbound.security = receiver.stream_settings.security;
                    for (const auto& tag : receiver.inbound_tags) {
                        ctx.inbound.tags.emplace_back(tag);
                    }
                    copy.inbound = ctx.inbound;
                }

                Require(ctx.inbound.tag.size() == 96 && ctx.inbound.protocol.size() == 104 &&
                            ctx.inbound.security.size() == 108 && ctx.inbound.tags.size() == 2 &&
                            ctx.inbound.tags[1].size() == 112,
                        "inbound metadata must outlive its cold receiver source");
                Require(counted_worker_pool.TotalAllocations() > 0 &&
                            counted_worker_pool.OutstandingAllocations() > baseline_allocations &&
                            counted_worker_pool.OutstandingBytes() > baseline_bytes,
                        "long inbound metadata and its copy must allocate through Worker PMR");
                Require(ctx.inbound.tag.get_allocator().resource() == &counted_worker_pool &&
                            ctx.inbound.protocol.get_allocator().resource() == &counted_worker_pool &&
                            ctx.inbound.security.get_allocator().resource() == &counted_worker_pool &&
                            ctx.inbound.tags.get_allocator().resource() == &counted_worker_pool &&
                            ctx.inbound.tags[0].get_allocator().resource() == &counted_worker_pool &&
                            copy.inbound.tag.get_allocator().resource() == &counted_worker_pool &&
                            copy.inbound.tags[0].get_allocator().resource() == &counted_worker_pool,
                        "inbound metadata and Context copies must use the Worker PMR resource");
                ctx.inbound.tag[0] = 'c';
                ctx.inbound.tags[1][0] = 'y';
                Require(copy.inbound.tag[0] == 'm' && copy.inbound.tags[1][0] == 'x',
                        "copied inbound metadata must be independent owned values");
            }
            Require(counted_worker_pool.OutstandingAllocations() == baseline_allocations &&
                        counted_worker_pool.OutstandingBytes() == baseline_bytes,
                    "destroying metadata Contexts must release their Worker PMR allocations");
        }
    }

    acpp::RoutingConfig config;
    acpp::RouteRuleConfig main_tag;
    main_tag.inbound_tag = {std::string(96, 'm')};
    main_tag.domain_full = {"main.example"};
    main_tag.outbound_tag = "main-out";
    acpp::RouteRuleConfig extra_tag;
    extra_tag.inbound_tag = {std::string(112, 'x')};
    extra_tag.domain_full = {"extra.example"};
    extra_tag.outbound_tag = "extra-out";
    config.rules = {main_tag, extra_tag};
    const Router router(config, nullptr);

    Context routed;
    routed.inbound.tag = std::string(96, 'm');
    routed.inbound.tags.emplace_back(std::string(112, 'x'));
    routed.outbound.target = acpp::TargetAddress("main.example", 443);
    Require(router.Route(routed).outbound_tag == "main-out",
            "primary inbound tag must match its rule");
    routed.outbound.target = acpp::TargetAddress("extra.example", 443);
    Require(router.Route(routed).outbound_tag == "extra-out",
            "non-empty extra tags must participate in routing");
    routed.inbound.tags.clear();
    Require(!router.Route(routed).matched,
            "empty extra tags must mean no additional inbound tags");
}

void TestInvalidConstruction() {
    acpp::RoutingConfig config;
    acpp::RouteRuleConfig valid;
    valid.domain_full = {"example.com"};
    valid.outbound_tag = "direct";
    config.rules.push_back(valid);
    acpp::RouteRuleConfig invalid = valid;
    invalid.domain_regex = {"["};
    config.rules.push_back(invalid);
    RequireThrows<std::regex_error>([&] { Router router(config, nullptr); },
                                   "invalid regex must fail construction");
    config.rules.back() = {};
    config.rules.back().outbound_tag = "direct";
    RequireThrows<std::logic_error>([&] { Router router(config, nullptr); },
                                   "unconditional rule must fail construction");
    config.rules.back() = valid;
    config.rules.back().outbound_tag.clear();
    RequireThrows<std::logic_error>([&] { Router router(config, nullptr); },
                                   "empty outbound tag must fail construction");
    config.rules.back() = valid;
    config.rules.back().geosite = {"cn"};
    RequireThrows<std::logic_error>([&] { Router router(config, nullptr); },
                                   "unresolved geo rules must fail construction");

    const Router empty(acpp::RoutingConfig{}, nullptr);
    Require(!empty.Route(acpp::session::Context{}).matched,
            "an empty router must have no implicit default");
}

}  // namespace

int main() {
    try {
        TestRulesAndOwnership();
        TestInboundMetadataOwnershipAndRouting();
        TestInvalidConstruction();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
