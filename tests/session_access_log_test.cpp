#include <gtest/gtest.h>

#include "common/session.hpp"

#include <asio/ip/address.hpp>

#include <cstdlib>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
thread_local bool count_allocations = false;
thread_local size_t allocations = 0;

void Expect(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

bool Has(std::string_view text, std::string_view field) {
    return text.find(field) != std::string_view::npos;
}
}  // namespace

void* operator new(std::size_t n) {
    if (count_allocations) ++allocations;
    if (void* p = std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

TEST(SessionAccessLog, Contract) {
    try {
        ::session::Context ctx;
        ctx.inbound.source_addr = ::net::ip::make_address("192.0.2.10");
        ctx.inbound.source_port = 52000;
        ctx.inbound.tag = "panel/hj-anytls/1041/anytls/55911";
        ctx.inbound.user_id = 714443;
        ctx.inbound.user_email = "panel/hj-anytls/1041|714443|714443";
        ctx.outbound.target = ::TargetAddress("example.com", 443);
        ctx.outbound.tag = "direct";
        ctx.outbound.connected_local_addr = ::net::ip::make_address("2602:2b5:20:111::abcd");
        auto access = ::FormatAccessLog(ctx);
        Expect(Has(access, "from 192.0.2.10:52000 accepted tcp:example.com:443") &&
               Has(access, "[panel/hj-anytls/1041/anytls/55911 -> direct]"),
               "accepted connection lost its source, target or route");
        Expect(Has(access, " user:714443 ") &&
               Has(access, " email:panel/hj-anytls/1041|714443|714443 ") &&
               Has(access, " sendThrough:2602:2b5:20:111::abcd"),
               "verified UID, existing identity and actual local address must coexist");

        ctx.inbound.ApplyForwardedMetadata(::ForwardedMetadata{
            .user_id = 1001,
            .user_email = ::memory::ThreadLocalString("alice@origin.example"),
            .client_ip = ::net::ip::make_address("203.0.113.88"),
            .inbound_tag = ::memory::ThreadLocalString("panel/site-a/10/vless/443"),
        });
        allocations = 0;
        count_allocations = true;
        access = ::FormatAccessLog(ctx);
        count_allocations = false;
        Expect(allocations == 1, "access log with passthrough fields must allocate once");
        Expect(Has(access, " origin:203.0.113.88|panel/site-a/10/vless/443|1001|alice@origin.example ") &&
               Has(access, " sendThrough:2602:2b5:20:111::abcd"),
               "passthrough origin IP, tag and user identity must appear in access log");
        ::ForwardedMetadata partial_origin;
        partial_origin.user_email = "bob@origin.example";
        ctx.inbound.ApplyForwardedMetadata(partial_origin);
        Expect(ctx.inbound.origin_tag.empty() &&
               ctx.inbound.origin_user_id == 0 &&
               ctx.inbound.origin_user_email == "bob@origin.example" &&
               ctx.inbound.origin_source_addr.is_unspecified() &&
               ctx.inbound.origin_source_ip.empty(),
               "partial forwarded metadata must replace rather than merge stale origin fields");
        ctx.inbound.ApplyForwardedMetadata(::ForwardedMetadata{});
        Expect(!ctx.inbound.HasOriginIdentity() &&
               ctx.inbound.origin_source_addr.is_unspecified() &&
               ctx.inbound.origin_source_ip.empty(),
               "empty forwarded metadata must clear all origin fields");

        ctx.worker_id = 7;
        ctx.content.speed_limit = 123456;
        ctx.content.network = ::Network::UDP;
        ctx.content.protocol = "quic";
        ctx.InitSubstreamFrom(ctx, 53000);
        Expect(ctx.worker_id == 7 &&
               ctx.inbound.source_port == 53000 &&
               ctx.inbound.tag == "panel/hj-anytls/1041/anytls/55911" &&
               ctx.outbound.tag == "direct" &&
               ctx.content.speed_limit == 123456 &&
               ctx.content.network == ::Network::TCP &&
               ctx.content.protocol.empty(),
               "self-aliased InitSubstreamFrom must preserve parent fields and reset content");
        ctx.inbound.source_port = 52000;
        ctx.outbound.target = ::TargetAddress("example.com", 443);
        ctx.outbound.connected_local_addr = ::net::ip::make_address("2602:2b5:20:111::abcd");

        ctx.inbound.user_email = "714443";
        access = ::FormatAccessLog(ctx);
        Expect(Has(access, " user:714443 ") && !Has(access, "email:"),
               "numeric identity duplicated the verified UID");
        ctx.inbound.user_id = 0;
        ctx.inbound.user_email = "user@example.com";
        ctx.outbound.connected_local_addr.reset();
        access = ::FormatAccessLog(ctx);
        Expect(Has(access, " email:user@example.com") && !Has(access, " user:") &&
               !Has(access, "sendThrough:"),
               "email-only identity must not become a numeric UID or fake local address");
        access = ::FormatAccessLog(ctx, ::AccessStatus::Rejected, "device limit exceeded");
        Expect(Has(access, " email:user@example.com") && !Has(access, " user:"),
               "authenticated static identity must survive admission rejection");
        ctx.inbound.user_email.clear();

        ctx.outbound.target = {};
        ctx.outbound.tag = {};
        access = ::FormatAccessLog(ctx, ::AccessStatus::Rejected, "authentication failed");
        Expect(Has(access, "from 192.0.2.10:52000 rejected authentication failed") &&
               Has(access, "[panel/hj-anytls/1041/anytls/55911]") &&
               !Has(access, "user:") && !Has(access, "email:") &&
               !Has(access, "tcp:") && !Has(access, "unknown") && !Has(access, " -> "),
               "pre-authentication rejection must omit unverified identity, target and outbound");
        ctx.outbound.target = ::TargetAddress("invalid host", 443);
        access = ::FormatAccessLog(ctx, ::AccessStatus::Rejected, "invalid target");
        Expect(!Has(access, "invalid host") && !Has(access, "tcp:"),
               "malformed target must not be logged as a valid destination");

        ctx.inbound.user_id = 714443;
        ctx.inbound.user_email = "714443";
        ctx.outbound.target = ::TargetAddress("example.com", 443);
        access = ::FormatAccessLog(ctx, ::AccessStatus::Rejected, "device limit exceeded");
        Expect(Has(access, "rejected tcp:example.com:443 device limit exceeded") &&
               Has(access, "user:714443") && !Has(access, "authentication failed"),
               "authenticated admission rejection lost its identity or true reason");

        ctx.inbound.source_ip = "2001:db8::1";
        ctx.outbound.target = ::TargetAddress("2001:db8::2", 65535);
        access = ::FormatAccessLog(ctx);
        Expect(Has(access, "from [2001:db8::1]:52000") &&
               Has(access, "tcp:[2001:db8::2]:65535"),
               "IPv6 endpoints need unambiguous port boundaries");
        allocations = 0;
        count_allocations = true;
        access = ::FormatAccessLog(ctx);
        count_allocations = false;
        Expect(allocations == 1, "access log must allocate only its final owning string");

        ctx.inbound.source_ip.clear();
        ctx.inbound.source_addr = ::net::ip::make_address("::ffff:192.0.2.1");
        ctx.outbound.target = ::TargetAddress(::net::ip::make_address("::ffff:198.51.100.1"), 443);
        access = ::FormatAccessLog(ctx);
        Expect(Has(access, "from 192.0.2.1:52000") && Has(access, "tcp:198.51.100.1:443"),
               "IPv4-mapped endpoints must retain their normalized identity");
        ctx.inbound.source_addr = ::net::ip::address{};
        ctx.inbound.user_id = 0;
        ctx.inbound.user_email.clear();
        ctx.outbound.target = {};
        access = ::FormatAccessLog(ctx, ::AccessStatus::Rejected, "connection limit exceeded");
        Expect(!Has(access, "unknown") && !Has(access, " from ") &&
               !Has(access, "email:") && !Has(access, "user:"),
               "missing pre-authentication fields must not be fabricated");
    } catch (const std::exception& error) {
        count_allocations = false;
        std::cerr << error.what() << '\n';
        FAIL() << error.what();
    }
}
