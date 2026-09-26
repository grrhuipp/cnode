#include "acppnode/common/session.hpp"

#include <asio/ip/address.hpp>

#include <iostream>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
thread_local bool count_allocations = false;
thread_local size_t allocations = 0;

void Expect(std::string_view actual, std::string_view expected) {
    if (actual != expected) {
        throw std::runtime_error("access log mismatch: " + std::string(actual));
    }
}

}  // namespace

void* operator new(std::size_t n) {
    if (count_allocations) ++allocations;
    if (void* p = std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

int main() {
    try {
        acpp::session::Context ctx;
        ctx.inbound.source_addr = acpp::net::ip::make_address("192.0.2.10");
        ctx.inbound.source_port = 52000;
        ctx.inbound.tag = "panel/hj-anytls/1041/anytls/55911";
        ctx.inbound.user_id = 714443;
        ctx.inbound.user_email = "panel/hj-anytls/1041|714443|714443";
        ctx.outbound.target = acpp::TargetAddress("example.com", 443);
        ctx.outbound.tag = ctx.inbound.tag;
        ctx.outbound.connected_local_addr =
            acpp::net::ip::make_address("2602:2b5:20:111::abcd");
        Expect(acpp::FormatAccessLog(ctx),
               "from 192.0.2.10:52000 accepted tcp:example.com:443 "
               "[panel/hj-anytls/1041/anytls/55911] user:714443 "
               "sendThrough:2602:2b5:20:111::abcd");

        ctx.outbound.tag = "ipv6_first";
        ctx.inbound.user_id = 0;
        ctx.inbound.user_email = "user@example.com";
        ctx.outbound.connected_local_addr.reset();
        Expect(acpp::FormatAccessLog(ctx),
               "from 192.0.2.10:52000 accepted tcp:example.com:443 "
               "[panel/hj-anytls/1041/anytls/55911 -> ipv6_first] "
               "user:user@example.com");

        ctx.inbound.user_email.clear();
        ctx.outbound.connected_local_addr = acpp::net::ip::make_address("198.51.100.2");
        Expect(acpp::FormatAccessLog(ctx),
               "from 192.0.2.10:52000 accepted tcp:example.com:443 "
               "[panel/hj-anytls/1041/anytls/55911 -> ipv6_first] "
               "sendThrough:198.51.100.2");

        ctx.inbound.source_ip = "2001:db8::1";
        ctx.inbound.source_port = 0;
        ctx.inbound.tag = {};
        ctx.outbound.tag = {};
        ctx.outbound.target = acpp::TargetAddress("2001:db8::2", 65535);
        ctx.outbound.target.host = "[2001:db8::2]";
        ctx.outbound.connected_local_addr.reset();
        Expect(acpp::FormatAccessLog(ctx),
               "from [2001:db8::1]:0 accepted tcp:[2001:db8::2]:65535 [-]");
        allocations = 0;
        count_allocations = true;
        auto log = acpp::FormatAccessLog(ctx);
        count_allocations = false;
        if (allocations != 1) throw std::runtime_error("common access log must allocate only its final owning string");
        std::cout << "access log owning allocations=" << allocations << '\n';

        ctx.inbound.source_ip.clear();
        ctx.inbound.source_addr = acpp::net::ip::make_address("::ffff:192.0.2.1");
        ctx.outbound.target.host.clear();
        ctx.outbound.target.resolved_addr = acpp::net::ip::make_address("::ffff:198.51.100.1");
        Expect(acpp::FormatAccessLog(ctx),
               "from 192.0.2.1:0 accepted tcp:198.51.100.1:65535 [-]");
        ctx.inbound.source_addr = acpp::net::ip::address{};
        ctx.outbound.target.resolved_addr.reset();
        Expect(acpp::FormatAccessLog(ctx),
               "from unknown:0 accepted tcp:unknown:65535 [-]");
    } catch (const std::exception& error) {
        count_allocations = false;
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
