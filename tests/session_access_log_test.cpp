#include "acppnode/common/session.hpp"

#include <asio/ip/address.hpp>

#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

void Expect(std::string_view actual, std::string_view expected) {
    if (actual != expected) {
        throw std::runtime_error("access log mismatch: " + std::string(actual));
    }
}

}  // namespace

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
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
