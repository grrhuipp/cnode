#include <gtest/gtest.h>

#include "transport/internet/outbound_bind.hpp"
#include "infra/outbound_bind_config.hpp"
#include "common/target_address.hpp"

#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include <array>
#include <stdexcept>
#include <string_view>

TEST(OutboundBind, Contract) {
    using Mode = ::OutboundBind::Mode;
    using Policy = ::OutboundBind::ChoicePolicy;
    using ::net::ip::make_address;

    for (const auto value : std::array<std::string_view, 5>{
             "", "0.0.0.0", "::", "0:0::", "::ffff:0.0.0.0"}) {
        auto bind = ::OutboundBind::Parse(value);
        ASSERT_FALSE((!bind || bind->GetMode() != Mode::None || bind->ExplicitAddress()));
    }
    auto automatic = ::OutboundBind::Parse("auto");
    ASSERT_FALSE((!automatic || automatic->GetMode() != Mode::Auto || automatic->ExplicitAddress()));
    auto ipv4 = ::OutboundBind::Parse("192.0.2.10");
    auto ipv6 = ::OutboundBind::Parse("2001:db8::10");
    ASSERT_FALSE((!ipv4 || ipv4->ExplicitAddress() != make_address("192.0.2.10") ||
        !ipv6 || ipv6->ExplicitAddress() != make_address("2001:db8::10")));
    for (const auto value : std::array<std::string_view, 3>{
             "not-an-ip", "192.0.2.1junk", "  auto"}) {
        ASSERT_FALSE((::OutboundBind::Parse(value)));
    }
    auto upper = ::OutboundBind::Parse("AUTO");
    ASSERT_FALSE((!upper || upper->GetMode() != Mode::Auto));
    for (const auto value : std::array<std::string_view, 7>{
             "127.0.0.1:9", "[127.0.0.1]", "[::1]", "127.0.0.1 ",
             "fe80::1%invalid", std::string_view("127.0.0.1\0ignored", 17),
             std::string_view("::1\0ignored", 11)}) {
        ASSERT_FALSE((::OutboundBind::Parse(value)));
    }

    const auto remote_v4 = make_address("198.51.100.1");
    const auto remote_v6 = make_address("2001:db8:1::1");
    const std::array<std::string_view, 3> entries{
        "2602:2b5:20:0111::/64", "192.0.2.4", "127.0.0.0/24"};
    auto ordered = ::OutboundBind::ParseCandidates(entries, Policy::IpHash);
    ASSERT_FALSE((!ordered || ordered->GetMode() != Mode::Ordered || !ordered->PrefersIPv6()));
    const auto first = ordered->Select(remote_v6, "203.0.113.42").address;
    ASSERT_FALSE((!first || !first->is_v6() || ::net::ip::network_v6(first->to_v6(), 64)
            .network() != ::net::ip::make_address_v6("2602:2b5:20:111::")));
    ASSERT_FALSE((ordered->Select(remote_v6, "203.0.113.42").address != first ||
        ordered->Select(remote_v6, "203.0.113.43").address == first));
    // An exact address is used as-is, even when it is not assigned locally;
    // later same-family entries must not silently replace it on dial failure.
    ASSERT_FALSE((ordered->Select(remote_v4, "client").address !=
        make_address("192.0.2.4")));

    const std::array<std::string_view, 1> single_v4{"127.0.0.0/24"};
    auto range_v4 = ::OutboundBind::ParseCandidates(single_v4, Policy::IpHash);
    ASSERT_FALSE((!range_v4));
    const auto v4_first = range_v4->Select(remote_v4, "203.0.113.42").address;
    ASSERT_FALSE((!v4_first || ::net::ip::network_v4(v4_first->to_v4(), 24).network() !=
            ::net::ip::make_address_v4("127.0.0.0") ||
        range_v4->Select(remote_v4, "203.0.113.42").address != v4_first ||
        range_v4->Select(remote_v4, "203.0.113.43").address == v4_first ||
        range_v4->Select(remote_v6, "client").address));

    auto user_ordered = ::OutboundBind::ParseCandidates(entries, Policy::UserHash);
    ASSERT_FALSE((!user_ordered));
    const auto user_a_ip1 = user_ordered->Select(remote_v6, "203.0.113.1", 1001, "a@test").address;
    const auto user_a_ip2 = user_ordered->Select(remote_v6, "198.51.100.9", 1001, "a@test").address;
    const auto user_b = user_ordered->Select(remote_v6, "203.0.113.1", 1002, "b@test").address;
    ASSERT_FALSE((!user_a_ip1 || user_a_ip1 != user_a_ip2 || user_a_ip1 == user_b));
    const auto email_a_ip1 = user_ordered->Select(remote_v6, "203.0.113.1", 0, "alice@test").address;
    const auto email_a_ip2 = user_ordered->Select(remote_v6, "198.51.100.9", 0, "alice@test").address;
    const auto email_b = user_ordered->Select(remote_v6, "203.0.113.1", 0, "bob@test").address;
    ASSERT_FALSE((!email_a_ip1 || email_a_ip1 != email_a_ip2 || email_a_ip1 == email_b));
    const auto panel1_repeat = user_ordered->Select(
        remote_v6, "203.0.113.1", 1001, "u@a", "panel/site-a/10/vless/443").address;
    const auto panel1_diff_ip = user_ordered->Select(
        remote_v6, "203.0.113.2", 1001, "u@a", "panel/site-a/10/vless/443").address;
    const auto panel2_same_uid = user_ordered->Select(
        remote_v6, "203.0.113.1", 1001, "u@a", "panel/site-b/10/vless/443").address;
    ASSERT_FALSE((!panel1_repeat || panel1_repeat != panel1_diff_ip ||
        panel1_repeat == panel2_same_uid));
    auto random_range = ::OutboundBind::ParseCandidates(entries, Policy::Random);
    ASSERT_FALSE((!random_range));
    const auto first_random = random_range->Select(remote_v6, "client", 80).address;
    bool saw_different = false;
    for (int i = 0; i < 64; ++i) {
        const auto next = random_range->Select(remote_v6, "client", 80).address;
        ASSERT_FALSE((!next || ::net::ip::network_v6(next->to_v6(), 64).network() !=
                ::net::ip::make_address_v6("2602:2b5:20:111::")));
        saw_different |= next != first_random;
    }
    ASSERT_FALSE((!saw_different));

    const std::array<std::string_view, 1> unassigned{"2602:2b5:20:111::1234"};
    auto exact = ::OutboundBind::ParseCandidates(unassigned, Policy::IpHash);
    ASSERT_FALSE((!exact || exact->Select(remote_v6, "client").address !=
        make_address("2602:2b5:20:111::1234") ||
        exact->Select(remote_v4, "client").address));

    for (const std::string_view bad : {"", "auto", "0.0.0.0", "0.0.0.0/32", "::/128",
                                       "0.0.0.0/24", "192.0.2.1/0", "::ffff:192.0.2.0/24",
                                       "127.0.0.0/024", "192.0.2.0/33",
                                       "2001:db8::/129", "127.0.0.1/24x", "not-ip/24"}) {
        const std::array<std::string_view, 1> candidate{bad};
        ASSERT_FALSE((::OutboundBind::ParseCandidates(candidate, Policy::IpHash)));
    }
    const ::tcp::endpoint public_inbound(make_address("192.0.2.10"), 443);
    ASSERT_FALSE((automatic->BindAddressFor(&public_inbound, make_address("127.0.0.1"))));
    const ::tcp::endpoint link_local_inbound(make_address("fe80::1"), 443);
    ASSERT_FALSE((automatic->BindAddressFor(&link_local_inbound, remote_v6)));
    ASSERT_FALSE((::OutboundBind::ParseCandidates(
            std::span<const std::string_view>{}, Policy::IpHash)));

    const auto parsed = ::json::parse(R"(["127.0.0.1/32", "::1"])");
    const auto random = ::json::parse(R"("random")");
    const auto ip_hash = ::json::parse(R"("ip_hash")");
    const auto user_hash = ::json::parse(R"("user_hash")");
    const auto configured = ::infra::ParseOutboundBindConfig(parsed, &random);
    ASSERT_FALSE((configured.GetMode() != Mode::Ordered ||
        ::infra::ParseOutboundBindConfig(parsed, &ip_hash).GetMode() != Mode::Ordered ||
        ::infra::ParseOutboundBindConfig(parsed, &user_hash).GetMode() != Mode::Ordered ||
        ::infra::ParseOutboundBindConfig(parsed).GetMode() != Mode::Ordered));
    auto rejected = [](std::string_view value, std::string_view strategy = {}) {
        const auto parsed_value = ::json::parse(value);
        std::optional<::json::value> parsed_strategy;
        if (!strategy.empty()) parsed_strategy.emplace(::json::parse(strategy));
        try {
            (void)::infra::ParseOutboundBindConfig(
                parsed_value, parsed_strategy ? &*parsed_strategy : nullptr);
        } catch (const std::invalid_argument&) {
            return true;
        }
        return false;
    };
    ASSERT_FALSE((!rejected("[]") || !rejected("[7]") || !rejected(R"(["bad/24"])") ||
        !rejected(R"(["::1"])", R"("round-robin")") ||
        !rejected(R"(["::1"])", R"("hash")") ||
        !rejected(R"("auto")", R"("ip_hash")")));
}
