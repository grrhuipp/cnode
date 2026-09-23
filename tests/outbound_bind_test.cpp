#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/infra/outbound_bind_config.hpp"

#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include <array>
#include <stdexcept>
#include <string_view>

int main() {
    using Mode = acpp::OutboundBind::Mode;
    using Policy = acpp::OutboundBind::ChoicePolicy;
    using acpp::net::ip::make_address;

    for (const auto value : std::array<std::string_view, 5>{
             "", "0.0.0.0", "::", "0:0::", "::ffff:0.0.0.0"}) {
        auto bind = acpp::OutboundBind::Parse(value);
        if (!bind || bind->GetMode() != Mode::None || bind->ExplicitAddress()) return 1;
    }
    auto automatic = acpp::OutboundBind::Parse("auto");
    if (!automatic || automatic->GetMode() != Mode::Auto || automatic->ExplicitAddress()) return 2;
    auto ipv4 = acpp::OutboundBind::Parse("192.0.2.10");
    auto ipv6 = acpp::OutboundBind::Parse("2001:db8::10");
    if (!ipv4 || ipv4->ExplicitAddress() != make_address("192.0.2.10") ||
        !ipv6 || ipv6->ExplicitAddress() != make_address("2001:db8::10")) return 3;
    for (const auto value : std::array<std::string_view, 4>{
             "not-an-ip", "192.0.2.1junk", "AUTO", "  auto"}) {
        if (acpp::OutboundBind::Parse(value)) return 4;
    }
    for (const auto value : std::array<std::string_view, 7>{
             "127.0.0.1:9", "[127.0.0.1]", "[::1]", "127.0.0.1 ",
             "fe80::1%invalid", std::string_view("127.0.0.1\0ignored", 17),
             std::string_view("::1\0ignored", 11)}) {
        if (acpp::OutboundBind::Parse(value)) return 5;
    }

    const auto remote_v4 = make_address("198.51.100.1");
    const auto remote_v6 = make_address("2001:db8:1::1");
    const std::array<std::string_view, 3> entries{
        "2602:2b5:20:0111::/64", "192.0.2.4", "127.0.0.0/24"};
    auto ordered = acpp::OutboundBind::ParseCandidates(entries, Policy::SourceHash);
    if (!ordered || ordered->GetMode() != Mode::Ordered || !ordered->PrefersIPv6()) return 6;
    const auto first = ordered->Select(remote_v6, "203.0.113.42", 30401).address;
    if (!first || !first->is_v6() || acpp::net::ip::network_v6(first->to_v6(), 64)
            .network() != acpp::net::ip::make_address_v6("2602:2b5:20:111::")) return 7;
    if (ordered->Select(remote_v6, "203.0.113.42", 30401).address != first ||
        ordered->Select(remote_v6, "203.0.113.42", 30402).address == first) return 8;
    // An exact address is used as-is, even when it is not assigned locally;
    // later same-family entries must not silently replace it on dial failure.
    if (ordered->Select(remote_v4, "client", 80).address !=
        make_address("192.0.2.4")) return 9;

    const std::array<std::string_view, 1> single_v4{"127.0.0.0/24"};
    auto range_v4 = acpp::OutboundBind::ParseCandidates(single_v4, Policy::SourceHash);
    if (!range_v4) return 10;
    const auto v4_first = range_v4->Select(remote_v4, "203.0.113.42", 30401).address;
    if (!v4_first || acpp::net::ip::network_v4(v4_first->to_v4(), 24).network() !=
            acpp::net::ip::make_address_v4("127.0.0.0") ||
        range_v4->Select(remote_v4, "203.0.113.42", 30401).address != v4_first ||
        range_v4->Select(remote_v4, "203.0.113.42", 30402).address == v4_first ||
        range_v4->Select(remote_v6, "client", 80).address) return 10;

    auto random_range = acpp::OutboundBind::ParseCandidates(entries, Policy::Random);
    if (!random_range) return 11;
    const auto first_random = random_range->Select(remote_v6, "client", 80).address;
    bool saw_different = false;
    for (int i = 0; i < 64; ++i) {
        const auto next = random_range->Select(remote_v6, "client", 80).address;
        if (!next || acpp::net::ip::network_v6(next->to_v6(), 64).network() !=
                acpp::net::ip::make_address_v6("2602:2b5:20:111::")) return 11;
        saw_different |= next != first_random;
    }
    if (!saw_different) return 12;

    const std::array<std::string_view, 1> unassigned{"2602:2b5:20:111::1234"};
    auto exact = acpp::OutboundBind::ParseCandidates(unassigned, Policy::SourceHash);
    if (!exact || exact->Select(remote_v6, "client", 80).address !=
        make_address("2602:2b5:20:111::1234") ||
        exact->Select(remote_v4, "client", 80).address) return 13;

    for (const std::string_view bad : {"", "auto", "0.0.0.0", "192.0.2.0/33",
                                       "2001:db8::/129", "127.0.0.1/24x", "not-ip/24"}) {
        const std::array<std::string_view, 1> candidate{bad};
        if (acpp::OutboundBind::ParseCandidates(candidate, Policy::SourceHash)) return 14;
    }
    if (acpp::OutboundBind::ParseCandidates(
            std::span<const std::string_view>{}, Policy::SourceHash)) return 15;

    const auto parsed = acpp::json::parse(R"(["127.0.0.1/32", "::1"])");
    const auto random = acpp::json::parse(R"("random")");
    const auto configured = acpp::infra::ParseOutboundBindConfig(parsed, &random);
    if (configured.GetMode() != Mode::Ordered ||
        acpp::infra::ParseOutboundBindConfig(parsed).GetMode() != Mode::Ordered) return 16;
    auto rejected = [](std::string_view value, std::string_view strategy = {}) {
        const auto parsed_value = acpp::json::parse(value);
        std::optional<acpp::json::value> parsed_strategy;
        if (!strategy.empty()) parsed_strategy.emplace(acpp::json::parse(strategy));
        try {
            (void)acpp::infra::ParseOutboundBindConfig(
                parsed_value, parsed_strategy ? &*parsed_strategy : nullptr);
        } catch (const std::invalid_argument&) {
            return true;
        }
        return false;
    };
    if (!rejected("[]") || !rejected("[7]") || !rejected(R"(["bad/24"])") ||
        !rejected(R"(["::1"])", R"("round-robin")") ||
        !rejected(R"("auto")", R"("hash")")) return 17;
    return 0;
}
