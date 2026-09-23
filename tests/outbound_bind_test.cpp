#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/infra/outbound_bind_config.hpp"

#include <array>
#include <string_view>
#include <stdexcept>
#include <vector>

int main() {
    using Mode = acpp::OutboundBind::Mode;

    for (const auto value : std::array<std::string_view, 5>{
             "", "0.0.0.0", "::", "0:0::", "::ffff:0.0.0.0"}) {
        auto bind = acpp::OutboundBind::Parse(value);
        if (!bind || bind->GetMode() != Mode::None || bind->ExplicitAddress()) return 1;
    }

    auto automatic = acpp::OutboundBind::Parse("auto");
    if (!automatic || automatic->GetMode() != Mode::Auto || automatic->ExplicitAddress()) {
        return 2;
    }

    auto ipv4 = acpp::OutboundBind::Parse("192.0.2.10");
    if (!ipv4 || ipv4->GetMode() != Mode::Explicit ||
        !ipv4->ExplicitAddress() || !ipv4->ExplicitAddress()->is_v4()) {
        return 3;
    }

    auto ipv6 = acpp::OutboundBind::Parse("2001:db8::10");
    if (!ipv6 || ipv6->GetMode() != Mode::Explicit ||
        !ipv6->ExplicitAddress() || !ipv6->ExplicitAddress()->is_v6()) {
        return 4;
    }

    for (const auto value :
         std::array<std::string_view, 4>{"not-an-ip", "192.0.2.1junk", "AUTO", "  auto"}) {
        if (acpp::OutboundBind::Parse(value)) return 5;
    }

    for (const auto value : std::array<std::string_view, 7>{"127.0.0.1:9", "[127.0.0.1]", "[::1]", "127.0.0.1 ",
             "fe80::1%invalid", std::string_view("127.0.0.1\0ignored", 17),
             std::string_view("::1\0ignored", 11)}) {
        if (acpp::OutboundBind::Parse(value)) return 20;
    }

    if (acpp::OutboundBind::Auto().GetMode() != Mode::Auto) return 6;

    using acpp::net::ip::make_address;
    using Policy = acpp::OutboundBind::ChoicePolicy;
    const std::vector<acpp::net::ip::address> local{
        make_address("127.0.0.1"), make_address("127.0.0.2"),
        make_address("::1"), make_address("2001:db8::11"),
        make_address("2001:db8::12")};
    const auto v4 = make_address("198.51.100.1");
    const auto v6 = make_address("2001:db8:1::1");
    const std::array<std::string_view, 3> sources{
        "2001:db8::/64", "192.0.2.4", "127.0.0.0/24"};
    auto ordered = acpp::OutboundBind::ParseCandidates(sources, local, Policy::SourceHash);
    if (!ordered || ordered->GetMode() != Mode::Ordered || !ordered->PrefersIPv6()) return 7;
    const auto first = ordered->Select(v6, "203.0.113.42", 30401);
    if (!first.address || !first.address->is_v6() || first.unavailable) return 8;
    for (int i = 0; i < 10; ++i) {
        if (ordered->Select(v6, "203.0.113.42", 30401).address != first.address) return 9;
    }
    if (ordered->Select(v6, "203.0.113.42", 30402).address == first.address) return 10;
    auto random_cidr = acpp::OutboundBind::ParseCandidates(
        std::array<std::string_view, 1>{"2001:db8::/64"}, local, Policy::Random);
    if (!random_cidr) return 26;
    bool saw_11 = false;
    bool saw_12 = false;
    for (int i = 0; i < 128; ++i) {
        const auto candidate = random_cidr->Select(v6, "203.0.113.42", 30401).address;
        saw_11 |= candidate == make_address("2001:db8::11");
        saw_12 |= candidate == make_address("2001:db8::12");
    }
    if (!saw_11 || !saw_12) return 27;
    const auto fallback = ordered->Select(v4, "203.0.113.42", 30401);
    if (!fallback.address || *fallback.address != make_address("127.0.0.1") &&
        *fallback.address != make_address("127.0.0.2") || fallback.unavailable) return 11;

    const std::array<std::string_view, 1> missing_v6{"2001:db8:ffff::/64"};
    auto unavailable = acpp::OutboundBind::ParseCandidates(
        missing_v6, local, Policy::SourceHash);
    if (!unavailable || !unavailable->Select(v6, "client", 80).unavailable ||
        unavailable->Select(v6, "client", 80).address ||
        unavailable->Select(v4, "client", 80).address ||
        unavailable->Select(v4, "client", 80).unavailable) return 12;

    const std::array<std::string_view, 2> ordered_ips{"2001:db8::99", "2001:db8::11"};
    auto next = acpp::OutboundBind::ParseCandidates(ordered_ips, local, Policy::Random);
    if (!next || next->Select(v6, "client", 80).address !=
        make_address("2001:db8::11")) return 13;

    for (const std::string_view bad : {"", "auto", "0.0.0.0", "192.0.2.0/33",
                                       "2001:db8::/129", "127.0.0.1/24x", "not-ip/24"}) {
        const std::array<std::string_view, 1> candidate{bad};
        if (acpp::OutboundBind::ParseCandidates(candidate, local, Policy::SourceHash)) return 14;
    }
    if (acpp::OutboundBind::ParseCandidates(
            std::span<const std::string_view>{}, local, Policy::SourceHash)) return 15;

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
