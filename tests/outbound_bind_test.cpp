#include "acppnode/transport/internet/outbound_bind.hpp"

#include <array>
#include <string_view>

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

    if (acpp::OutboundBind::Auto().GetMode() != Mode::Auto) return 6;
    return 0;
}
