#include "acppnode/app/proxyman/outbound/handler_registry.hpp"
#include "acppnode/app/proxyman/inbound/handler_registry.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace {

class TestOutbound final : public acpp::Outbound {
public:
    TestOutbound(std::string tag, int generation)
        : tag_(std::move(tag)), generation_(generation) {}

    std::string_view Tag() const noexcept override { return tag_; }

    acpp::net::awaitable<acpp::OutboundProcessResult> Process(
        acpp::net::io_context&,
        const acpp::tcp::endpoint*,
        acpp::session::Context&,
        const acpp::TimeoutsConfig&,
        acpp::transport::Link,
        acpp::StatsShard&,
        const acpp::RelayConfig&,
        acpp::buf::MultiBufferBatch,
        std::chrono::seconds,
        std::chrono::seconds) override {
        co_return acpp::RelayResult{};
    }

    int Generation() const noexcept { return generation_; }

private:
    std::string tag_;
    int generation_;
};

using OutboundRegistry = acpp::proxyman::outbound::HandlerRegistry;
static_assert(!noexcept(std::declval<OutboundRegistry&>().AddHandler(
    std::declval<std::unique_ptr<acpp::Outbound>>())));
static_assert(!noexcept(std::declval<OutboundRegistry&>().ReplaceHandler(
    std::declval<std::unique_ptr<acpp::Outbound>>())));
static_assert(!noexcept(std::declval<OutboundRegistry&>().RemoveHandler(
    std::declval<std::string_view>())));
static_assert(std::is_same_v<
    decltype(std::declval<OutboundRegistry&>().GetHandler(
        std::declval<std::string_view>())),
    std::shared_ptr<acpp::Outbound>>);

using InboundRegistry = acpp::proxyman::inbound::HandlerRegistry;
static_assert(std::is_same_v<
    decltype(std::declval<InboundRegistry&>().GetHandler(
        std::declval<std::string_view>())),
    std::shared_ptr<acpp::proxyman::inbound::Handler>>);
static_assert(!noexcept(std::declval<InboundRegistry&>().ReplaceHandler(
    std::declval<std::unique_ptr<acpp::proxyman::inbound::Handler>>())));
static_assert(!noexcept(std::declval<InboundRegistry&>().RemoveHandler(
    std::declval<std::string_view>())));

}  // namespace

int main() {
    acpp::proxyman::outbound::HandlerRegistry registry;

    auto first = std::make_unique<TestOutbound>("direct", 1);
    auto* first_raw = first.get();
    auto first_owner = registry.AddHandler(std::move(first));
    if (first_owner.get() != first_raw) return 1;
    if (registry.GetHandler("direct").get() != first_raw) return 2;
    if (registry.GetHandler("") != nullptr) return 3;

    if (registry.ReplaceHandler(nullptr) != nullptr) return 4;
    if (registry.GetHandler("direct").get() != first_raw) return 5;

    auto second = std::make_unique<TestOutbound>("direct", 2);
    auto* second_raw = second.get();
    auto second_owner = registry.ReplaceHandler(std::move(second));
    if (second_owner.get() != second_raw) return 6;
    if (registry.GetHandler("direct").get() != second_raw) return 7;
    if (static_cast<TestOutbound*>(registry.GetHandler("direct").get())->Generation() != 2) return 8;

    if (static_cast<TestOutbound*>(first_owner.get())->Generation() != 1) return 9;

    if (registry.AddHandler(std::make_unique<TestOutbound>("direct", 99)) != nullptr) return 10;
    if (registry.GetHandler("direct").get() != second_raw) return 11;

    auto fallback = std::make_unique<TestOutbound>("fallback", 3);
    auto* fallback_raw = fallback.get();
    if (registry.ReplaceHandler(std::move(fallback)).get() != fallback_raw) return 14;
    registry.RemoveHandler("direct");
    if (registry.GetHandler("direct") != nullptr) return 15;
    if (registry.GetHandler("fallback").get() != fallback_raw) return 16;

    if (static_cast<TestOutbound*>(second_owner.get())->Generation() != 2) return 17;

    return 0;
}
