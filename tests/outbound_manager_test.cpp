#include "acppnode/app/proxyman/outbound/manager.hpp"
#include "acppnode/app/proxyman/inbound/manager.hpp"
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
        std::span<const uint8_t>,
        acpp::buf::MultiBuffer&,
        std::chrono::seconds,
        std::chrono::seconds) override {
        co_return acpp::RelayResult{};
    }

    int Generation() const noexcept { return generation_; }

private:
    std::string tag_;
    int generation_;
};

class OversizedTagOutbound final : public acpp::Outbound {
public:
    std::string_view Tag() const noexcept override {
        static constexpr char marker = 'x';
        return {&marker, std::numeric_limits<size_t>::max()};
    }

    acpp::net::awaitable<acpp::OutboundProcessResult> Process(
        acpp::net::io_context&,
        const acpp::tcp::endpoint*,
        acpp::session::Context&,
        const acpp::TimeoutsConfig&,
        acpp::transport::Link,
        acpp::StatsShard&,
        const acpp::RelayConfig&,
        std::span<const uint8_t>,
        acpp::buf::MultiBuffer&,
        std::chrono::seconds,
        std::chrono::seconds) override {
        co_return acpp::RelayResult{};
    }
};

using OutboundManager = acpp::proxyman::outbound::Manager;
static_assert(!noexcept(std::declval<OutboundManager&>().AddHandler(
    std::declval<std::unique_ptr<acpp::Outbound>>())));
static_assert(!noexcept(std::declval<OutboundManager&>().ReplaceHandler(
    std::declval<std::unique_ptr<acpp::Outbound>>())));
static_assert(!noexcept(std::declval<OutboundManager&>().RemoveHandler(
    std::declval<std::string_view>())));
static_assert(std::is_same_v<
    decltype(std::declval<OutboundManager&>().GetHandler(
        std::declval<std::string_view>())),
    std::shared_ptr<acpp::Outbound>>);

using InboundManager = acpp::proxyman::inbound::Manager;
static_assert(std::is_same_v<
    decltype(std::declval<InboundManager&>().GetHandler(
        std::declval<std::string_view>())),
    std::shared_ptr<acpp::proxyman::inbound::Handler>>);
static_assert(!noexcept(std::declval<InboundManager&>().ReplaceHandler(
    std::declval<std::unique_ptr<acpp::proxyman::inbound::Handler>>())));
static_assert(!noexcept(std::declval<InboundManager&>().RemoveHandler(
    std::declval<std::string_view>())));

}  // namespace

int main() {
    acpp::proxyman::outbound::Manager manager;

    auto first = std::make_unique<TestOutbound>("direct", 1);
    auto* first_raw = first.get();
    auto first_owner = manager.AddHandler(std::move(first));
    if (first_owner.get() != first_raw) return 1;
    if (manager.GetHandler("direct").get() != first_raw) return 2;
    if (manager.GetDefaultHandler().get() != first_raw) return 3;

    if (manager.ReplaceHandler(nullptr) != nullptr) return 4;
    if (manager.GetHandler("direct").get() != first_raw) return 5;

    auto second = std::make_unique<TestOutbound>("direct", 2);
    auto* second_raw = second.get();
    auto second_owner = manager.ReplaceHandler(std::move(second));
    if (second_owner.get() != second_raw) return 6;
    if (manager.GetHandler("direct").get() != second_raw) return 7;
    if (manager.GetDefaultHandler().get() != second_raw) return 8;
    if (static_cast<TestOutbound*>(manager.GetHandler("direct").get())->Generation() != 2) return 9;

    if (static_cast<TestOutbound*>(first_owner.get())->Generation() != 1) return 10;

    try {
        (void)manager.AddHandler(std::make_unique<OversizedTagOutbound>());
        return 11;
    } catch (const std::length_error&) {
    }
    if (manager.GetHandler("direct").get() != second_raw ||
        manager.GetDefaultHandler().get() != second_raw) return 12;

    try {
        (void)manager.ReplaceHandler(std::make_unique<OversizedTagOutbound>());
        return 13;
    } catch (const std::length_error&) {
    }
    if (manager.GetHandler("direct").get() != second_raw ||
        manager.GetDefaultHandler().get() != second_raw) return 14;

    auto fallback = std::make_unique<TestOutbound>("fallback", 3);
    auto* fallback_raw = fallback.get();
    if (manager.AddHandler(std::move(fallback)).get() != fallback_raw) return 15;
    if (manager.GetDefaultHandler().get() != second_raw) return 16;

    manager.RemoveHandler("direct");
    if (manager.GetHandler("direct") != nullptr) return 17;
    if (manager.GetHandler("fallback").get() != fallback_raw) return 18;
    if (manager.GetDefaultHandler().get() != fallback_raw) return 19;

    if (static_cast<TestOutbound*>(second_owner.get())->Generation() != 2) return 20;

    return 0;
}
