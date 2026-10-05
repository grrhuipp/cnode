#include "acppnode/app/proxyman/outbound/manager.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/use_future.hpp>

#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

class TestOutbound final : public acpp::Outbound {
public:
    TestOutbound(std::string tag, int generation, int& stop_count)
        : tag_(std::move(tag)), generation_(generation), stop_count_(stop_count) {}

    std::string_view Tag() const noexcept override { return tag_; }

    acpp::net::awaitable<acpp::OutboundProcessResult> Process(
        acpp::net::any_io_executor,
        const acpp::tcp::endpoint*,
        acpp::session::Context&,
        const acpp::TimeoutsConfig&,
        acpp::transport::Link,
        acpp::StatsShard&,
        const acpp::RelayConfig&,
        acpp::buf::MultiBuffer,
        std::chrono::seconds,
        std::chrono::seconds) const override {
        co_return acpp::RelayResult{};
    }

    acpp::net::awaitable<void> Stop() const override {
        ++stop_count_;
        co_return;
    }

    int Generation() const noexcept { return generation_; }

private:
    std::string tag_;
    int generation_;
    int& stop_count_;
};

class OversizedTagOutbound final : public acpp::Outbound {
public:
    std::string_view Tag() const noexcept override {
        static constexpr char marker = 'x';
        return {&marker, std::numeric_limits<size_t>::max()};
    }

    acpp::net::awaitable<acpp::OutboundProcessResult> Process(
        acpp::net::any_io_executor,
        const acpp::tcp::endpoint*,
        acpp::session::Context&,
        const acpp::TimeoutsConfig&,
        acpp::transport::Link,
        acpp::StatsShard&,
        const acpp::RelayConfig&,
        acpp::buf::MultiBuffer,
        std::chrono::seconds,
        std::chrono::seconds) const override {
        co_return acpp::RelayResult{};
    }
};

acpp::net::awaitable<int> RunTest(acpp::net::any_io_executor executor) {
    acpp::proxyman::outbound::Manager manager(executor);
    int first_stops = 0;
    int second_stops = 0;
    int fallback_stops = 0;

    auto first = std::make_unique<TestOutbound>("direct", 1, first_stops);
    const auto* first_raw = first.get();
    auto first_owner = co_await manager.AddHandler(std::move(first));
    if (first_owner.get() != first_raw) co_return 1;
    if (manager.GetHandler("direct").get() != first_raw) co_return 2;
    if (manager.GetHandler("")) co_return 3;

    if (co_await manager.ReplaceHandler(nullptr)) co_return 4;
    if (manager.GetHandler("direct").get() != first_raw) co_return 5;

    auto second = std::make_unique<TestOutbound>("direct", 2, second_stops);
    const auto* second_raw = second.get();
    auto second_owner = co_await manager.ReplaceHandler(std::move(second));
    if (second_owner.get() != second_raw || first_stops != 1) co_return 6;
    const auto selected = manager.GetHandler("direct");
    const auto* selected_test = dynamic_cast<const TestOutbound*>(selected.get());
    if (!selected_test || selected_test->Generation() != 2) co_return 7;
    const auto* retired_test = dynamic_cast<const TestOutbound*>(first_owner.get());
    if (!retired_test || retired_test->Generation() != 1) co_return 8;

    try {
        (void)co_await manager.AddHandler(std::make_unique<OversizedTagOutbound>());
        co_return 9;
    } catch (const std::length_error&) {
    }
    if (manager.GetHandler("direct").get() != second_raw) co_return 10;

    auto fallback = std::make_unique<TestOutbound>("fallback", 3, fallback_stops);
    const auto* fallback_raw = fallback.get();
    if ((co_await manager.AddHandler(std::move(fallback))).get() != fallback_raw) {
        co_return 11;
    }

    co_await manager.RemoveHandler("direct");
    if (manager.GetHandler("direct") || second_stops != 1) co_return 12;
    if (manager.GetHandler("fallback").get() != fallback_raw) co_return 13;
    if (dynamic_cast<const TestOutbound*>(second_owner.get())->Generation() != 2) {
        co_return 14;
    }

    co_await manager.Clear();
    if (manager.GetHandler("fallback") || fallback_stops != 1) co_return 15;
    co_return 0;
}

}  // namespace

int main() {
    acpp::net::io_context io_context;
    auto result = acpp::net::co_spawn(
        io_context, RunTest(io_context.get_executor()), acpp::net::use_future);
    io_context.run();
    try {
        return result.get();
    } catch (...) {
        return 100;
    }
}
