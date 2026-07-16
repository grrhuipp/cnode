#include "acppnode/app/proxyman/outbound/manager.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <memory>
#include <string>
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

}  // namespace

int main() {
    acpp::proxyman::outbound::Manager manager;

    auto first = std::make_unique<TestOutbound>("direct", 1);
    auto* first_raw = first.get();
    if (manager.AddHandler(std::move(first)) != first_raw) return 1;
    if (manager.GetHandler("direct") != first_raw) return 2;
    if (manager.GetDefaultHandler() != first_raw) return 3;

    if (manager.ReplaceHandler(nullptr) != nullptr) return 4;
    if (manager.GetHandler("direct") != first_raw) return 5;

    auto second = std::make_unique<TestOutbound>("direct", 2);
    auto* second_raw = second.get();
    if (manager.ReplaceHandler(std::move(second)) != second_raw) return 6;
    if (manager.GetHandler("direct") != second_raw) return 7;
    if (manager.GetDefaultHandler() != second_raw) return 8;
    if (static_cast<TestOutbound*>(manager.GetHandler("direct"))->Generation() != 2) return 9;

    manager.DrainRetiredHandlers();
    if (manager.GetHandler("direct") != second_raw) return 10;

    return 0;
}
