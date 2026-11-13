#include <gtest/gtest.h>

#include "app/inbound_handler.hpp"
#include "app/relay.hpp"
#include "app/outbound_handler.hpp"
#include "app/dns.hpp"
#include "common/session.hpp"
#include "app/stats.hpp"
#include "infra/config_types.hpp"
#include "proxy/outbound.hpp"
#include "common/awaitable_task_group.hpp"

#include <asio/co_spawn.hpp>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace {

using ::app::OutboundHandlerRegistry;
using ::app::PreparedOutboundConfig;

struct Probe {
    int created = 0;
    int destroyed = 0;
    int processed = 0;
    ::transport::OutboundDialer* last_dialer = nullptr;
};

class CountingOutbound final : public ::proxy::Outbound {
public:
    explicit CountingOutbound(Probe& probe) : probe_(probe) { ++probe_.created; }
    ~CountingOutbound() noexcept override { ++probe_.destroyed; }

    ::net::awaitable<::proxy::OutboundProcessResult> Process(
        ::common::Context&, ::transport::Link, ::transport::OutboundDialer& dialer,
        const ::infra::TimeoutsConfig&, ::app::StatsShard&, const ::app::RelayConfig&,
        ::common::MultiBufferBatch) override {
        ++probe_.processed;
        probe_.last_dialer = &dialer;
        co_return ::app::RelayResult{};
    }

private:
    Probe& probe_;
};

PreparedOutboundConfig MakeConfig(std::string tag, Probe& probe) {
    return PreparedOutboundConfig{
        .tag = std::move(tag),
        .protocol = "test-counting",
        .sender = {},
        .create = ::app::MakePreparedOutboundCreator<
            Probe*,
            +[](std::string_view, std::shared_ptr<Probe* const> probe,
                ::net::io_context&, ::common::AwaitableTaskGroup&)
                -> std::unique_ptr<::proxy::Outbound> {
                return std::make_unique<CountingOutbound>(**probe);
            }>(&probe),
    };
}

class HandlerRegistryTest : public ::testing::Test {
protected:
    ::net::io_context io;
    ::app::DNSWorker dns_worker{
        io, ::app::DnsConfig{
            .servers = {{::net::ip::address_v4::loopback(), 9}}}, 8};
    ::app::DNS dns{dns_worker};
    ::common::ResidentTaskGroup tasks{io.get_executor()};
    Probe first_probe;
    Probe second_probe;
    OutboundHandlerRegistry registry{{MakeConfig("direct", first_probe)}, io, dns,
                             std::chrono::seconds(1), tasks.Tasks()};

    void TearDown() override {
        bool joined = false;
        auto cleanup = [&]() -> ::net::awaitable<void> {
            co_await tasks.AsyncJoin();
            co_await dns_worker.AsyncJoin();
        };
        ::net::co_spawn(io, cleanup(), [&](std::exception_ptr error) {
            EXPECT_FALSE(error);
            joined = true;
        });
        io.restart();
        io.run();
        EXPECT_TRUE(joined);
    }
};

TEST_F(HandlerRegistryTest, LookupReturnsPublishedHandlerAndRejectsUnknownTags) {
    auto first = registry.GetHandler("direct");
    ASSERT_TRUE(first);
    EXPECT_EQ(registry.GetHandler("direct"), first);
    EXPECT_FALSE(registry.GetHandler(""));
    EXPECT_FALSE(registry.GetHandler("missing"));
}

TEST_F(HandlerRegistryTest, DispatchReachesPublishedProtocol) {
    auto first = registry.GetHandler("direct");
    ASSERT_TRUE(first);
    ::common::Context ctx;
    ::infra::TimeoutsConfig timeouts;
    ::app::StatsShard stats;
    ::app::RelayConfig relay;
    bool completed = false;
    ::net::co_spawn(io,
        first->Dispatch(ctx, ::transport::Link{}, timeouts, stats, relay, {}),
        [&](std::exception_ptr error, ::proxy::OutboundProcessResult result) {
            EXPECT_FALSE(error);
            EXPECT_TRUE(result.has_value());
            completed = true;
        });
    io.run();
    EXPECT_TRUE(completed);
    EXPECT_EQ(first_probe.processed, 1);
    EXPECT_NE(first_probe.last_dialer, nullptr);
}

TEST_F(HandlerRegistryTest, RejectedReplacementPreservesPublishedHandler) {
    auto first = registry.GetHandler("direct");
    PreparedOutboundConfig missing_creator;
    missing_creator.tag = "direct";
    EXPECT_THROW(registry.Replace(missing_creator), std::logic_error);
    EXPECT_EQ(registry.GetHandler("direct"), first);
}

TEST_F(HandlerRegistryTest, ReplacementKeepsExistingRequestAliveUntilReleased) {
    auto first = registry.GetHandler("direct");
    ASSERT_TRUE(first);
    registry.Replace(MakeConfig("direct", second_probe));
    auto second = registry.GetHandler("direct");
    ASSERT_TRUE(second);
    EXPECT_NE(second, first);
    EXPECT_EQ(first_probe.destroyed, 0);
    first.reset();
    EXPECT_EQ(first_probe.destroyed, 1);
}

TEST_F(HandlerRegistryTest, RemovalKeepsExistingRequestAliveUntilReleased) {
    auto request = registry.GetHandler("direct");
    ASSERT_TRUE(request);
    registry.Remove("direct");
    EXPECT_FALSE(registry.GetHandler("direct"));
    EXPECT_EQ(first_probe.destroyed, 0);
    request.reset();
    EXPECT_EQ(first_probe.destroyed, 1);
}

TEST_F(HandlerRegistryTest, DuplicateTagsReleaseAllUnpublishedHandlers) {
    Probe probe;
    EXPECT_THROW(
        (OutboundHandlerRegistry({MakeConfig("same", probe), MakeConfig("same", probe)},
                         io, dns, std::chrono::seconds(1), tasks.Tasks())),
        std::logic_error);
    EXPECT_EQ(probe.destroyed, probe.created);
}

}  // namespace
