#include <gtest/gtest.h>

#include "app/inbound_handler.hpp"
#include "app/relay.hpp"
#include "app/request_load.hpp"
#include "app/rate_limiter.hpp"
#include "app/connection_limiter_core.hpp"
#include "app/group_coordinator.hpp"
#include "common/session.hpp"
#include "transport/transport_stack.hpp"
#include "proxy/inbound_admission.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

// 接受的 TCP 连接在传输握手期间的准入：经生产 InboundHandler 执行，只替换外部
// 传输构建器，以便在握手进行中观察全进程配额表。

namespace {

using Reason = app::ConnectionLimiter::RejectReason;
using Scope = app::ConnectionLimiter::ReservationScope;
constexpr std::string_view kSourceIp = "192.0.2.1";
constexpr std::string_view kForwardedIp = "198.51.100.7";

template<class Scenario>
void RunFixture(const app::RateLimitConfig& config, Scenario scenario) {
    net::io_context io;
    auto coordinator = std::make_shared<app::GroupCoordinator>(io);
    coordinator->RegisterWorker();
    auto limiter = app::ConnectionLimiter::Acquire(config, coordinator);
    app::UserOnlineTracker tracker(*coordinator);
    app::StatsShard stats;
    const app::AdmissionEnvironment environment{*coordinator, *limiter, tracker, stats};
    bool finalized = false;
    bool expired = false;
    std::exception_ptr failure;
    net::cancellation_signal cancellation;
    net::steady_timer watchdog(io, std::chrono::seconds(5));
    watchdog.async_wait([&](IoErrorCode error) {
        if (!error) {
            expired = true;
            cancellation.emit(net::cancellation_type::all);
        }
    });
    auto run = [&]() -> net::awaitable<void> {
        try {
            co_await scenario(io, environment);
        } catch (...) {
            failure = std::current_exception();
        }
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        co_await net::post(io, net::use_awaitable);
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
        limiter.reset();
        finalized = true;
    };
    net::co_spawn(io, run(), net::bind_cancellation_slot(cancellation.slot(),
        [&](std::exception_ptr error) {
            if (error) failure = error;
            watchdog.cancel();
        }));
    io.run();
    EXPECT_FALSE(expired) << "admission fixture exceeded its completion deadline";
    EXPECT_FALSE(failure) << "an exception escaped the accepted-connection boundary";
    EXPECT_TRUE(finalized);
}

class Stream final : public transport::AsyncStream {
public:
    net::awaitable<size_t> AsyncRead(net::mutable_buffer) override { co_return 0; }
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer>) override { co_return; }
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override { co_return common::MultiBuffer{}; }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override { NotifyClosed(); }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }
};

// 传输构建与协议准备阶段的脚本；协程只在测试执行器上运行。
struct Script {
    std::function<net::awaitable<void>()> during_build;
    std::function<net::awaitable<void>(common::Context&)> on_prepare;
    std::string real_ip;
    int children = 0;
    bool throw_in_build = false;
    int prepared = 0;
    app::ConnectionLimiter* limiter = nullptr;
};
Script* script = nullptr;

class ScriptedProxy final : public proxy::Inbound {
public:
    explicit ScriptedProxy(const app::AdmissionEnvironment& environment)
        : Inbound(std::in_place_type<ScriptedProxy>), environment_(environment) {}
    struct Session {
        Session() = default;
        Session(const Session&) = delete;
        Session(Session&&) = delete;
        net::awaitable<tl::expected<proxy::AuthenticatedInbound, common::ErrorCode>>
        Authenticate(transport::AsyncStream&, proxy::InboundAuthentication authentication,
                     proxy::InboundContext&) {
            co_return std::move(authentication).Bind(common::UserProfile{}, std::nullopt);
        }
        net::awaitable<proxy::InboundPrepared> Prepare(
            std::unique_ptr<transport::AsyncStream>& stream, proxy::InboundContext& context) {
            ++script->prepared;
            if (script->on_prepare) co_await script->on_prepare(context.session);
            co_return routing::DispatchRequest{std::move(stream)};
        }
    };
    const app::AdmissionEnvironment& Environment() const noexcept { return environment_; }
    auto SessionArguments() const noexcept { return std::tuple{}; }
private:
    const app::AdmissionEnvironment& environment_;
};

class Dispatcher final : public routing::Dispatcher {
    net::awaitable<app::RelayResult> Dispatch(net::io_context&, const routing::DispatchPolicy&,
        routing::DispatchRequest, common::Context&,
        app::StatsShard&, const infra::TimeoutsConfig&) override { co_return app::RelayResult{}; }
};

net::awaitable<Reason> ReserveClientIp(app::ConnectionLimiter& limiter, std::string_view ip,
                                       std::vector<app::ConnectionLimiter::Reservation>* held = nullptr) {
    auto pending = limiter.TryReserve({.scope = Scope::ClientIp, .tag = "test", .ip = ip});
    EXPECT_TRUE(pending);
    if (!pending) co_return Reason::NONE;
    auto admission = co_await std::move(*pending);
    if (held && admission.reason == Reason::NONE) held->push_back(std::move(admission.reservation));
    co_return admission.reason;
}

transport::StreamSettings Network(transport::NetworkMode mode) {
    transport::StreamSettings settings;
    settings.network_mode = mode;
    return transport::NormalizeStreamSettings(settings);
}

void RunAccepted(const app::RateLimitConfig& config, transport::StreamSettings settings, Script& current,
                 std::function<net::awaitable<void>(const app::AdmissionEnvironment&)> after = {}) {
    script = &current;
    current.limiter = nullptr;
    RunFixture(config, [&](net::io_context& io, const app::AdmissionEnvironment& environment)
        -> net::awaitable<void> {
        current.limiter = &environment.limiter;
        app::ReceiverSettings receiver{
            .inbound_tag = "test", .inbound_tags = {}, .protocol = "fixture",
            .stream_settings = std::move(settings),
            .dispatch_policy = {{}, routing::ForceOutbound{"direct"}},
            .proxy_protocol = transport::ProxyProtocolMode::Off};
        auto handler = std::make_shared<app::InboundHandler>(
            std::move(receiver), std::make_unique<ScriptedProxy>(environment), environment);
        Dispatcher dispatcher;
        app::RequestLoadState load(100, 0);
        infra::TimeoutsConfig timeouts;
        common::Context context;
        context.conn_id = 1;
        context.inbound.tag = "test";
        context.inbound.source_ip = kSourceIp;
        co_await handler->ProcessAcceptedTCP(io, dispatcher, environment.stats, load, timeouts,
            std::make_unique<Stream>(), context);
        if (after) co_await after(environment);
    });
    script = nullptr;
}

// 握手结束后按 IP 额度必须全部归还：同一地址恰好还能占用 limit 个槽位。
net::awaitable<void> ExpectIpQuotaRestored(app::ConnectionLimiter& limiter, std::string_view ip, uint32_t limit) {
    std::vector<app::ConnectionLimiter::Reservation> held;
    for (uint32_t i = 0; i < limit; ++i) EXPECT_EQ(co_await ReserveClientIp(limiter, ip, &held), Reason::NONE);
    EXPECT_EQ(co_await ReserveClientIp(limiter, ip), Reason::MAX_CONNECTIONS_PER_IP);
}

class PreHandshakeSourceIpQuota : public testing::TestWithParam<transport::NetworkMode> {};

// 客户端地址在握手前已确定的传输：沉默的握手期连接必须已经占用来源 IP 的额度。
TEST_P(PreHandshakeSourceIpQuota, SilentHandshakeOccupiesTheSourceAddress) {
    Script current;
    bool observed = false;
    current.during_build = [&]() -> net::awaitable<void> {
        EXPECT_EQ(co_await ReserveClientIp(*current.limiter, kSourceIp), Reason::MAX_CONNECTIONS_PER_IP);
        EXPECT_EQ(co_await ReserveClientIp(*current.limiter, kForwardedIp), Reason::NONE);
        observed = true;
    };
    current.children = GetParam() == transport::NetworkMode::Grpc ? 1 : 0;
    // 物理连接与其首个同地址子流共用一个按 IP 额度，不重复计数。
    current.on_prepare = [&](common::Context& context) -> net::awaitable<void> {
        EXPECT_EQ(std::string_view(context.inbound.source_ip), kSourceIp);
        EXPECT_EQ(co_await ReserveClientIp(*current.limiter, kSourceIp), Reason::MAX_CONNECTIONS_PER_IP);
    };
    RunAccepted({.max_conn_per_ip = 1}, Network(GetParam()), current,
        [](const app::AdmissionEnvironment& environment) -> net::awaitable<void> {
            co_await ExpectIpQuotaRestored(environment.limiter, kSourceIp, 1);
            EXPECT_EQ(environment.stats.errors, 0);
        });
    EXPECT_TRUE(observed);
    EXPECT_EQ(current.prepared, 1);
}

INSTANTIATE_TEST_SUITE_P(FinalClientAddress, PreHandshakeSourceIpQuota,
    testing::Values(transport::NetworkMode::Tcp, transport::NetworkMode::HttpUpgrade,
                    transport::NetworkMode::Grpc),
    [](const testing::TestParamInfo<transport::NetworkMode>& info) {
        switch (info.param) {
            case transport::NetworkMode::Tcp: return std::string("Raw");
            case transport::NetworkMode::HttpUpgrade: return std::string("HttpUpgradeWithoutRealIpHeader");
            default: return std::string("GrpcChild");
        }
    });

// 配置了真实 IP 头的传输：socket 地址是可信前置代理，握手期间不占用其额度，
// 握手后连接按转发地址计数；该额度同样是族底座，首个同地址子流沿用。
TEST(InboundTransportAdmission, ForwardedAddressOwnsTheQuotaAfterTheHandshake) {
    Script current;
    current.real_ip = kForwardedIp;
    current.during_build = [&]() -> net::awaitable<void> {
        std::vector<app::ConnectionLimiter::Reservation> held;
        EXPECT_EQ(co_await ReserveClientIp(*current.limiter, kSourceIp, &held), Reason::NONE);
    };
    current.on_prepare = [&](common::Context& context) -> net::awaitable<void> {
        EXPECT_EQ(std::string_view(context.inbound.source_ip), kForwardedIp);
        EXPECT_EQ(co_await ReserveClientIp(*current.limiter, kForwardedIp), Reason::MAX_CONNECTIONS_PER_IP);
        auto child = current.limiter->TryReserve({.scope = Scope::Logical,
            .family = context.inbound.connection_family, .tag = "test", .ip = kForwardedIp});
        EXPECT_TRUE(child);
        if (child) {
            auto first = co_await std::move(*child);
            EXPECT_EQ(first.reason, Reason::NONE);
            auto extra = current.limiter->TryReserve({.scope = Scope::Logical,
                .family = context.inbound.connection_family, .tag = "test", .ip = kForwardedIp});
            EXPECT_TRUE(extra);
            if (extra) EXPECT_EQ((co_await std::move(*extra)).reason, Reason::MAX_CONNECTIONS_PER_IP);
        }
        std::vector<app::ConnectionLimiter::Reservation> held;
        EXPECT_EQ(co_await ReserveClientIp(*current.limiter, kSourceIp, &held), Reason::NONE);
    };
    RunAccepted({.max_conn_per_ip = 1}, Network(transport::NetworkMode::Ws), current,
        [](const app::AdmissionEnvironment& environment) -> net::awaitable<void> {
            co_await ExpectIpQuotaRestored(environment.limiter, kForwardedIp, 1);
            co_await ExpectIpQuotaRestored(environment.limiter, kSourceIp, 1);
        });
    EXPECT_EQ(current.prepared, 1);
}

// 传输构建逃逸的异常与协议处理异常同样只计一次错误，并归还全部额度。
TEST(InboundTransportAdmission, EscapedTransportFailureIsCountedAndReleasesQuota) {
    Script current;
    current.throw_in_build = true;
    bool checked = false;
    RunAccepted({.max_connections = 1, .max_conn_per_ip = 1}, Network(transport::NetworkMode::Tcp), current,
        [&](const app::AdmissionEnvironment& environment) -> net::awaitable<void> {
            EXPECT_EQ(environment.stats.errors, 1);
            co_await ExpectIpQuotaRestored(environment.limiter, kSourceIp, 1);
            auto pending = environment.limiter.TryReserve({.scope = Scope::Physical});
            EXPECT_TRUE(pending);
            if (!pending) co_return;
            auto admitted = co_await std::move(*pending);
            EXPECT_EQ(admitted.reason, Reason::NONE);
            checked = true;
        });
    EXPECT_TRUE(checked);
    EXPECT_EQ(current.prepared, 0);
}

// 同一起始槽位上的 kProbe + 1 个地址：前 kProbe 个占满探测窗口。
std::vector<std::string> CollidingAddresses(size_t count) {
    using Core = app::ConnectionLimiterCore;
    std::unordered_map<size_t, std::vector<std::string>> buckets;
    for (uint32_t value = 0;; ++value) {
        auto address = "10." + std::to_string((value >> 16) & 255) + "." +
                       std::to_string((value >> 8) & 255) + "." + std::to_string(value & 255);
        auto& bucket = buckets[Core::IpHash(address) & (Core::kSlotCount - 1)];
        bucket.push_back(std::move(address));
        if (bucket.size() == count) return bucket;
    }
}

// 跟踪表探测窗口已满时，新地址照常放行（不计入按 IP 额度），且其归还不得
// 扣减之后为同一地址建立的真实槽位。
TEST(InboundTransportAdmission, UntrackedAddressIsAdmittedAndNeverReleasesATrackedSlot) {
    const auto colliding = CollidingAddresses(app::ConnectionLimiterCore::kProbe + 1);
    RunFixture({.max_conn_per_ip = 1}, [&](net::io_context&, const app::AdmissionEnvironment& environment)
        -> net::awaitable<void> {
        auto& limiter = environment.limiter;
        std::vector<app::ConnectionLimiter::Reservation> window;
        for (size_t i = 0; i + 1 < colliding.size(); ++i)
            EXPECT_EQ(co_await ReserveClientIp(limiter, colliding[i], &window), Reason::NONE);
        const std::string_view overflow = colliding.back();
        std::vector<app::ConnectionLimiter::Reservation> untracked;
        EXPECT_EQ(co_await ReserveClientIp(limiter, overflow, &untracked), Reason::NONE);
        EXPECT_EQ(co_await ReserveClientIp(limiter, overflow, &untracked), Reason::NONE);
        window.erase(window.begin());
        std::vector<app::ConnectionLimiter::Reservation> tracked;
        EXPECT_EQ(co_await ReserveClientIp(limiter, overflow, &tracked), Reason::NONE);
        EXPECT_EQ(co_await ReserveClientIp(limiter, overflow), Reason::MAX_CONNECTIONS_PER_IP);
        untracked.clear();
        EXPECT_EQ(co_await ReserveClientIp(limiter, overflow), Reason::MAX_CONNECTIONS_PER_IP);
        tracked.clear();
        co_await ExpectIpQuotaRestored(limiter, overflow, 1);
    });
}

// 物理连接的按 IP 底座：首个同地址子流沿用，其余子流各加一份；物理连接先
// 退出时底座移交给仍在运行的子流，最后一个持有者退出才归还。
TEST(InboundTransportAdmission, PhysicalSourceIpFloorIsSharedAndTransferredToChildren) {
    RunFixture({.max_conn_per_ip = 2}, [](net::io_context&, const app::AdmissionEnvironment& environment)
        -> net::awaitable<void> {
        auto& limiter = environment.limiter;
        auto pending = limiter.TryReserve({.scope = Scope::PhysicalClientIp, .tag = "test", .ip = kSourceIp});
        EXPECT_TRUE(pending);
        if (!pending) co_return;
        auto physical = co_await std::move(*pending);
        EXPECT_EQ(physical.reason, Reason::NONE);
        const auto family = physical.reservation.FamilyLease();
        EXPECT_TRUE(family);
        auto reserve_child = [&]() -> net::awaitable<app::ConnectionLimiter::Admission> {
            auto request = limiter.TryReserve({
                .scope = Scope::Logical, .family = family, .tag = "test", .ip = kSourceIp});
            EXPECT_TRUE(request);
            if (!request) co_return app::ConnectionLimiter::Admission{};
            co_return co_await std::move(*request);
        };
        auto first = co_await reserve_child();
        EXPECT_EQ(first.reason, Reason::NONE);
        auto second = co_await reserve_child();
        EXPECT_EQ(second.reason, Reason::NONE);
        EXPECT_EQ((co_await reserve_child()).reason, Reason::MAX_CONNECTIONS_PER_IP);
        physical.reservation = {};
        EXPECT_EQ(co_await ReserveClientIp(limiter, kSourceIp), Reason::MAX_CONNECTIONS_PER_IP);
        first.reservation = {};
        {
            std::vector<app::ConnectionLimiter::Reservation> held;
            EXPECT_EQ(co_await ReserveClientIp(limiter, kSourceIp, &held), Reason::NONE);
            EXPECT_EQ(co_await ReserveClientIp(limiter, kSourceIp), Reason::MAX_CONNECTIONS_PER_IP);
        }
        second.reservation = {};
        co_await ExpectIpQuotaRestored(limiter, kSourceIp, 2);
    });
}

}  // namespace

// Replace the external transport builder; the PROXY protocol reader is unused.
net::awaitable<transport::TransportBuildResult> transport::BuildInboundTransport(app::GroupCoordinator&, net::io_context&,
    std::unique_ptr<transport::AsyncStream> raw, const transport::StreamSettings&, transport::SslContext*, uint64_t,
    std::shared_ptr<transport::InboundTransportStreamHandler> streams, transport::InboundTransportMetadata* metadata,
    const transport::InboundFallbackContext*) {
    auto& current = *script;
    if (current.during_build) co_await current.during_build();
    if (current.throw_in_build) throw std::runtime_error("transport-build-failure");
    if (streams) {
        streams->OnInboundTransportReady(*raw);
        for (int child = 0; child < current.children; ++child)
            co_await streams->OnInboundTransportStream(std::make_unique<Stream>(), {});
        co_return std::unique_ptr<transport::AsyncStream>{};
    }
    if (metadata) metadata->real_ip = current.real_ip;
    co_return raw;
}
net::awaitable<transport::ProxyProtocolReadResult> transport::ReadInboundProxyProtocol(transport::AsyncStream&, std::chrono::seconds) {
    throw std::logic_error("unexpected proxy protocol"); co_return transport::ProxyProtocolReadResult{};
}
