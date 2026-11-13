#include <gtest/gtest.h>

#include "proxy/anytls/anytls_codec.hpp"
#include "app/relay.hpp"
#include "app/inbound_handler.hpp"
#include "app/user_store.hpp"
#include "app/stats.hpp"
#include "app/group_coordinator.hpp"
#include "common/user_online_tracker.hpp"
#include "common/allocator.hpp"
#include "common/mux_codec.hpp"
#include "proxy/mux/mux_server.hpp"
#include "common/session.hpp"
#include "routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <chrono>
#include <cstring>
#include <optional>
#include <utility>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
using namespace std::chrono_literals;

size_t BufferCount() noexcept { return common::test_buffers_live; }
size_t BufferPeak() noexcept { return common::test_buffers_peak; }

template <typename Cleanup>
class CleanupGuard {
public:
    explicit CleanupGuard(Cleanup cleanup) : cleanup_(std::move(cleanup)) {}
    ~CleanupGuard() { cleanup_(); }
private:
    Cleanup cleanup_;
};

// Setup and teardown use the same allocation lease as protocol callbacks.
// The coordinator stays alive until domain services and reserved returns drain.
class DomainFixture {
    using UserStore = app::UserStore;

public:
    explicit DomainFixture(net::io_context& io)
        : io_(io),
          coordinator_(std::make_shared<app::GroupCoordinator>(io)) {
        UserStore::ClearWorkerView();
        coordinator_->RegisterWorker();
        limiter_ = app::ConnectionLimiter::Acquire({}, coordinator_);
    }
    ~DomainFixture() {
        Shutdown();
        users_.reset();
        UserStore::ClearWorkerView();
    }
    net::any_io_executor Executor() { return io_.get_executor(); }
    app::GroupCoordinator& Coordinator() noexcept { return *coordinator_; }
    app::ConnectionLimiter& Limiter() noexcept { return *limiter_; }

    void InstallUsers(std::span<const UserStore::UserUpdate> updates) {
        auto snapshot = UserStore::PrepareUsers(updates);
        auto view = UserStore::PrepareWorkerView(snapshot);
        UserStore::CommitSnapshot(std::move(snapshot));
        users_ = view;
        UserStore::InstallWorkerView(std::move(view));
    }

    void Shutdown() {
        if (!coordinator_) return;
        coordinator_->CloseAdmission();
        std::exception_ptr failure;
        bool joined = false;
        net::co_spawn(io_, [this]() -> net::awaitable<void> {
            co_await coordinator_->AsyncJoin();
            coordinator_->ReleaseServices();
            co_await coordinator_->Finalize();
        }, [&](std::exception_ptr error) { failure = error; joined = true; });
        io_.restart();
        io_.run();
        EXPECT_TRUE(joined);
        EXPECT_FALSE(failure);
        EXPECT_TRUE(io_.stopped());
        limiter_.reset();
        coordinator_.reset();
    }

private:
    net::io_context& io_;
    UserStore::WorkerView users_;
    std::shared_ptr<app::GroupCoordinator> coordinator_;
    std::shared_ptr<app::ConnectionLimiter> limiter_;
};

void Frame(std::vector<uint8_t>& out, uint8_t command, uint32_t sid,
           std::span<const uint8_t> payload = {}) {
    out.insert(out.end(), {command, uint8_t(sid >> 24), uint8_t(sid >> 16),
        uint8_t(sid >> 8), uint8_t(sid), uint8_t(payload.size() >> 8), uint8_t(payload.size())});
    out.insert(out.end(), payload.begin(), payload.end());
}

struct StreamState {
    explicit StreamState(net::io_context& io) : wake(io), write_wake(io) {}
    net::steady_timer wake;
    net::steady_timer write_wake;
    std::vector<uint8_t> input;
    std::vector<uint8_t> output;
    size_t offset = 0;
    bool closed = false;
    bool destroyed = false;
    int pending_reads = 0;
    int pending_writes = 0;
    bool block_writes = false;
    IoErrorCode write_failure;
    bool partial_synack = false;
    int synack_fault = 0;
    int synack_faults = 0;
    bool delayed_write_cleanup = false;
    bool stall_payload = false;
    bool fail_syn_read = false;
    void FeedInvalidFrame(bool mux) {
        if (mux) input.insert(input.end(), {0, 3, 0, 1, 2, 0});
        else Frame(input, 99, 0);
        wake.cancel();
    }
};

class Stream final : public transport::AsyncStream {
public:
    explicit Stream(StreamState& state) : state_(state) {}
    ~Stream() override { state_.destroyed = true; }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer output) override {
        while (state_.offset == state_.input.size() && !state_.closed) {
            state_.wake.expires_at(net::steady_timer::time_point::max());
            ++state_.pending_reads;
            auto [error] = co_await state_.wake.async_wait(net::as_tuple(net::use_awaitable));
            --state_.pending_reads;
            if (error && state_.offset == state_.input.size() && !state_.closed)
                throw IoSystemError(error);
        }
        if (state_.closed) co_return 0;
        const size_t count = std::min(output.size(), state_.input.size() - state_.offset);
        std::memcpy(output.data(), state_.input.data() + state_.offset, count);
        state_.offset += count;
        if (state_.stall_payload && count == 7 && static_cast<const uint8_t*>(output.data())[0] == 2) {
            state_.stall_payload = false;
            std::this_thread::sleep_for(1100ms); // Ready I/O and an overdue timer now compete on one Worker.
        }
        // Model allocation failure while reading a new SYN with established children live.
        if (state_.fail_syn_read && count == 7 &&
            static_cast<const uint8_t*>(output.data())[0] == 1) {
            state_.fail_syn_read = false;
            throw std::bad_alloc();
        }
        co_return count;
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer data) override {
        const auto* bytes = static_cast<const uint8_t*>(data.data());
        if (state_.synack_fault != 0 && data.size() == 7 && bytes[0] == 7) {
            ++state_.synack_faults;
            state_.output.insert(state_.output.end(), bytes, bytes + 3);
            if (state_.synack_fault == 1) throw std::bad_alloc();
            if (state_.synack_fault == 2) throw transport::LinkError(common::ErrorCode::BLOCKED);
            throw std::runtime_error("physical SYNACK exception");
        }
        const bool partial_synack = state_.partial_synack && data.size() == 7 && bytes[0] == 7;
        if (partial_synack) state_.output.insert(state_.output.end(), bytes, bytes + 3);
        if (state_.block_writes || partial_synack) {
            state_.write_wake.expires_at(net::steady_timer::time_point::max());
            ++state_.pending_writes;
            auto [error] = co_await state_.write_wake.async_wait(net::as_tuple(net::use_awaitable));
            --state_.pending_writes;
            if (state_.write_failure) throw IoSystemError(state_.write_failure);
            if (error && (state_.block_writes || partial_synack)) {
                if (state_.delayed_write_cleanup) {
                    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
                    net::steady_timer cleanup(co_await net::this_coro::executor);
                    cleanup.expires_after(20ms);
                    co_await cleanup.async_wait(net::use_awaitable);
                }
                throw IoSystemError(error);
            }
        }
        state_.output.insert(state_.output.end(), bytes, bytes + data.size());
        co_return data.size();
    }
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        std::array<uint8_t, 8192> data{};
        const auto count = co_await AsyncRead(net::buffer(data));
        common::MultiBuffer result;
        if (count && !result.AppendSpan(std::span(data).first(count)))
            throw std::bad_alloc();
        co_return result;
    }
    void ShutdownWrite() override {}
    void Cancel() noexcept override {
        NotifyCancellation(); state_.wake.cancel(); state_.write_wake.cancel();
    }
    void Close() override {
        state_.closed = true; NotifyClosed(); state_.wake.cancel(); state_.write_wake.cancel();
    }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return !state_.closed; }
private:
    StreamState& state_;
};

class Dispatcher final : public routing::Dispatcher {
public:
    explicit Dispatcher(net::io_context& io) : gate(io) {
        gate.expires_at(net::steady_timer::time_point::max());
    }
    net::steady_timer gate;
    int active = 0;
    int finished = 0;
    int attempting_writes = 0;
    bool write_payload = false;
    struct Observation {
        common::Context* context;
        uint64_t conn_id;
        uint16_t port;
        bool active = true;
    };
    std::vector<Observation> observations;
    int overlapping_contexts = 0;
    int changed_contexts = 0;
    net::awaitable<app::RelayResult> Dispatch(net::io_context& io,
        const routing::DispatchPolicy&, std::unique_ptr<transport::AsyncStream>, transport::Link link,
        common::InitialPayload, common::Context& ctx, app::StatsShard&, const infra::TimeoutsConfig&) override {
        struct Scope {
            Dispatcher& owner;
            size_t index;
            Scope(Dispatcher& d, common::Context& ctx) : owner(d), index(d.observations.size()) {
                for (const auto& observation : d.observations)
                    if (observation.active && observation.context == &ctx) ++d.overlapping_contexts;
                d.observations.push_back({&ctx, ctx.conn_id, ctx.outbound.target.port});
                ++owner.active;
            }
            ~Scope() {
                const auto& record = owner.observations[index];
                if (record.context->conn_id != record.conn_id || record.context->outbound.target.port != record.port)
                    ++owner.changed_contexts;
                owner.observations[index].active = false;
                --owner.active; ++owner.finished;
            }
        } scope(*this, ctx);
        EXPECT_EQ(ctx.content.network, common::Network::TCP);
        // Model DNS/dial work before relay subscribes to the logical source.
        (void)co_await gate.async_wait(net::as_tuple(net::use_awaitable));
        if (write_payload) {
            ++attempting_writes;
            constexpr std::array<uint8_t, 3> payload{1, 2, 3};
            std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
            try { co_await link.writer->WriteBuffers(buffers); }
            catch (const IoSystemError&) {}
        }
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        net::steady_timer cleanup(io);
        cleanup.expires_after(20ms);
        co_await cleanup.async_wait(net::use_awaitable);
        co_return app::RelayResult{};
    }
};

net::awaitable<app::RelayResult> RunMux(std::unique_ptr<transport::AsyncStream> stream,
    routing::Dispatcher& dispatcher, const app::ReceiverSettings& receiver,
    net::io_context& io, const app::AdmissionEnvironment& environment,
    common::Context& context, app::StatsShard& stats, const infra::TimeoutsConfig& timeouts) {
    co_return co_await proxy::ServeMuxInbound(io, {stream.get(), stream.get(), stream.get()},
        *stream, dispatcher, receiver.dispatch_policy, environment, context, stats, timeouts, 0);
}

void RunCase(int mode, bool blocked_writes, bool mux) {
    net::io_context io;
    DomainFixture domain(io);
    StreamState stream(io);
    const auto hash = proxy::HashAnyTlsPassword("lifecycle-test");
    stream.input.assign(hash.begin(), hash.end());
    stream.input.insert(stream.input.end(), {0, 0});
    constexpr std::array<uint8_t, 3> settings{'v', '=', '2'};
    Frame(stream.input, 4, 0, settings);
    constexpr std::array<uint8_t, 7> target{1, 127, 0, 0, 1, 0, 80};
    for (uint32_t sid = 1; sid <= 2; ++sid) {
        Frame(stream.input, 1, sid);
        Frame(stream.input, 2, sid, target);
    }
    if (mux) {
        stream.input.clear();
        for (uint8_t sid = 1; sid <= 2; ++sid) {
            stream.input.insert(stream.input.end(), {0, 12, 0, sid, 1, 0, 1, 0, 80, 1, 127, 0, 0, 1});
        }
    }
    using namespace app;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    user.profile.user_id = 1;
    user.profile.email = "lifecycle@test";
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"lifecycle", users}};
    domain.InstallUsers(updates);
    std::weak_ptr<const UserStore::AnyTlsCredential> old_table =
        UserStore::FindAnyTlsUser("lifecycle", hash);
    common::UserOnlineTracker tracker(domain.Coordinator());
    app::StatsShard stats;
    const AdmissionEnvironment environment{
        domain.Coordinator(), domain.Limiter(), tracker, stats};
    proxy::AnyTlsInboundHandler handler(environment, {});
    Dispatcher dispatcher(io);
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    common::Context context;
    context.inbound.tag = "lifecycle";
    context.inbound.source_ip = "127.0.0.1";
    infra::TimeoutsConfig timeouts;
    net::cancellation_signal cancellation;
    bool returned = false;
    int active_at_return = -1;
    int finished_at_return = -1;
    std::exception_ptr failure;
    common::ErrorCode returned_error = common::ErrorCode::INTERNAL;
    auto request = mux
        ? RunMux(std::make_unique<Stream>(stream), dispatcher, receiver, io, environment, context, stats, timeouts)
        : handler.Process(std::make_unique<Stream>(stream), dispatcher, receiver, io, context, timeouts, 0);
    CleanupGuard cleanup([&] {
        cancellation.emit(net::cancellation_type::all);
        stream.closed = true;
        stream.wake.cancel();
        stream.write_wake.cancel();
        dispatcher.gate.cancel();
        io.restart();
        // A device reservation starts the coordinator's persistent return pump.
        // Join the request before shutting that pump down; io.run() alone cannot drain it.
        while (!returned) io.run_one();
        domain.Shutdown();
    });
    net::co_spawn(domain.Executor(), std::move(request),
        net::bind_cancellation_slot(cancellation.slot(), [&](std::exception_ptr error, app::RelayResult result) {
            returned = true;
            active_at_return = dispatcher.active;
            finished_at_return = dispatcher.finished;
            failure = error;
            returned_error = result.error;
        }));
    io.poll();
    {
        EXPECT_EQ(dispatcher.active, 2);
        EXPECT_EQ(stream.pending_reads, 1);
    }
    if (!mux) {
        EXPECT_FALSE(old_table.expired());
        domain.InstallUsers(updates);
        EXPECT_TRUE(old_table.expired());
        {
            EXPECT_EQ(context.inbound.user_id, 1);
            EXPECT_EQ(context.inbound.user_email, "lifecycle@test");
        }
    }
    if (blocked_writes) {
        stream.block_writes = true;
        dispatcher.write_payload = true;
        dispatcher.gate.cancel();
        io.poll();
        {
            EXPECT_EQ(dispatcher.attempting_writes, 2);
            EXPECT_EQ(stream.pending_writes, 1);
        }
    }
    if (mode == 0) cancellation.emit(net::cancellation_type::terminal);
    else if (mode == 1) stream.FeedInvalidFrame(mux);
    else if (mode == 2) { stream.closed = true; stream.wake.cancel(); }
    else if (mode == 4) {
        // Fail the already-started physical write before session retirement.
        stream.write_failure = io_error::connection_reset;
        stream.write_wake.cancel();
    } else {
        Frame(stream.input, 1, 3);
        stream.fail_syn_read = true;
        stream.wake.cancel();
    }
    io.run_for(500ms);
    EXPECT_TRUE(returned);
    EXPECT_EQ(active_at_return, 0);
    EXPECT_EQ(finished_at_return, 2);
    EXPECT_TRUE(stream.destroyed);
    EXPECT_EQ(stream.pending_reads, 0);
    EXPECT_EQ(stream.pending_writes, 0);
    // Drain fixture work while every borrowed request object remains alive.
    dispatcher.gate.cancel();
    io.restart();
    io.run_for(1s);
    EXPECT_EQ(dispatcher.active, 0);
    {
        EXPECT_EQ(tracker.OnlineDeviceCount("lifecycle", 1), 0);
        if (mode == 0) {
            {
                EXPECT_FALSE(failure);
                EXPECT_EQ(returned_error, common::ErrorCode::CANCELLED);
            }
        } else if (mode == 3) {
            {
                EXPECT_FALSE(failure);
                EXPECT_EQ(returned_error, common::ErrorCode::RESOURCE_EXHAUSTED);
            }
        } else if (mode == 4) {
            EXPECT_FALSE(failure);
            EXPECT_EQ(returned_error, common::ErrorCode::SOCKET_CLOSED);
        } else {
            const auto expected = mode == 1
                ? (mux ? common::ErrorCode::PROTOCOL_DECODE_FAILED : common::ErrorCode::PROTOCOL_INVALID_COMMAND) : common::ErrorCode::OK;
            {
                EXPECT_FALSE(failure);
                EXPECT_EQ(returned_error, expected);
            }
        }
    }
}
bool HasAlert(const std::vector<uint8_t>& bytes) {
    for (size_t offset = 0; offset + 7 <= bytes.size();) {
        const size_t size = (size_t(bytes[offset + 5]) << 8) | bytes[offset + 6];
        if (offset + 7 + size > bytes.size()) return false;
        if (bytes[offset] == 5 && size != 0) return true;
        offset += 7 + size;
    }
    return false;
}

bool HasFrame(const std::vector<uint8_t>& bytes, uint8_t command, uint32_t sid) {
    for (size_t offset = 0; offset + 7 <= bytes.size();) {
        const size_t size = (size_t(bytes[offset + 5]) << 8) | bytes[offset + 6];
        if (offset + 7 + size > bytes.size()) return false;
        const uint32_t frame_sid = (uint32_t(bytes[offset + 1]) << 24) |
            (uint32_t(bytes[offset + 2]) << 16) | (uint32_t(bytes[offset + 3]) << 8) | bytes[offset + 4];
        if (bytes[offset] == command && frame_sid == sid) return true;
        offset += 7 + size;
    }
    return false;
}

void RunHandshakeCase(int mode) {
    net::io_context io;
    DomainFixture domain(io);
    StreamState stream(io);
    const auto hash = proxy::HashAnyTlsPassword("handshake-test");
    stream.input.assign(hash.begin(), hash.end());
    stream.input.insert(stream.input.end(), {0, 0});
    constexpr std::array<uint8_t, 3> settings{'v', '=', '2'};
    constexpr std::array<uint8_t, 7> target{1, 127, 0, 0, 1, 0, 80};
    Frame(stream.input, 4, 0, settings);
    for (uint32_t sid = 1; sid <= (mode == 3 ? 129u : 1u); ++sid) {
        Frame(stream.input, 1, sid);
        if (mode != 3) Frame(stream.input, 2, sid, target);
    }
    using namespace app;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"handshake", users}};
    domain.InstallUsers(updates);
    common::UserOnlineTracker tracker(domain.Coordinator());
    app::StatsShard stats;
    const AdmissionEnvironment environment{
        domain.Coordinator(), domain.Limiter(), tracker, stats};
    proxy::AnyTlsInboundHandler handler(environment, {});
    Dispatcher dispatcher(io);
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    common::Context context;
    context.inbound.tag = "handshake";
    infra::TimeoutsConfig timeouts;
    timeouts.handshake = 1;
    stream.partial_synack = mode < 2;
    stream.delayed_write_cleanup = mode < 2;
    stream.stall_payload = mode == 4;
    stream.synack_fault = mode >= 5 ? mode - 4 : 0;
    net::cancellation_signal cancellation;
    bool returned = false;
    int active_at_return = -1;
    std::exception_ptr failure;
    common::ErrorCode returned_error = common::ErrorCode::OK;
    CleanupGuard cleanup([&] {
        cancellation.emit(net::cancellation_type::all);
        stream.closed = true;
        stream.wake.cancel();
        stream.write_wake.cancel();
        dispatcher.gate.cancel();
        io.restart();
        while (!returned) io.run_one();
        domain.Shutdown();
    });
    net::co_spawn(domain.Executor(), handler.Process(std::make_unique<Stream>(stream), dispatcher,
        receiver, io, context, timeouts, 0), net::bind_cancellation_slot(cancellation.slot(),
        [&](std::exception_ptr error, app::RelayResult result) {
            failure = error;
            returned_error = result.error;
            returned = true;
            active_at_return = dispatcher.active;
        }));
    io.poll();
    if (mode >= 5) {
        EXPECT_EQ(stream.synack_faults, 1);
        EXPECT_FALSE(failure);
        EXPECT_EQ(returned_error, mode == 5 ? common::ErrorCode::RESOURCE_EXHAUSTED :
            mode == 6 ? common::ErrorCode::BLOCKED : common::ErrorCode::INTERNAL);
        EXPECT_TRUE(returned);
        EXPECT_TRUE(stream.closed);
        EXPECT_TRUE(stream.destroyed);
        EXPECT_EQ(active_at_return, 0);
        EXPECT_EQ(stream.pending_reads, 0);
        EXPECT_EQ(stream.pending_writes, 0);
        return;
    }
    {
        EXPECT_FALSE(returned);
        EXPECT_EQ(stream.pending_reads, 1);
    }
    if (mode < 2) {
        {
            EXPECT_EQ(stream.pending_writes, 1);
            EXPECT_EQ(dispatcher.active, 0);
            EXPECT_FALSE(HasFrame(stream.output, 7, 1));
        }
        if (mode == 1) {
            cancellation.emit(net::cancellation_type::terminal);
            io.poll();
            {
                EXPECT_FALSE(returned);
                EXPECT_FALSE(stream.destroyed);
            }
        }
        io.run_for(mode == 0 ? 1200ms : 100ms);
        {
            EXPECT_TRUE(returned);
            EXPECT_TRUE(stream.closed);
            EXPECT_FALSE(HasFrame(stream.output, 3, 1));
        }
    } else if (mode == 2) {
        EXPECT_EQ(dispatcher.active, 1);
        stream.block_writes = true;
        dispatcher.write_payload = true;
        dispatcher.gate.cancel();
        io.poll();
        EXPECT_EQ(stream.pending_writes, 1);
        Frame(stream.input, 1, 2);
        Frame(stream.input, 2, 2, target);
        stream.wake.cancel();
        io.run_for(1150ms);
        {
            EXPECT_FALSE(returned);
            EXPECT_FALSE(stream.closed);
            EXPECT_EQ(dispatcher.active, 1);
            EXPECT_EQ(stream.pending_writes, 1);
        }
        stream.block_writes = false;
        stream.write_wake.cancel();
        io.run_for(100ms);
        {
            EXPECT_FALSE(stream.closed);
            EXPECT_EQ(dispatcher.finished, 1);
            EXPECT_TRUE(HasFrame(stream.output, 3, 2));
            EXPECT_FALSE(HasFrame(stream.output, 7, 2));
        }
        stream.FeedInvalidFrame(false);
        io.run_for(100ms);
    } else if (mode == 3) {
        {
            EXPECT_EQ(dispatcher.active, 0);
            EXPECT_TRUE(HasFrame(stream.output, 7, 129));
            EXPECT_TRUE(HasFrame(stream.output, 3, 129));
        }
        Frame(stream.input, 1, 129);
        stream.wake.cancel();
        io.run_for(100ms);
        {
            EXPECT_TRUE(returned);
            EXPECT_TRUE(HasAlert(stream.output));
        }
    } else {
        io.run_for(100ms);
        {
            EXPECT_EQ(dispatcher.active, 0);
            EXPECT_EQ(dispatcher.finished, 0);
            EXPECT_TRUE(HasFrame(stream.output, 3, 1));
        }
        stream.FeedInvalidFrame(false);
        io.run_for(100ms);
    }
    {
        EXPECT_TRUE(returned);
        EXPECT_EQ(active_at_return, 0);
        EXPECT_TRUE(stream.destroyed);
        EXPECT_EQ(stream.pending_reads, 0);
        EXPECT_EQ(stream.pending_writes, 0);
    }
    io.restart();
    io.run_for(1100ms); // A removed deadline must not retain pending work or touch dead stream state.
}

void RunIdentityCase(int mode) {
    net::io_context io;
    DomainFixture domain(io);
    StreamState stream(io);
    const auto hash = proxy::HashAnyTlsPassword("identity-test");
    stream.input.assign(hash.begin(), hash.end());
    stream.input.insert(stream.input.end(), {0, 0});
    constexpr std::array<uint8_t, 3> settings{'v', '=', '2'};
    Frame(stream.input, 4, 0, settings);
    const uint32_t first_sid = mode == 6 ? UINT32_MAX : 7;
    constexpr std::array<uint8_t, 7> target{1, 127, 0, 0, 1, 0, 80};
    constexpr std::array<uint8_t, 7> changed_target{1, 127, 0, 0, 1, 0, 81};
    Frame(stream.input, 1, first_sid);
    const bool pending = mode == 1 || mode == 8;
    if (!pending) Frame(stream.input, 2, first_sid, target);
    using namespace app;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"identity", users}};
    domain.InstallUsers(updates);
    common::UserOnlineTracker tracker(domain.Coordinator());
    app::StatsShard stats;
    const AdmissionEnvironment environment{
        domain.Coordinator(), domain.Limiter(), tracker, stats};
    proxy::AnyTlsInboundHandler handler(environment, {});
    Dispatcher dispatcher(io);
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    common::Context context;
    context.inbound.tag = "identity";
    context.inbound.source_ip = "127.0.0.1";
    infra::TimeoutsConfig timeouts;
    net::cancellation_signal cancellation;
    bool returned = false;
    common::ErrorCode result_error = common::ErrorCode::INTERNAL;
    std::exception_ptr failure;
    CleanupGuard cleanup([&] {
        cancellation.emit(net::cancellation_type::all);
        stream.closed = true;
        stream.wake.cancel();
        stream.write_wake.cancel();
        dispatcher.gate.cancel();
        io.restart();
        while (!returned) io.run_one();
        domain.Shutdown();
    });
    net::co_spawn(domain.Executor(), handler.Process(std::make_unique<Stream>(stream), dispatcher,
        receiver, io, context, timeouts, 0), net::bind_cancellation_slot(cancellation.slot(), [&](std::exception_ptr error, app::RelayResult result) {
            returned = true;
            failure = error;
            result_error = result.error;
        }));
    io.poll();
    {
        EXPECT_EQ(dispatcher.active, (pending ? 0 : 1));
        EXPECT_EQ(stream.pending_reads, 1);
    }
    if (mode == 2) {
        dispatcher.gate.cancel();
        io.run_for(50ms);
        {
            EXPECT_EQ(dispatcher.finished, 1);
            EXPECT_FALSE(returned);
        }
    }
    if (mode == 9) {
        constexpr std::array<uint8_t, 32> payload{};
        Frame(stream.input, 2, first_sid, payload);
        // Keep only the frame header: the payload bytes arrive later.
        stream.input.erase(stream.input.end() - static_cast<std::ptrdiff_t>(payload.size()),
                           stream.input.end());
        stream.wake.cancel();
        io.poll();
        {
            EXPECT_EQ(stream.pending_reads, 1);
            EXPECT_EQ(dispatcher.active, 1);
        }
        dispatcher.gate.cancel();
        io.run_for(50ms);
        {
            EXPECT_EQ(dispatcher.finished, 1);
            EXPECT_FALSE(returned);
        }
        stream.input.insert(stream.input.end(), payload.begin(), payload.end());
        Frame(stream.input, 1, 19);
        Frame(stream.input, 2, 19, changed_target);
    } else if (mode == 8) {
        Frame(stream.input, 3, first_sid);
        Frame(stream.input, 2, first_sid, changed_target);
    } else {
        const uint32_t sid = mode == 3 ? 6 : mode == 4 ? 0 : mode == 6 ? 1 : (mode == 5 || mode == 7) ? 19 : first_sid;
        constexpr std::array<uint8_t, 1> forbidden_payload{0};
        Frame(stream.input, 1, sid, mode == 5 ? std::span<const uint8_t>(forbidden_payload) : std::span<const uint8_t>{});
        Frame(stream.input, 2, sid, changed_target);
    }
    stream.wake.cancel();
    io.run_for(100ms);
    const size_t started = dispatcher.observations.size();
    const bool rejected = returned && !failure && result_error == common::ErrorCode::PROTOCOL_INVALID_COMMAND && HasAlert(stream.output);
    if (!returned) stream.FeedInvalidFrame(false);
    io.run_for(500ms);
    {
        EXPECT_TRUE(returned);
        EXPECT_EQ(dispatcher.active, 0);
        EXPECT_TRUE(stream.destroyed);
    }
    const size_t expected = (mode == 7 || mode == 9) ? 2 : pending ? 0 : 1;
    {
        EXPECT_EQ(started, expected);
        EXPECT_EQ(dispatcher.overlapping_contexts, 0);
        EXPECT_EQ(dispatcher.changed_contexts, 0);
    }
    if (mode < 7) EXPECT_TRUE(rejected);
}
class ParsingDispatcher final : public routing::Dispatcher {
public:
    std::vector<uint8_t> bytes;
    std::string host;
    int calls = 0;
    net::awaitable<app::RelayResult> Dispatch(net::io_context&,
        const routing::DispatchPolicy&, std::unique_ptr<transport::AsyncStream>, transport::Link link,
        common::InitialPayload first, common::Context& ctx, app::StatsShard&, const infra::TimeoutsConfig&) override {
        ++calls;
        host = ctx.outbound.target.host;
        auto data = std::move(first).MoveToMultiBuffer();
        while (bytes.size() < 60000) {
            for (const auto* buffer : data) {
                if (buffer) bytes.insert(bytes.end(), buffer->Bytes().begin(), buffer->Bytes().end());
            }
            if (bytes.size() >= 60000) break;
            data = co_await link.reader->ReadMultiBuffer();
            if (data.byte_size() == 0) break;
        }
        co_return app::RelayResult{};
    }
};

void RunParsingCase(int mode) {
    net::io_context io;
    DomainFixture execution(io);
    StreamState stream(io);
    const auto hash = proxy::HashAnyTlsPassword("parsing-test");
    stream.input.assign(hash.begin(), hash.end());
    stream.input.insert(stream.input.end(), {0, 0});
    constexpr std::array<uint8_t, 3> settings{'v', '=', '2'};
    Frame(stream.input, 4, 0, settings);
    Frame(stream.input, 1, 1);
    std::vector<uint8_t> target{1, 127, 0, 0, 1, 0, 80};
    const std::string domain = std::string(63, 'a') + '.' + std::string(63, 'b') + '.' +
        std::string(63, 'c') + '.' + std::string(61, 'd');
    if (mode == 2) { target.assign(19, 0); target[0] = 4; target[16] = 1; target[18] = 80; }
    else if (mode == 3) {
        target = {3, uint8_t(domain.size())}; target.insert(target.end(), domain.begin(), domain.end());
        target.insert(target.end(), {0, 80});
    } else if (mode == 4) target = {255};
    else if (mode == 5) target = {3, 0, 0, 80};
    else if (mode == 6) target.back() = 0;
    else if (mode == 7 || mode == 8) target.resize(2);
    else if (mode == 9) { target.assign(259, 'x'); target[0] = 3; target[1] = 255; target[257] = 0; target[258] = 80; }
    else if (mode == 10) {
        constexpr std::string_view magic = "sp.v2.udp-over-tcp.arpa";
        target = {3, uint8_t(magic.size())};
        target.insert(target.end(), magic.begin(), magic.end());
        target.insert(target.end(), {0, 0, 2}); // UoT connect flag must be 0 or 1.
    }
    std::vector<uint8_t> expected(60000);
    for (size_t i = 0; i < expected.size(); ++i) expected[i] = uint8_t(i % 251);
    if (mode == 0) {
        target.insert(target.end(), expected.begin(), expected.end());
        Frame(stream.input, 2, 1, target);
    } else {
        for (const auto byte : target) {
            Frame(stream.input, 2, 1, std::span(&byte, 1));
            Frame(stream.input, 2, 1); // Empty PSH is not logical EOF.
        }
        if (mode < 4) Frame(stream.input, 2, 1, expected);
        if (mode == 7) Frame(stream.input, 3, 1);
    }
    using namespace app;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"parsing", users}};
    execution.InstallUsers(updates);
    common::UserOnlineTracker tracker(execution.Coordinator());
    app::StatsShard stats;
    const AdmissionEnvironment environment{
        execution.Coordinator(), execution.Limiter(), tracker, stats};
    proxy::AnyTlsInboundHandler handler(environment, {});
    ParsingDispatcher dispatcher;
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    common::Context context;
    context.inbound.tag = "parsing";
    infra::TimeoutsConfig timeouts;
    net::cancellation_signal cancellation;
    bool returned = false;
    std::exception_ptr failure;
    common::ErrorCode result_error = common::ErrorCode::INTERNAL;
    CleanupGuard cleanup([&] {
        cancellation.emit(net::cancellation_type::all);
        stream.closed = true;
        stream.wake.cancel();
        stream.write_wake.cancel();
        io.restart();
        while (!returned) io.run_one();
        execution.Shutdown();
    });
    net::co_spawn(execution.Executor(), handler.Process(std::make_unique<Stream>(stream), dispatcher,
        receiver, io, context, timeouts, 0), net::bind_cancellation_slot(cancellation.slot(),
        [&](std::exception_ptr error, app::RelayResult result) {
            returned = true;
            failure = error;
            result_error = result.error;
        }));
    io.poll();
    {
        EXPECT_FALSE(returned);
        EXPECT_EQ(stream.pending_reads, 1);
    }
    if (mode < 4) {
        {
            EXPECT_EQ(dispatcher.calls, 1);
            EXPECT_EQ(dispatcher.bytes, expected);
        }
        if (mode == 3) EXPECT_EQ(dispatcher.host, domain);
    } else {
        EXPECT_EQ(dispatcher.calls, 0);
    }
    if (mode == 8) cancellation.emit(net::cancellation_type::terminal);
    else stream.FeedInvalidFrame(false);
    io.run_for(500ms);
    {
        EXPECT_TRUE(returned);
        EXPECT_TRUE(stream.destroyed);
        EXPECT_EQ(stream.pending_reads, 0);
        EXPECT_EQ(stream.pending_writes, 0);
    }
    if (mode == 8) {
        EXPECT_FALSE(failure);
        EXPECT_EQ(result_error, common::ErrorCode::CANCELLED);
    }
}
class QueueDispatcher final : public routing::Dispatcher {
public:
    explicit QueueDispatcher(net::io_context& io) : gate(io) {
        gate.expires_at(net::steady_timer::time_point::max());
    }
    net::steady_timer gate;
    bool consume = false;
    int active = 0;
    std::vector<uint8_t> received;
    net::awaitable<app::RelayResult> Dispatch(net::io_context& io,
        const routing::DispatchPolicy&, std::unique_ptr<transport::AsyncStream>, transport::Link link,
        common::InitialPayload first, common::Context&, app::StatsShard&, const infra::TimeoutsConfig&) override {
        ++active;
        (void)co_await gate.async_wait(net::as_tuple(net::use_awaitable));
        if (consume) {
            auto data = std::move(first).MoveToMultiBuffer();
            try {
                while (true) {
                    for (const auto* buffer : data) {
                        if (!buffer) continue;
                        received.insert(received.end(), buffer->Bytes().begin(), buffer->Bytes().end());
                    }
                    data.clear();
                    data = co_await link.reader->ReadMultiBuffer();
                    if (data.byte_size() == 0) break;
                }
            } catch (const IoSystemError&) {}
        }
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        net::steady_timer cleanup(io);
        cleanup.expires_after(20ms);
        co_await cleanup.async_wait(net::use_awaitable);
        --active;
        co_return app::RelayResult{};
    }
};

void RunQueueCase(int mode, uint32_t seed = 0) {
    net::io_context io;
    DomainFixture domain(io);
    StreamState stream(io);
    const auto hash = proxy::HashAnyTlsPassword("queue-test");
    stream.input.assign(hash.begin(), hash.end());
    stream.input.insert(stream.input.end(), {0, 0});
    constexpr std::array<uint8_t, 3> settings{'v', '=', '2'};
    constexpr std::array<uint8_t, 7> target{1, 127, 0, 0, 1, 0, 80};
    Frame(stream.input, 4, 0, settings);
    Frame(stream.input, 1, 1);
    Frame(stream.input, 2, 1, target);
    using namespace app;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"queue", users}};
    domain.InstallUsers(updates);
    common::UserOnlineTracker tracker(domain.Coordinator());
    app::StatsShard stats;
    const AdmissionEnvironment environment{
        domain.Coordinator(), domain.Limiter(), tracker, stats};
    proxy::AnyTlsInboundHandler handler(environment, {});
    QueueDispatcher dispatcher(io);
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    common::Context context;
    context.inbound.tag = "queue";
    infra::TimeoutsConfig timeouts;
    net::cancellation_signal cancellation;
    bool returned = false;
    int active_at_return = -1;
    EXPECT_EQ(BufferCount(), 0);
    const auto previous_peak = common::test_buffers_peak;
    CleanupGuard restore_peak([&] { common::test_buffers_peak = previous_peak; });
    common::test_buffers_peak = 0;
    CleanupGuard cleanup([&] {
        cancellation.emit(net::cancellation_type::all);
        stream.closed = true;
        stream.wake.cancel();
        stream.write_wake.cancel();
        dispatcher.gate.cancel();
        io.restart();
        while (!returned) io.run_one();
        domain.Shutdown();
    });
    net::co_spawn(domain.Executor(), handler.Process(std::make_unique<Stream>(stream), dispatcher,
        receiver, io, context, timeouts, 0), net::bind_cancellation_slot(cancellation.slot(),
        [&](std::exception_ptr, app::RelayResult) {
            returned = true; active_at_return = dispatcher.active;
        }));
    io.poll();
    {
        EXPECT_EQ(dispatcher.active, 1);
        EXPECT_EQ(stream.pending_reads, 1);
    }
    std::vector<uint8_t> expected(mode == 0 ? 2048 : 65535);
    for (size_t i = 0; i < expected.size(); ++i) expected[i] = uint8_t(i % 251);
    size_t offset = 0;
    size_t fragments = 0;
    constexpr std::array<size_t, 7> boundaries{1, 4095, 4096, 4097, 8191, 8192, 3};
    uint32_t random = seed + 1;
    while (offset < expected.size()) {
        random ^= random << 13; random ^= random >> 17; random ^= random << 5;
        const size_t want = mode == 0 || mode == 6 ? 1 : mode == 2 ? (fragments % 2 == 0 ? 1 : 8192)
            : mode == 3 ? boundaries[fragments % boundaries.size()]
            : mode == 7 ? (random % 4 == 0 ? 1 : 1 + random % 8192) : 65535;
        const size_t count = std::min(want, expected.size() - offset);
        Frame(stream.input, 2, 1, std::span(expected).subspan(offset, count));
        offset += count;
        ++fragments;
    }
    stream.wake.cancel();
    io.poll();
    const size_t queued_blocks = BufferCount();
    const bool bounded = queued_blocks <= (expected.size() + 4095) / 4096;
    {
        EXPECT_EQ(stream.offset, stream.input.size());
        EXPECT_EQ(stream.pending_reads, 1);
    }
    if (mode == 4 || mode == 5) {
        Frame(stream.input, 2, 1, std::span(expected).first(1));
        stream.wake.cancel();
        io.poll();
        {
            EXPECT_EQ(stream.pending_reads, 0);
            EXPECT_EQ(dispatcher.active, 1);
        }
        expected.push_back(expected[0]);
    }
    if (mode == 5) {
        cancellation.emit(net::cancellation_type::terminal);
        io.poll();
        {
            EXPECT_FALSE(returned);
            EXPECT_FALSE(stream.destroyed);
        }
    } else {
        Frame(stream.input, 3, 1);
        dispatcher.consume = true;
        dispatcher.gate.cancel();
        stream.wake.cancel();
        io.run_for(100ms);
        {
            EXPECT_EQ(dispatcher.received, expected);
            EXPECT_EQ(dispatcher.active, 0);
        }
        stream.FeedInvalidFrame(false);
    }
    io.run_for(100ms);
    {
        EXPECT_TRUE(returned);
        EXPECT_EQ(active_at_return, 0);
        EXPECT_TRUE(stream.destroyed);
        EXPECT_EQ(stream.pending_reads, 0);
        EXPECT_EQ(stream.pending_writes, 0);
    }
    EXPECT_EQ(BufferCount(), 0);
    {
        EXPECT_TRUE(bounded);
        EXPECT_LE(BufferPeak(), 24);
    }
}

class MuxUdpDispatcher final : public routing::Dispatcher {
public:
    explicit MuxUdpDispatcher(net::io_context& io) : gate(io) {
        gate.expires_at(net::steady_timer::time_point::max());
    }
    struct Packet {
        common::TargetAddress target;
        std::vector<uint8_t> bytes;
    };
    net::steady_timer gate;
    bool pause = false;
    int active = 0;
    int finished = 0;
    bool input_eof = false;
    std::exception_ptr failure;
    std::vector<Packet> received;

    net::awaitable<app::RelayResult> Dispatch(net::io_context&,
        const routing::DispatchPolicy&, std::unique_ptr<transport::AsyncStream>, transport::Link link,
        common::InitialPayload, common::Context& ctx, app::StatsShard&, const infra::TimeoutsConfig&) override {
        struct Scope {
            MuxUdpDispatcher& owner;
            explicit Scope(MuxUdpDispatcher& value) : owner(value) { ++owner.active; }
            ~Scope() { --owner.active; ++owner.finished; }
        } scope(*this);
        try {
            EXPECT_EQ(ctx.content.network, common::Network::UDP);
            if (pause) (void)co_await gate.async_wait(net::as_tuple(net::use_awaitable));
            for (;;) {
                auto packet = co_await link.reader->ReadMultiBuffer();
                if (packet.empty()) {
                    input_eof = true;
                    break;
                }
                const auto datagram = common::InspectUdpDatagram(packet);
                EXPECT_TRUE(datagram.Valid());
                if (!datagram.Valid()) co_return app::RelayResult{};
                Packet observation{*datagram.target, {}};
                for (const auto* buffer : packet) {
                    const auto bytes = buffer->Bytes();
                    observation.bytes.insert(observation.bytes.end(), bytes.begin(), bytes.end());
                }
                received.push_back(std::move(observation));
                co_await link.writer->WriteMultiBuffer(std::move(packet));
            }
        } catch (...) {
            failure = std::current_exception();
            throw;
        }
        co_return app::RelayResult{};
    }
};

void RunMuxUdpCase(int mode) {
    net::io_context io;
    DomainFixture domain(io);
    StreamState stream(io);
    MuxUdpDispatcher dispatcher(io);
    dispatcher.pause = mode >= 2;
    app::StatsShard stats;
    common::UserOnlineTracker tracker(domain.Coordinator());
    const app::AdmissionEnvironment environment{
        domain.Coordinator(), domain.Limiter(), tracker, stats};
    app::ReceiverSettings receiver{
        .inbound_tag = {}, .inbound_tags = {}, .protocol = {}, .stream_settings = {},
        .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    common::Context context;
    context.inbound.tag = "mux-udp";
    infra::TimeoutsConfig timeouts;
    const common::TargetAddress target("127.0.0.1", 53);
    const common::TargetAddress changed("127.0.0.2", 5353);
    std::array<uint8_t, common::kMaxFrameHeaderBytes> header{};
    auto append = [&](size_t size) {
        EXPECT_NE(size, 0);
        stream.input.insert(stream.input.end(), header.begin(), header.begin() + size);
    };
    const size_t open_size = common::EncodeNewHeaderTo(
        header, 1, common::NetworkType::UDP, target, 0, mode == 1);
    append(open_size);
    std::vector<MuxUdpDispatcher::Packet> expected_packets;
    if (mode == 1) expected_packets.push_back({target, {}});
    bool returned = false;
    std::exception_ptr failure;
    net::cancellation_signal cancellation;
    EXPECT_EQ(BufferCount(), 0);
    CleanupGuard cleanup([&] {
        cancellation.emit(net::cancellation_type::all);
        stream.closed = true;
        stream.wake.cancel();
        stream.write_wake.cancel();
        dispatcher.gate.cancel();
        io.restart();
        while (!returned) io.run_one();
        domain.Shutdown();
    });
    net::co_spawn(domain.Executor(),
        RunMux(std::make_unique<Stream>(stream), dispatcher, receiver, io, environment, context, stats, timeouts),
        net::bind_cancellation_slot(cancellation.slot(),
            [&](std::exception_ptr error, app::RelayResult) { failure = error; returned = true; }));
    io.poll();
    {
        EXPECT_EQ(dispatcher.active, 1);
        EXPECT_EQ(dispatcher.received.size(), (mode == 1 ? 1u : 0u));
    }
    // Neither a no-Data KEEP nor a KEEPALIVE with Data is a UDP packet.
    stream.input.insert(stream.input.end(), {0, 4, 0, 1, 2, 0, 0, 4, 0, 1, 4, 1, 0, 0});
    const size_t count = mode >= 2 ? 1500 : 1;
    for (size_t i = 0; i < count; ++i) {
        append(common::EncodeKeepUDPHeaderTo(header, 1, changed, 0));
        expected_packets.push_back({changed, {}});
    }
    if (mode < 2) {
        append(common::EncodeKeepDataHeaderTo(header, 1, 1));
        stream.input.push_back(0x42);
        append(common::EncodeKeepDataHeaderTo(header, 1, 0));
        expected_packets.push_back({target, {0x42}});
        expected_packets.push_back({target, {}});
    }
    const bool end_has_data = mode != 2 && mode != 3;
    const bool end_empty = mode == 1 || mode == 4;
    if (end_has_data) {
        stream.input.insert(stream.input.end(), {0, 4, 0, 1, 3, 1, 0, uint8_t(end_empty ? 0 : 1)});
        if (!end_empty) stream.input.push_back(0xff);
        expected_packets.push_back({target, end_empty ? std::vector<uint8_t>{} : std::vector<uint8_t>{0xff}});
    } else {
        append(common::EncodeEndTo(header, 1));
    }
    stream.wake.cancel();
    io.poll();
    if (mode >= 2) {
        {
            EXPECT_TRUE(dispatcher.received.empty());
            EXPECT_EQ(dispatcher.active, 1);
        }
        EXPECT_LE(BufferCount(), 4 * 1024 * 1024 / common::Buffer::kSize + 32);
        if (mode == 3) {
            cancellation.emit(net::cancellation_type::terminal);
        } else {
            dispatcher.gate.cancel();
        }
        io.run_for(100ms);
    }
    if (mode != 3) {
        EXPECT_FALSE(dispatcher.failure);
        const size_t expected = expected_packets.size();
        {
            EXPECT_EQ(dispatcher.received.size(), expected);
            EXPECT_EQ(dispatcher.finished, 1);
            EXPECT_TRUE(dispatcher.input_eof);
        }
        for (size_t i = 0; i < std::min(expected, dispatcher.received.size()); ++i) {
            const auto& packet = dispatcher.received[i];
            {
                EXPECT_TRUE(packet.target.SameEndpoint(expected_packets[i].target));
                EXPECT_EQ(packet.bytes, expected_packets[i].bytes);
            }
        }
        common::MultiBuffer output;
        EXPECT_TRUE(output.AppendSpan(stream.output));
        size_t replies = 0;
        while (!output.empty()) {
            const auto frame = common::DecodeFrame(output);
            {
                EXPECT_TRUE(frame);
                if (!frame) break;
                EXPECT_NE(frame->frame_size, 0);
            }
            if (!frame || frame->frame_size == 0) break;
            if (frame->status == common::SessionStatus::KEEP) {
                {
                    EXPECT_TRUE(frame->has_data);
                    EXPECT_TRUE(frame->has_target);
                    EXPECT_LT(replies, dispatcher.received.size());
                }
                if (replies >= dispatcher.received.size()) break;
                const auto& packet = dispatcher.received[replies++];
                {
                    EXPECT_TRUE(frame->target.SameEndpoint(packet.target));
                    EXPECT_EQ(frame->data_len, packet.bytes.size());
                }
                output.DropPrefixBytes(frame->data_offset);
                std::vector<uint8_t> bytes(frame->data_len);
                {
                    EXPECT_EQ(output.CopyPrefixTo(bytes), bytes.size());
                    EXPECT_EQ(bytes, packet.bytes);
                }
                output.DropPrefixBytes(frame->data_len);
            } else {
                output.DropPrefixBytes(frame->frame_size);
            }
        }
        EXPECT_EQ(replies, expected);
        stream.FeedInvalidFrame(true);
        io.run_for(100ms);
    }
    if (mode == 3) {
        {
            EXPECT_TRUE(dispatcher.received.empty());
            EXPECT_FALSE(dispatcher.input_eof);
        }
    }
    {
        EXPECT_TRUE(returned);
        EXPECT_FALSE(failure);
        EXPECT_EQ(dispatcher.active, 0);
        EXPECT_EQ(stream.pending_reads, 0);
        EXPECT_EQ(stream.pending_writes, 0);
        EXPECT_TRUE(stream.destroyed);
    }
    EXPECT_EQ(BufferCount(), 0);
    domain.Shutdown();
}

}  // namespace

namespace {
struct ParentStopCase { int mode; bool blocked_writes; bool mux; const char* name; };
class SubstreamParentStop : public testing::TestWithParam<ParentStopCase> {};
TEST_P(SubstreamParentStop, JoinsChildrenAndReleasesAuthenticationLease) {
    const auto& value = GetParam();
    RunCase(value.mode, value.blocked_writes, value.mux);
}
INSTANTIATE_TEST_SUITE_P(TransportAndFailure, SubstreamParentStop, testing::Values(
    ParentStopCase{0, false, false, "AnyTlsCancellation"},
    ParentStopCase{1, false, false, "AnyTlsInvalidFrame"},
    ParentStopCase{2, false, false, "AnyTlsPhysicalEof"},
    ParentStopCase{3, false, false, "AnyTlsReadAllocationFailure"},
    ParentStopCase{0, true, false, "AnyTlsCancellationWithBlockedWrites"},
    ParentStopCase{1, true, false, "AnyTlsInvalidFrameWithBlockedWrites"},
    ParentStopCase{2, true, false, "AnyTlsPhysicalEofWithBlockedWrites"},
    ParentStopCase{3, true, false, "AnyTlsReadAllocationFailureWithBlockedWrites"},
    ParentStopCase{4, true, false, "AnyTlsPhysicalWriteFailureWithBlockedWrites"},
    ParentStopCase{0, false, true, "MuxCancellation"},
    ParentStopCase{1, false, true, "MuxInvalidFrame"},
    ParentStopCase{0, true, true, "MuxCancellationWithBlockedWrites"}),
    [](const auto& info) { return info.param.name; });
class AnyTlsHandshakeLifecycle : public testing::TestWithParam<int> {};
TEST_P(AnyTlsHandshakeLifecycle, JoinsPreparationWithoutCancellingEstablishedSiblings) { RunHandshakeCase(GetParam()); }
INSTANTIATE_TEST_SUITE_P(Behaviors, AnyTlsHandshakeLifecycle, testing::Range(0, 8),
    ([](const auto& info) {
        constexpr std::array names{"PartialSynackTimeout", "PartialSynackCancellation", "WriteGateTimeoutIsolation", "CapacityRejectedIdRetired", "OverdueReadyHeader", "SynackAllocationFailure", "SynackLinkFailure", "SynackUnexpectedFailure"};
        return names[info.param];
    }));
class AnyTlsStreamIdentity : public testing::TestWithParam<int> {};
TEST_P(AnyTlsStreamIdentity, PreservesIndependentContextsAndRejectsInvalidReuse) { RunIdentityCase(GetParam()); }
INSTANTIATE_TEST_SUITE_P(Behaviors, AnyTlsStreamIdentity, testing::Range(0, 10),
    ([](const auto& info) {
        constexpr std::array names{"DuplicateActive", "DuplicatePending", "ReuseCompleted", "Descending", "Zero", "SynPayload", "Wraparound", "ValidGap", "FinBeforeTarget", "PayloadAfterRetirement"};
        return names[info.param];
    }));
class AnyTlsTargetParsing : public testing::TestWithParam<int> {};
TEST_P(AnyTlsTargetParsing, DispatchesOnlyCompleteValidTargetsAndJoinsOnStop) { RunParsingCase(GetParam()); }
INSTANTIATE_TEST_SUITE_P(Behaviors, AnyTlsTargetParsing, testing::Range(0, 11),
    ([](const auto& info) {
        constexpr std::array names{"Coalesced", "FragmentedIpv4", "FragmentedIpv6", "MaximumDomain", "InvalidType", "EmptyDomain", "ZeroPort", "Truncated", "CancelPending", "OversizedDomain", "InvalidUotRequest"};
        return names[info.param];
    }));
class AnyTlsInboundQueue : public testing::TestWithParam<int> {};
TEST_P(AnyTlsInboundQueue, PreservesPayloadWithinCapacityAndReclaimsOnStop) { RunQueueCase(GetParam(), 0); }
INSTANTIATE_TEST_SUITE_P(Behaviors, AnyTlsInboundQueue, testing::Range(0, 7),
    ([](const auto& info) {
        constexpr std::array names{"TinyFragments", "WholeFrame", "SparseMixed", "BoundaryFragments", "ByteBudgetBackpressure", "CancelFullQueue", "MaximumTinyFragments"};
        return names[info.param];
    }));
class AnyTlsInboundQueueFragments : public testing::TestWithParam<uint32_t> {};
TEST_P(AnyTlsInboundQueueFragments, PreservesPayloadAcrossRandomFrameBoundaries) {
    RunQueueCase(7, GetParam());
}
INSTANTIATE_TEST_SUITE_P(Seeds, AnyTlsInboundQueueFragments, testing::Range(uint32_t{0}, uint32_t{16}));
class MuxUdpLifecycle : public testing::TestWithParam<int> {};
TEST_P(MuxUdpLifecycle, PreservesDatagramAndControlBoundariesAndReclaimsStorage) { RunMuxUdpCase(GetParam()); }
INSTANTIATE_TEST_SUITE_P(Behaviors, MuxUdpLifecycle, testing::Range(0, 6),
    ([](const auto& info) {
        constexpr std::array names{"EndPayload", "EmptyNewAndEndData", "DrainQueuedEmptyDatagrams", "CancelQueuedEmptyDatagrams", "EmptyEndData", "NonemptyEndData"};
        return names[info.param];
    }));
struct PeerVersion { std::string_view text; uint32_t version; };
class AnyTlsPeerVersion : public testing::TestWithParam<PeerVersion> {};
TEST_P(AnyTlsPeerVersion, ParsesExactVersionKeyWithoutNarrowing) {
    const auto& value = GetParam();
    const auto parsed = proxy::ParsePeerSettings(value.text);
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed->version, value.version >= 2 ? proxy::SessionVersion::V2 : proxy::SessionVersion::V1);
}
INSTANTIATE_TEST_SUITE_P(ValidSettings, AnyTlsPeerVersion, testing::Values(
PeerVersion{"", 1}, PeerVersion{"v=1", 1}, PeerVersion{"v=2", 2}, PeerVersion{"v=3", 3},
        PeerVersion{"v=20", 20}, PeerVersion{"v=256", 256}, PeerVersion{"v=4294967295", UINT32_MAX},
        PeerVersion{"v=02", 2}, PeerVersion{"v=2\r\nclient=test\r\n", 2},
        PeerVersion{"client=has-v=2\nnot-v=2", 1}, PeerVersion{"\n\r\nv=2\n", 2},
        PeerVersion{"padding-md5=v=2", 1}, PeerVersion{"client=x\nclient=y\nv=1", 1}));
class AnyTlsMalformedPeerSettings : public testing::TestWithParam<std::string_view> {};
TEST_P(AnyTlsMalformedPeerSettings, RejectsMalformedSettingsAtomically) {
    const auto parsed = proxy::ParsePeerSettings(GetParam());
    ASSERT_FALSE(parsed);
    EXPECT_EQ(parsed.error(), common::ErrorCode::PROTOCOL_DECODE_FAILED);
}
INSTANTIATE_TEST_SUITE_P(InvalidSettings, AnyTlsMalformedPeerSettings, testing::Values(
"v=", "v=0", "v=-1", "v=+2", "v= 2", "v=2 ",
        "v=2x", "v=1\nv=2", "v=2\nv=2", "v=4294967296", "v=9999999999999999999999",
        "v", "=2", "padding-md5=a\npadding-md5=b", "v=2\rx", std::string_view("v=2\0junk", 8)));
}  // namespace
