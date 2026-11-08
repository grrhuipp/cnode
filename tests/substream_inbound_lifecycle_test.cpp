#include <gtest/gtest.h>

#include "anytls_inbound.hpp"
#include "mux_inbound.hpp"
#include "../credentials.hpp"
#include "../anytls_codec.hpp"
#include "../padding.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/stats.hpp"
#include "app/session_group_executor.hpp"
#include "common/allocator.hpp"
#include "common/buffer_util.hpp"
#include "common/memory_stats.hpp"
#include "common/mux/mux_codec.hpp"
#include "common/session.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "transport/async_stream.hpp"
#include "transport/link_error.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <chrono>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
using namespace std::chrono_literals;

size_t BufferCount() noexcept { return memory::detail::test_buffers_live; }
size_t BufferPeak() noexcept { return memory::detail::test_buffers_peak; }

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

// Setup and teardown use the same allocation lease as protocol callbacks.
// The coordinator stays alive until domain services and reserved returns drain.
class DomainFixture {
    using UserStore = proxyman::inbound::UserStore;
    struct Hooks final : ExecutionDomain::Hooks {
        memory::AllocationDomain memory;
        std::optional<memory::ScopedAllocationDomain> allocation;
        UserStore::WorkerView users;
        UserStore::WorkerView previous_users;

        void Enter() noexcept override {
            allocation.emplace(memory);
            previous_users = UserStore::ExchangeWorkerView(users);
        }
        void Leave() noexcept override {
            users = UserStore::ExchangeWorkerView(std::move(previous_users));
            allocation.reset();
        }
        void OnFailure(std::exception_ptr) noexcept override { std::terminate(); }
    };

public:
    explicit DomainFixture(net::io_context& io)
        : io_(io), hooks_(std::make_shared<Hooks>()),
          previous_users_(UserStore::ExchangeWorkerView({})),
          coordinator_(std::make_shared<GroupCoordinator>(io)) {
        coordinator_->RegisterWorker(0, io, io.get_executor());
        domain_ = ExecutionDomain::Create(io, 0, io.get_executor(), hooks_, coordinator_);
        hooks_->memory.SetLeaseGroup(domain_->LeaseIdentity(), &ExecutionDomain::SharesLeaseIdentity);
    }
    ~DomainFixture() {
        Shutdown();
        memory::ScopedAllocationDomain allocation(hooks_->memory);
        hooks_->users.reset();
        UserStore::InstallWorkerView(std::move(previous_users_));
    }

    memory::AllocationDomain& Memory() noexcept { return hooks_->memory; }
    net::any_io_executor Executor() { return domain_->Executor(); }

    void InstallUsers(std::span<const UserStore::UserUpdate> updates) {
        auto snapshot = UserStore::PrepareUsers(updates);
        auto view = UserStore::PrepareWorkerView(snapshot);
        UserStore::CommitSnapshot(std::move(snapshot));
        hooks_->users = view;
        UserStore::InstallWorkerView(std::move(view));
    }

    void Shutdown() {
        if (!domain_) return;
        memory::ScopedAllocationDomain allocation(hooks_->memory);
        coordinator_->CloseAdmission();
        std::exception_ptr failure;
        bool joined = false;
        net::co_spawn(io_, [this]() -> net::awaitable<void> {
            co_await coordinator_->AsyncJoin();
            coordinator_->ReleaseServices();
            domain_.reset();
            co_await coordinator_->Finalize();
        }, [&](std::exception_ptr error) { failure = error; joined = true; });
        io_.restart();
        io_.poll();
        Check(joined && !failure && io_.stopped(),
              "coordinator must join controls, retire domains, and finalize returns without pending work");
    }

private:
    net::io_context& io_;
    std::shared_ptr<Hooks> hooks_;
    UserStore::WorkerView previous_users_;
    std::shared_ptr<GroupCoordinator> coordinator_;
    std::shared_ptr<ExecutionDomain> domain_;
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
    bool partial_synack = false;
    int synack_fault = 0;
    bool delayed_write_cleanup = false;
    bool stall_payload = false;
    bool record_payload_buffers = false;
    std::vector<const void*> payload_buffers;
    bool fail_syn_read = false;
    void FeedInvalidFrame(bool mux) {
        if (mux) input.insert(input.end(), {0, 3, 0, 1, 2, 0});
        else Frame(input, 99, 0);
        wake.cancel();
    }
};

class Stream final : public AsyncStream {
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
        if (state_.record_payload_buffers && count >= 4096) state_.payload_buffers.push_back(output.data());
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
            state_.output.insert(state_.output.end(), bytes, bytes + 3);
            if (state_.synack_fault == 1) throw std::bad_alloc();
            if (state_.synack_fault == 2) throw transport::LinkError(ErrorCode::BLOCKED);
            throw std::runtime_error("physical SYNACK exception");
        }
        const bool partial_synack = state_.partial_synack && data.size() == 7 && bytes[0] == 7;
        if (partial_synack) state_.output.insert(state_.output.end(), bytes, bytes + 3);
        if (state_.block_writes || partial_synack) {
            state_.write_wake.expires_at(net::steady_timer::time_point::max());
            ++state_.pending_writes;
            auto [error] = co_await state_.write_wake.async_wait(net::as_tuple(net::use_awaitable));
            --state_.pending_writes;
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
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        std::array<uint8_t, 8192> data{};
        const auto count = co_await AsyncRead(net::buffer(data));
        buf::MultiBuffer result;
        if (count && !buf::AppendSpanToMultiBuffer(std::span(data).first(count), result))
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
        session::Context* context;
        uint64_t conn_id;
        uint16_t port;
        bool active = true;
    };
    std::vector<Observation> observations;
    int overlapping_contexts = 0;
    int changed_contexts = 0;
    net::awaitable<RelayResult> Dispatch(net::io_context& io,
        const routing::DispatchPolicy&, std::unique_ptr<AsyncStream>, transport::Link link,
        InitialPayload, session::Context& ctx, StatsShard&, const TimeoutsConfig&) override {
        struct Scope {
            Dispatcher& owner;
            size_t index;
            Scope(Dispatcher& d, session::Context& ctx) : owner(d), index(d.observations.size()) {
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
        Check(ctx.content.network == Network::TCP, "child must enter the ordinary dispatcher");
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
        co_return RelayResult{};
    }
};

net::awaitable<RelayResult> RunMux(std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher, const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io, session::Context& context, StatsShard& stats, const TimeoutsConfig& timeouts) {
    co_return co_await mux::ProcessInbound(io, {stream.get(), stream.get(), stream.get()},
        *stream, dispatcher, receiver.dispatch_policy, nullptr, context, stats, timeouts, 0);
}

bool RunCase(int mode, bool baseline, bool blocked_writes = false, bool mux = false) {
    net::io_context io;
    DomainFixture domain(io);
    memory::ScopedAllocationDomain allocation(domain.Memory());
    StreamState stream(io);
    const auto hash = anytls::PasswordHash("lifecycle-test");
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
    using namespace proxyman::inbound;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    user.profile.user_id = 1;
    user.profile.email = "lifecycle@test";
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"lifecycle", users}};
    domain.InstallUsers(updates);
    std::weak_ptr<const UserStore::AnyTlsCredential> old_table =
        UserStore::FindAnyTlsUser("lifecycle", hash);
    UserOnlineTracker validator;
    StatsShard stats;
    proxy::anytls::inbound::Handler handler(validator, stats, {});
    Dispatcher dispatcher(io);
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    session::Context context;
    context.inbound.tag = "lifecycle";
    context.inbound.source_ip = "127.0.0.1";
    TimeoutsConfig timeouts;
    net::cancellation_signal cancellation;
    bool returned = false;
    int active_at_return = -1;
    int finished_at_return = -1;
    std::exception_ptr failure;
    ErrorCode returned_error = ErrorCode::INTERNAL;
    auto request = mux
        ? RunMux(std::make_unique<Stream>(stream), dispatcher, receiver, io, context, stats, timeouts)
        : handler.Process(std::make_unique<Stream>(stream), dispatcher, receiver, io, context, timeouts, 0);
    net::co_spawn(domain.Executor(), std::move(request),
        net::bind_cancellation_slot(cancellation.slot(), [&](std::exception_ptr error, RelayResult result) {
            returned = true;
            active_at_return = dispatcher.active;
            finished_at_return = dispatcher.finished;
            failure = error;
            returned_error = result.error;
        }));
    io.poll();
    Check(dispatcher.active == 2 && stream.pending_reads == 1, "both logical requests must be pending");
    if (!mux && !baseline) {
        Check(!old_table.expired(), "published snapshot must still own its users");
        domain.InstallUsers(updates);
        Check(old_table.expired(), "authenticated control transport must not retain the old user table");
        Check(context.inbound.user_id == 1 && context.inbound.user_email == "lifecycle@test",
              "session metadata must survive destruction of its authentication snapshot");
    }
    if (blocked_writes) {
        stream.block_writes = true;
        dispatcher.write_payload = true;
        dispatcher.gate.cancel();
        io.poll();
        Check(dispatcher.attempting_writes == 2 && stream.pending_writes == 1,
              "one child must hold the physical writer while another waits for its gate");
    }
    if (mode == 0) cancellation.emit(net::cancellation_type::terminal);
    else if (mode == 1) stream.FeedInvalidFrame(mux);
    else if (mode == 2) { stream.closed = true; stream.wake.cancel(); }
    else {
        Frame(stream.input, 1, 3);
        stream.fail_syn_read = true;
        stream.wake.cancel();
    }
    io.run_for(500ms);
    const bool joined = returned && dispatcher.active == 0 && finished_at_return == 2 &&
                        stream.destroyed && stream.pending_reads == 0 && stream.pending_writes == 0;
    constexpr std::array names{"parent-cancel", "session-failure", "physical-eof", "physical-read-allocation-failure"};
    std::cout << (mux ? "mux-" : "anytls-") << names[mode] << (blocked_writes ? "-blocked-writes" : "")
              << " returned=" << returned << " active-at-return=" << active_at_return
              << " finished-at-return=" << finished_at_return << " joined=" << joined << '\n';
    // Keep all borrowed fixtures alive even when observing the old unsafe path.
    dispatcher.gate.cancel();
    io.restart();
    io.run_for(1s);
    Check(dispatcher.active == 0, "fixture must join remaining old children");
    if (!baseline) {
        Check(joined, "container parent must cancel and join every dynamic request");
        Check(validator.OnlineDeviceCount("lifecycle", 1) == 0, "online lease must be released after join");
        if (mode == 0) {
            if (mux) Check(!failure && returned_error == ErrorCode::CANCELLED, "Mux cancellation must be reported");
            else {
                Check(bool(failure), "parent cancellation must be reported");
                try { std::rethrow_exception(failure); }
                catch (const IoSystemError& error) { Check(error.code() == io_error::operation_aborted, "cancel error changed"); }
            }
        } else if (mode == 3) {
            Check(bool(failure), "physical-read-allocation-failure must propagate the original exception");
            try { std::rethrow_exception(failure); }
            catch (const std::bad_alloc&) {}
        } else {
            const auto expected = mode == 1
                ? (mux ? ErrorCode::PROTOCOL_DECODE_FAILED : ErrorCode::PROTOCOL_INVALID_COMMAND) : ErrorCode::OK;
            Check(!failure && returned_error == expected,
                  "session result must survive companion cancellation");
        }
    }
    return joined;
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

void RunHandshakeCase(int mode, bool baseline = false) {
    constexpr std::array names{"partial-synack-timeout", "partial-synack-parent-cancel",
        "write-gate-timeout-isolation", "capacity-rejected-id-retired", "overdue-ready-header",
        "synack-memory-error", "synack-link-error", "synack-unexpected-error"};
    net::io_context io;
    DomainFixture domain(io);
    memory::ScopedAllocationDomain allocation(domain.Memory());
    StreamState stream(io);
    const auto hash = anytls::PasswordHash("handshake-test");
    stream.input.assign(hash.begin(), hash.end());
    stream.input.insert(stream.input.end(), {0, 0});
    constexpr std::array<uint8_t, 3> settings{'v', '=', '2'};
    constexpr std::array<uint8_t, 7> target{1, 127, 0, 0, 1, 0, 80};
    Frame(stream.input, 4, 0, settings);
    for (uint32_t sid = 1; sid <= (mode == 3 ? 129u : 1u); ++sid) {
        Frame(stream.input, 1, sid);
        if (mode != 3) Frame(stream.input, 2, sid, target);
    }
    using namespace proxyman::inbound;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"handshake", users}};
    domain.InstallUsers(updates);
    UserOnlineTracker validator;
    StatsShard stats;
    proxy::anytls::inbound::Handler handler(validator, stats, {});
    Dispatcher dispatcher(io);
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    session::Context context;
    context.inbound.tag = "handshake";
    TimeoutsConfig timeouts;
    timeouts.handshake = 1;
    stream.partial_synack = mode < 2;
    stream.delayed_write_cleanup = mode < 2;
    stream.stall_payload = mode == 4;
    stream.synack_fault = mode >= 5 ? mode - 4 : 0;
    net::cancellation_signal cancellation;
    bool returned = false;
    int active_at_return = -1;
    net::co_spawn(domain.Executor(), handler.Process(std::make_unique<Stream>(stream), dispatcher,
        receiver, io, context, timeouts, 0), net::bind_cancellation_slot(cancellation.slot(),
        [&](std::exception_ptr, RelayResult) {
            returned = true; active_at_return = dispatcher.active;
        }));
    io.poll();
    if (mode >= 5) {
        const bool passed = returned && stream.closed && stream.destroyed && active_at_return == 0 &&
            stream.pending_reads == 0 && stream.pending_writes == 0;
        std::cout << "handshake-" << names[mode]
                  << " joined=" << (returned && stream.destroyed) << " passed=" << passed << '\n';
        Check(baseline || passed, "physical frame failure must retain the owned logical context and original exception code");
        return;
    }
    Check(!returned && stream.pending_reads == 1, "session reader must remain live during stream preparation");
    if (mode < 2) {
        Check(stream.pending_writes == 1 && dispatcher.active == 0 && !HasFrame(stream.output, 7, 1),
              "SYNACK must be incomplete and still belong to handshake preparation");
        if (mode == 1) {
            cancellation.emit(net::cancellation_type::terminal);
            io.poll();
            Check(!returned && !stream.destroyed, "parent must wait for cancelled physical write cleanup");
        }
        io.run_for(mode == 0 ? 1200ms : 100ms);
        Check(returned && stream.closed && !HasFrame(stream.output, 3, 1),
              "an interrupted physical frame must abort the session before another frame is written");
    } else if (mode == 2) {
        Check(dispatcher.active == 1, "prepared stream must enter dispatcher");
        stream.block_writes = true;
        dispatcher.write_payload = true;
        dispatcher.gate.cancel();
        io.poll();
        Check(stream.pending_writes == 1, "established stream must own the physical write gate");
        Frame(stream.input, 1, 2);
        Frame(stream.input, 2, 2, target);
        stream.wake.cancel();
        io.run_for(1150ms);
        Check(!returned && !stream.closed && dispatcher.active == 1 && stream.pending_writes == 1,
              "a handshake waiting for the write gate must not cancel its established sibling");
        stream.block_writes = false;
        stream.write_wake.cancel();
        io.run_for(100ms);
        Check(!stream.closed && dispatcher.finished == 1 && HasFrame(stream.output, 3, 2) &&
              !HasFrame(stream.output, 7, 2), "only the expired logical stream must receive FIN after the gate releases");
        stream.FeedInvalidFrame(false);
        io.run_for(100ms);
    } else if (mode == 3) {
        Check(dispatcher.active == 0 && HasFrame(stream.output, 7, 129) && HasFrame(stream.output, 3, 129),
              "full session must reject the new stream before address dispatch");
        Frame(stream.input, 1, 129);
        stream.wake.cancel();
        io.run_for(100ms);
        Check(returned && HasAlert(stream.output), "a capacity-rejected ID must never be admitted on reuse");
    } else {
        io.run_for(100ms);
        Check(dispatcher.active == 0 && dispatcher.finished == 0 && HasFrame(stream.output, 3, 1),
              "a header ready after its absolute deadline must not dispatch before the timer callback");
        stream.FeedInvalidFrame(false);
        io.run_for(100ms);
    }
    Check(returned && active_at_return == 0 && stream.destroyed &&
          stream.pending_reads == 0 && stream.pending_writes == 0,
          "handshake children and physical writes must join before transport destruction");
    io.restart();
    io.run_for(1100ms); // A removed deadline must not retain pending work or touch dead stream state.
    domain.Shutdown();
    Check(io.stopped(), "joined handshakes must leave no live deadline work");
    std::cout << "handshake-" << names[mode] << " joined=1 passed=1\n";
}

void RunIdentityCase(int mode, bool baseline) {
    constexpr std::array names{"duplicate-active", "duplicate-pending", "reuse-completed",
        "descending", "zero", "syn-payload", "wraparound", "valid-gap", "fin-before-target", "payload-after-retirement"};
    net::io_context io;
    DomainFixture domain(io);
    memory::ScopedAllocationDomain allocation(domain.Memory());
    StreamState stream(io);
    const auto hash = anytls::PasswordHash("identity-test");
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
    using namespace proxyman::inbound;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"identity", users}};
    domain.InstallUsers(updates);
    UserOnlineTracker validator;
    StatsShard stats;
    proxy::anytls::inbound::Handler handler(validator, stats, {});
    Dispatcher dispatcher(io);
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    session::Context context;
    context.inbound.tag = "identity";
    context.inbound.source_ip = "127.0.0.1";
    TimeoutsConfig timeouts;
    bool returned = false;
    ErrorCode result_error = ErrorCode::INTERNAL;
    std::exception_ptr failure;
    net::co_spawn(domain.Executor(), handler.Process(std::make_unique<Stream>(stream), dispatcher,
        receiver, io, context, timeouts, 0), [&](std::exception_ptr error, RelayResult result) {
            returned = true;
            failure = error;
            result_error = result.error;
        });
    io.poll();
    Check(dispatcher.active == (pending ? 0 : 1) && stream.pending_reads == 1,
          "initial identity state must be established");
    if (mode == 2) {
        dispatcher.gate.cancel();
        io.run_for(50ms);
        Check(dispatcher.finished == 1 && !returned, "first request must retire while session stays open");
    }
    if (mode == 9) {
        constexpr std::array<uint8_t, 32> payload{};
        Frame(stream.input, 2, first_sid, payload);
        // Keep only the frame header: the payload bytes arrive later.
        stream.input.erase(stream.input.end() - static_cast<std::ptrdiff_t>(payload.size()),
                           stream.input.end());
        stream.wake.cancel();
        io.poll();
        Check(stream.pending_reads == 1 && dispatcher.active == 1,
              "payload read must suspend while the original dispatch is alive");
        dispatcher.gate.cancel();
        io.run_for(50ms);
        Check(dispatcher.finished == 1 && !returned, "dispatch must retire while payload read stays pending");
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
    const bool rejected = returned && !failure && result_error == ErrorCode::PROTOCOL_INVALID_COMMAND && HasAlert(stream.output);
    if (!returned) stream.FeedInvalidFrame(false);
    io.run_for(500ms);
    Check(returned && dispatcher.active == 0 && stream.destroyed, "identity fixture must join all requests");
    std::cout << "identity-" << names[mode] << " started=" << started
              << " overlapping=" << dispatcher.overlapping_contexts
              << " changed=" << dispatcher.changed_contexts << " rejected=" << rejected << '\n';
    if (baseline) return;
    const size_t expected = (mode == 7 || mode == 9) ? 2 : pending ? 0 : 1;
    Check(started == expected && dispatcher.overlapping_contexts == 0 && dispatcher.changed_contexts == 0,
          "each SYN must create one independent request context exactly once");
    Check(mode >= 7 || rejected, "invalid SYN must alert and reject the session");
}
class ParsingDispatcher final : public routing::Dispatcher {
public:
    std::vector<uint8_t> bytes;
    std::string host;
    int calls = 0;
    net::awaitable<RelayResult> Dispatch(net::io_context&,
        const routing::DispatchPolicy&, std::unique_ptr<AsyncStream>, transport::Link link,
        InitialPayload first, session::Context& ctx, StatsShard&, const TimeoutsConfig&) override {
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
        co_return RelayResult{};
    }
};

void RunParsingCase(int mode) {
    constexpr std::array names{"coalesced", "ipv4-fragmented", "ipv6-fragmented", "max-domain",
        "invalid-type", "empty-domain", "zero-port", "truncated", "cancel-pending", "oversized-domain", "invalid-uot-request"};
    net::io_context io;
    DomainFixture execution(io);
    memory::ScopedAllocationDomain allocation(execution.Memory());
    StreamState stream(io);
    const auto hash = anytls::PasswordHash("parsing-test");
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
    using namespace proxyman::inbound;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"parsing", users}};
    execution.InstallUsers(updates);
    UserOnlineTracker validator;
    StatsShard stats;
    proxy::anytls::inbound::Handler handler(validator, stats, {});
    ParsingDispatcher dispatcher;
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    session::Context context;
    context.inbound.tag = "parsing";
    TimeoutsConfig timeouts;
    net::cancellation_signal cancellation;
    bool returned = false;
    std::exception_ptr failure;
    net::co_spawn(execution.Executor(), handler.Process(std::make_unique<Stream>(stream), dispatcher,
        receiver, io, context, timeouts, 0), net::bind_cancellation_slot(cancellation.slot(),
        [&](std::exception_ptr error, RelayResult) { returned = true; failure = error; }));
    io.poll();
    Check(!returned && stream.pending_reads == 1, "logical parsing must leave the session reader alive");
    if (mode < 4) {
        Check(dispatcher.calls == 1 && dispatcher.bytes == expected, "target prefix and frame boundaries must preserve every data byte");
        if (mode == 3) Check(dispatcher.host == domain, "maximum domain length must survive fragmented decoding");
    } else {
        Check(dispatcher.calls == 0, "invalid or incomplete address must not enter dispatcher");
    }
    if (mode == 8) cancellation.emit(net::cancellation_type::terminal);
    else stream.FeedInvalidFrame(false);
    io.run_for(500ms);
    Check(returned && stream.destroyed && stream.pending_reads == 0 && stream.pending_writes == 0,
          "parsing tasks must join before transport destruction");
    Check(mode != 8 || bool(failure), "pending parser must propagate parent cancellation");
    std::cout << "parsing-" << names[mode] << " calls=" << dispatcher.calls
              << " bytes=" << dispatcher.bytes.size() << " joined=1\n";
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
    std::vector<const void*> received_buffers;
    net::awaitable<RelayResult> Dispatch(net::io_context& io,
        const routing::DispatchPolicy&, std::unique_ptr<AsyncStream>, transport::Link link,
        InitialPayload first, session::Context&, StatsShard&, const TimeoutsConfig&) override {
        ++active;
        (void)co_await gate.async_wait(net::as_tuple(net::use_awaitable));
        if (consume) {
            auto data = std::move(first).MoveToMultiBuffer();
            try {
                while (true) {
                    for (const auto* buffer : data) {
                        if (!buffer) continue;
                        received_buffers.push_back(buffer->Bytes().data());
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
        co_return RelayResult{};
    }
};

void RunQueueCase(int mode, bool baseline = false, uint32_t seed = 0) {
    constexpr std::array names{"tiny-fragments", "whole-frame", "sparse-mixed", "boundary-fragments",
        "byte-budget-backpressure", "cancel-full-queue", "maximum-tiny-fragments", "random-fragments"};
    net::io_context io;
    DomainFixture domain(io);
    memory::ScopedAllocationDomain allocation(domain.Memory());
    StreamState stream(io);
    const auto hash = anytls::PasswordHash("queue-test");
    stream.input.assign(hash.begin(), hash.end());
    stream.input.insert(stream.input.end(), {0, 0});
    constexpr std::array<uint8_t, 3> settings{'v', '=', '2'};
    constexpr std::array<uint8_t, 7> target{1, 127, 0, 0, 1, 0, 80};
    Frame(stream.input, 4, 0, settings);
    Frame(stream.input, 1, 1);
    Frame(stream.input, 2, 1, target);
    using namespace proxyman::inbound;
    PreparedAnyTlsUser user;
    user.password_hash = hash;
    const UserSet users = PreparedAnyTlsUsers{user};
    const std::array updates{UserStore::UserUpdate{"queue", users}};
    domain.InstallUsers(updates);
    UserOnlineTracker validator;
    StatsShard stats;
    proxy::anytls::inbound::Handler handler(validator, stats, {});
    QueueDispatcher dispatcher(io);
    ReceiverSettings receiver{.inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {}, .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    session::Context context;
    context.inbound.tag = "queue";
    TimeoutsConfig timeouts;
    net::cancellation_signal cancellation;
    bool returned = false;
    int active_at_return = -1;
    Check(BufferCount() == 0, "buffer accounting must start empty");
    memory::detail::test_buffers_peak = 0;
    net::co_spawn(domain.Executor(), handler.Process(std::make_unique<Stream>(stream), dispatcher,
        receiver, io, context, timeouts, 0), net::bind_cancellation_slot(cancellation.slot(),
        [&](std::exception_ptr, RelayResult) {
            returned = true; active_at_return = dispatcher.active;
        }));
    io.poll();
    Check(dispatcher.active == 1 && stream.pending_reads == 1, "request must pause before consuming its logical input");
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
    stream.record_payload_buffers = mode == 1;
    stream.wake.cancel();
    io.poll();
    const size_t queued_blocks = BufferCount();
    const bool bounded = queued_blocks <= (expected.size() + 4095) / 4096;
    Check(stream.offset == stream.input.size() && stream.pending_reads == 1,
          "queue must accept the full payload budget independent of frame fragmentation");
    if (mode == 4 || mode == 5) {
        Frame(stream.input, 2, 1, std::span(expected).first(1));
        stream.wake.cancel();
        io.poll();
        Check(stream.pending_reads == 0 && dispatcher.active == 1,
              "the next payload must wait for capacity without entering the queue");
        expected.push_back(expected[0]);
    }
    if (mode == 5) {
        cancellation.emit(net::cancellation_type::terminal);
        io.poll();
        Check(!returned && !stream.destroyed, "queue cancellation must join delayed request cleanup");
    } else {
        Frame(stream.input, 3, 1);
        dispatcher.consume = true;
        dispatcher.gate.cancel();
        stream.wake.cancel();
        io.run_for(100ms);
        Check(dispatcher.received == expected && dispatcher.active == 0,
              "queue drain and backpressure must preserve every byte through logical FIN");
        if (mode == 1) Check(dispatcher.received_buffers == stream.payload_buffers,
            "whole payload buffers must transfer through the queue without copying");
        stream.FeedInvalidFrame(false);
    }
    io.run_for(100ms);
    Check(returned && active_at_return == 0 && stream.destroyed &&
          stream.pending_reads == 0 && stream.pending_writes == 0,
          "queue storage must not outlive its joined session");
    Check(BufferCount() == 0, "all queued and in-flight Buffer allocations must be released");
    std::cout << "queue-" << names[mode] << " seed=" << seed << " fragments=" << fragments << " queued-blocks=" << queued_blocks
              << " capacity-bytes=" << queued_blocks * buf::Buffer::kSize << " bounded=" << bounded
              << " peak-blocks=" << BufferPeak() << " released=1\n";
    if (!baseline) Check(bounded && BufferPeak() <= 24,
        "queue and current physical frame must stay within their combined Buffer capacity budget");
}

void TestPeerSettings() {
    struct Valid { std::string_view text; uint32_t version; };
    constexpr std::array valid{
        Valid{"", 1}, Valid{"v=1", 1}, Valid{"v=2", 2}, Valid{"v=3", 3},
        Valid{"v=20", 20}, Valid{"v=256", 256}, Valid{"v=4294967295", UINT32_MAX},
        Valid{"v=02", 2}, Valid{"v=2\r\nclient=test\r\n", 2},
        Valid{"client=has-v=2\nnot-v=2", 1}, Valid{"\n\r\nv=2\n", 2},
        Valid{"padding-md5=v=2", 1}, Valid{"client=x\nclient=y\nv=1", 1}};
    constexpr std::array invalid{"v=", "v=0", "v=-1", "v=+2", "v= 2", "v=2 ",
        "v=2x", "v=1\nv=2", "v=2\nv=2", "v=4294967296", "v=9999999999999999999999",
        "v", "=2", "padding-md5=a\npadding-md5=b", "v=2\rx"};
    for (const auto& item : valid) {
        const auto parsed = anytls::ParsePeerSettings(item.text);
        Check(parsed && parsed->version == (item.version >= 2 ? anytls::SessionVersion::V2 : anytls::SessionVersion::V1),
              "peer settings must parse the exact version key without narrowing or substring inference");
    }
    for (const auto text : invalid) {
        const auto parsed = anytls::ParsePeerSettings(text);
        Check(!parsed && parsed.error() == ErrorCode::PROTOCOL_DECODE_FAILED, "malformed peer settings must fail atomically");
    }
    Check(!anytls::ParsePeerSettings(std::string_view("v=2\0junk", 8)), "embedded NUL is not a version terminator");
    const auto defaults = anytls::ClientSettings(*anytls::DefaultPaddingScheme());
    const auto parsed = anytls::ParsePeerSettings(defaults);
    Check(parsed && parsed->version == anytls::SessionVersion::V2 &&
          parsed->padding_md5 == anytls::DefaultPaddingScheme()->Digest() &&
          defaults.find("\nclient=cnode\n") != std::string::npos,
          "advertised settings must identify this implementation and its supported version");
    std::cout << "peer-settings cases=" << valid.size() + invalid.size() + 2 << " passed=1\n";
}
class MuxUdpDispatcher final : public routing::Dispatcher {
public:
    explicit MuxUdpDispatcher(net::io_context& io) : gate(io) {
        gate.expires_at(net::steady_timer::time_point::max());
    }
    struct Packet {
        TargetAddress target;
        std::vector<uint8_t> bytes;
    };
    net::steady_timer gate;
    bool pause = false;
    int active = 0;
    int finished = 0;
    bool input_eof = false;
    std::exception_ptr failure;
    std::vector<Packet> received;

    net::awaitable<RelayResult> Dispatch(net::io_context&,
        const routing::DispatchPolicy&, std::unique_ptr<AsyncStream>, transport::Link link,
        InitialPayload, session::Context& ctx, StatsShard&, const TimeoutsConfig&) override {
        struct Scope {
            MuxUdpDispatcher& owner;
            explicit Scope(MuxUdpDispatcher& value) : owner(value) { ++owner.active; }
            ~Scope() { --owner.active; ++owner.finished; }
        } scope(*this);
        try {
            Check(ctx.content.network == Network::UDP, "Mux UDP must use the ordinary UDP dispatcher");
            if (pause) (void)co_await gate.async_wait(net::as_tuple(net::use_awaitable));
            for (;;) {
                auto packet = co_await link.reader->ReadMultiBuffer();
                if (packet.empty()) {
                    input_eof = true;
                    break;
                }
                const auto datagram = buf::InspectUdpDatagram(packet);
                Check(datagram.Valid(), "Mux UDP input must retain a complete message and target");
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
        co_return RelayResult{};
    }
};

void RunMuxUdpCase(int mode) {
    net::io_context io;
    DomainFixture domain(io);
    memory::ScopedAllocationDomain allocation(domain.Memory());
    StreamState stream(io);
    MuxUdpDispatcher dispatcher(io);
    dispatcher.pause = mode >= 2;
    StatsShard stats;
    proxyman::inbound::ReceiverSettings receiver{
        .inbound_tag = {}, .inbound_tags = {}, .protocol = {}, .stream_settings = {},
        .dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
    session::Context context;
    context.inbound.tag = "mux-udp";
    TimeoutsConfig timeouts;
    const TargetAddress target("127.0.0.1", 53);
    const TargetAddress changed("127.0.0.2", 5353);
    std::array<uint8_t, mux::kMaxFrameHeaderBytes> header{};
    auto append = [&](size_t size) {
        Check(size != 0, "Mux UDP fixture header encoding failed");
        stream.input.insert(stream.input.end(), header.begin(), header.begin() + size);
    };
    const size_t open_size = mux::EncodeNewHeaderTo(
        header, 1, mux::NetworkType::UDP, target, 0, mode == 1);
    append(open_size);
    std::vector<MuxUdpDispatcher::Packet> expected_packets;
    if (mode == 1) expected_packets.push_back({target, {}});
    bool returned = false;
    std::exception_ptr failure;
    net::cancellation_signal cancellation;
    Check(BufferCount() == 0, "Mux UDP fixture must start without live buffers");
    net::co_spawn(domain.Executor(),
        RunMux(std::make_unique<Stream>(stream), dispatcher, receiver, io, context, stats, timeouts),
        net::bind_cancellation_slot(cancellation.slot(),
            [&](std::exception_ptr error, RelayResult) { failure = error; returned = true; }));
    io.poll();
    Check(dispatcher.active == 1 && dispatcher.received.size() == (mode == 1 ? 1u : 0u),
          "Mux NEW without Data must not manufacture an empty datagram");
    // Neither a no-Data KEEP nor a KEEPALIVE with Data is a UDP packet.
    stream.input.insert(stream.input.end(), {0, 4, 0, 1, 2, 0, 0, 4, 0, 1, 4, 1, 0, 0});
    const size_t count = mode >= 2 ? 1500 : 1;
    for (size_t i = 0; i < count; ++i) {
        append(mux::EncodeKeepUDPHeaderTo(header, 1, changed, 0));
        expected_packets.push_back({changed, {}});
    }
    if (mode < 2) {
        append(mux::EncodeKeepDataHeaderTo(header, 1, 1));
        stream.input.push_back(0x42);
        append(mux::EncodeKeepDataHeaderTo(header, 1, 0));
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
        append(mux::EncodeEndTo(header, 1));
    }
    stream.wake.cancel();
    io.poll();
    if (mode >= 2) {
        Check(dispatcher.received.empty() && dispatcher.active == 1,
              "paused Mux dispatcher must retain queued empty datagrams");
        Check(BufferCount() <= 4 * 1024 * 1024 / buf::Buffer::kSize + 32,
              "empty Mux UDP queue must charge a Buffer capacity floor");
        if (mode == 3) {
            cancellation.emit(net::cancellation_type::terminal);
        } else {
            dispatcher.gate.cancel();
        }
        io.run_for(100ms);
    }
    if (mode != 3) {
        if (dispatcher.failure) std::rethrow_exception(dispatcher.failure);
        const size_t expected = expected_packets.size();
        Check(dispatcher.received.size() == expected && dispatcher.finished == 1 &&
              dispatcher.input_eof,
              "Mux must deliver every datagram, including END Data, before input EOF");
        for (size_t i = 0; i < expected; ++i) {
            const auto& packet = dispatcher.received[i];
            Check(packet.target.SameEndpoint(expected_packets[i].target) &&
                  packet.bytes == expected_packets[i].bytes,
                  "Mux UDP target, final END payload or zero/nonzero boundary changed");
        }
        buf::MultiBuffer output;
        Check(buf::AppendSpanToMultiBuffer(stream.output, output), "Mux reply fixture allocation failed");
        size_t replies = 0;
        while (!output.empty()) {
            const auto frame = mux::DecodeFrame(output);
            Check(frame && frame->frame_size != 0, "Mux UDP reply must have a real wire header");
            if (frame->status == mux::SessionStatus::KEEP) {
                Check(frame->has_data && frame->has_target &&
                      replies < dispatcher.received.size(), "Mux UDP reply lost Data or endpoint");
                const auto& packet = dispatcher.received[replies++];
                Check(frame->target.SameEndpoint(packet.target) && frame->data_len == packet.bytes.size(),
                      "Mux UDP zero reply was dropped or misframed");
                output.DropPrefixBytes(frame->data_offset);
                std::vector<uint8_t> bytes(frame->data_len);
                Check(output.CopyPrefixTo(bytes) == bytes.size() && bytes == packet.bytes,
                      "Mux UDP reply changed or truncated payload bytes");
                output.DropPrefixBytes(frame->data_len);
            } else {
                output.DropPrefixBytes(frame->frame_size);
            }
        }
        Check(replies == expected, "Mux UDP must encode every empty reply exactly once");
        stream.FeedInvalidFrame(true);
        io.run_for(100ms);
    }
    if (mode == 3) {
        Check(dispatcher.received.empty() && !dispatcher.input_eof,
              "cancelling queued Mux UDP input must not report normal EOF or deliver discarded packets");
    }
    Check(returned && !failure && dispatcher.active == 0 &&
          stream.pending_reads == 0 && stream.pending_writes == 0 && stream.destroyed,
          "Mux UDP cancellation and close must join all logical and physical work");
    Check(BufferCount() == 0, "Mux UDP must release every queued and in-flight Buffer");
    domain.Shutdown();
}

}  // namespace

TEST(SubstreamInboundLifecycle, Contract) {
    try {
        constexpr bool baseline = false;
        RunCase(0, baseline);
        RunCase(1, baseline);
        if (!baseline) {
            RunCase(2, false);
            RunCase(3, false);
            RunCase(0, false, true);
            RunCase(1, false, true);
            RunCase(0, false, false, true);
            RunCase(1, false, false, true);
            RunCase(0, false, true, true);
            for (int mode = 0; mode < 10; ++mode) RunIdentityCase(mode, false);
            for (int mode = 0; mode < 11; ++mode) RunParsingCase(mode);
            for (int mode = 0; mode < 8; ++mode) RunHandshakeCase(mode);
            for (int mode = 0; mode < 7; ++mode) RunQueueCase(mode);
            for (uint32_t seed = 0; seed < 16; ++seed) RunQueueCase(7, false, seed);
            TestPeerSettings();
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        FAIL() << error.what();
    }
}

TEST(SubstreamInboundLifecycle, MuxUdpEmptyDatagramsAndControlFrames) {
    for (int mode = 0; mode < 6; ++mode) {
        SCOPED_TRACE(mode);
        RunMuxUdpCase(mode);
    }
}
