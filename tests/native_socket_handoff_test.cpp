#include <gtest/gtest.h>

#include "app/session_group_executor.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/datagram_socket.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "transport/link_error.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/read.hpp>
#include <asio/redirect_error.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <latch>
#include <optional>
#include <thread>
#include <vector>
#include <stdexcept>

namespace {
using namespace std::chrono_literals;
using transport::internet::DatagramSocket;

void Require(bool value, const char* reason) {
    if (!value) {
        ADD_FAILURE() << reason;
        throw std::runtime_error(reason);
    }
}

template<class T>
T Finish(std::future<T> future) {
    Require(future.wait_for(5s) == std::future_status::ready, "native handoff operation stalled");
    return future.get();
}

struct Hooks final : ExecutionDomain::Hooks {
    memory::AllocationDomain allocation;
    std::optional<memory::ScopedAllocationDomain> lease;
    void Enter() noexcept override { lease.emplace(allocation); }
    void Leave() noexcept override { lease.reset(); }
    void OnFailure(std::exception_ptr) noexcept override { std::terminate(); }
};

struct Fixture {
    net::io_context old_io, new_io, control;
    net::executor_work_guard<net::io_context::executor_type> old_work{old_io.get_executor()};
    net::executor_work_guard<net::io_context::executor_type> new_work{new_io.get_executor()};
    net::executor_work_guard<net::io_context::executor_type> control_work{control.get_executor()};
    std::shared_ptr<GroupCoordinator> coordinator = std::make_shared<GroupCoordinator>(control);
    std::shared_ptr<Hooks> hooks = std::make_shared<Hooks>();
    std::shared_ptr<ExecutionDomain> domain;
    std::thread old_thread, new_thread, control_thread;
    std::latch old_stopped{1};
    std::latch reactors_stopped{3};
    std::latch release_pools{1};

    Fixture() {
        coordinator->RegisterWorker(0, old_io, old_io.get_executor());
        coordinator->RegisterWorker(1, new_io, new_io.get_executor());
        domain = ExecutionDomain::Create(old_io, 0, old_io.get_executor(), hooks, coordinator);
        hooks->allocation.SetLeaseGroup(domain->LeaseIdentity(), ExecutionDomain::SharesLeaseIdentity);
        old_thread = std::thread([&] {
            old_io.run();
            old_stopped.count_down();
            reactors_stopped.count_down();
            release_pools.wait();
        });
        new_thread = std::thread([&] {
            new_io.run();
            reactors_stopped.count_down();
            release_pools.wait();
        });
        control_thread = std::thread([&] {
            control.run();
            reactors_stopped.count_down();
            release_pools.wait();
        });
    }
    template<class F> auto OnDomain(F function) {
        return Finish(net::co_spawn(domain->Executor(), std::move(function), net::use_future));
    }
    auto Prepare() {
        return Finish(net::co_spawn(control, domain->PreparePassiveHandoff(
            {1, &new_io, new_io.get_executor()}), net::use_future));
    }
    void Commit(const std::shared_ptr<ExecutionDomain::Handoff>& handoff) {
        Finish(net::co_spawn(control, handoff->Commit(), net::use_future));
    }
    void Cancel(const std::shared_ptr<ExecutionDomain::Handoff>& handoff) {
        Finish(net::co_spawn(control, handoff->Cancel(), net::use_future));
    }
    void StopOldReactor() {
        old_work.reset();
        old_io.stop();
        // Stop native dispatch, not the source pool: migrated allocations
        // still return through its remote-free queue until session teardown.
        old_stopped.wait();
    }
    ~Fixture() {
        coordinator->CloseAdmission();
        Finish(net::co_spawn(control, coordinator->AsyncJoin(), net::use_future));
        domain.reset();
        Finish(net::co_spawn(control, [this]() -> net::awaitable<void> {
            coordinator->ReleaseServices();
            co_await coordinator->Finalize();
        }, net::use_future));
        coordinator.reset();
        hooks.reset();
        old_work.reset(); new_work.reset(); control_work.reset();
        reactors_stopped.wait();
        release_pools.count_down();
        if (old_thread.joinable()) old_thread.join();
        new_thread.join(); control_thread.join();
    }
};

// Registered first, so it fails after the socket's target registration has
// succeeded. This exercises rollback of a genuinely released/assigned fd.
struct RejectPrepare final : ExecutionDomain::NativeResource {
    bool reject = true;
    unsigned cancelled = 0;
    net::awaitable<void> PrepareHandoff(const ExecutionDomain::HandoffTarget&) override {
        if (reject) throw std::runtime_error("reject prepared handoff");
        co_return;
    }
    void CommitHandoff(const ExecutionDomain::HandoffTarget&) noexcept override {}
    net::awaitable<void> CancelHandoff(const ExecutionDomain::HandoffTarget&) override {
        ++cancelled;
        co_return;
    }
};

void TcpPendingReadAndScatterWrite() {
    Fixture f;
    tcp::acceptor acceptor(f.control, {net::ip::address_v4::loopback(), 0});
    tcp::socket socket(f.old_io), peer(f.control);
    socket.open(tcp::v4());
    socket.set_option(net::socket_base::send_buffer_size(4096));
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    const auto fd = socket.native_handle();
    const auto local = socket.local_endpoint();
    const auto remote = socket.remote_endpoint();
    std::unique_ptr<TcpStream> stream;
    RejectPrepare reject;
    f.OnDomain([&]() -> net::awaitable<void> {
        f.domain->RegisterResource(reject);
        stream = std::make_unique<TcpStream>(std::move(socket));
        const std::array<uint8_t, 3> prefix{'p', 'r', 'e'};
        stream->PrependReadData(prefix);
        co_return;
    });
    bool failed = false;
    try { (void)f.Prepare(); } catch (const std::runtime_error&) { failed = true; }
    Require(failed && reject.cancelled == 1, "failed prepare did not roll back all resources");
    f.OnDomain([&]() -> net::awaitable<void> {
        Require(stream->NativeHandle() == fd && stream->LocalEndpoint() == local &&
                stream->RemoteEndpoint() == remote, "TCP rollback replaced fd or tuple");
        reject.reject = false;
        co_return;
    });
    auto cancelled_handoff = f.Prepare();
    f.Cancel(cancelled_handoff);
    cancelled_handoff.reset();

    std::vector<uint8_t> bytes(4 * 1024 * 1024 + 31);
    for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>(i * 31u);
    const std::array<net::const_buffer, 5> scatter{
        net::buffer(bytes.data(), 17), net::const_buffer{},
        net::buffer(bytes.data() + 17, 1024 * 1024 + 9),
        net::buffer(bytes.data() + 1024 * 1024 + 26, bytes.size() - 1024 * 1024 - 26),
        net::const_buffer{}};
    auto writing = net::co_spawn(f.domain->Executor(), stream->WriteBuffers(scatter), net::use_future);
    std::promise<void> armed;
    auto reading = net::co_spawn(f.domain->Executor(), [&]() -> net::awaitable<std::thread::id> {
        std::array<char, 3> prefix{};
        Require(co_await stream->AsyncRead(net::buffer(prefix)) == 3 &&
                prefix == std::array<char, 3>{'p', 'r', 'e'}, "handoff lost pending read prefix");
        armed.set_value();
        char byte = 0;
        Require(co_await stream->AsyncRead(net::buffer(&byte, 1)) == 1 && byte == 'r',
                "pending TCP read did not survive handoff");
        co_return std::this_thread::get_id();
    }, net::use_future);
    Finish(armed.get_future());
    f.OnDomain([]() -> net::awaitable<void> { co_return; });
    Require(writing.wait_for(0s) != std::future_status::ready && peer.available() != 0,
            "TCP test did not reach a partially successful, backpressured scatter write");
    auto active_rollback = f.Prepare();
    f.Cancel(active_rollback);
    active_rollback.reset();
    Require(reading.wait_for(0s) != std::future_status::ready &&
            writing.wait_for(0s) != std::future_status::ready,
            "TCP rollback exposed migration cancellation to pending I/O");
    auto handoff = f.Prepare();
    Require(reading.wait_for(0s) != std::future_status::ready &&
            writing.wait_for(0s) != std::future_status::ready, "frozen business completed during prepare");
    f.Commit(handoff);
    handoff.reset();
    f.StopOldReactor();
    f.OnDomain([&]() -> net::awaitable<void> {
        Require(&f.domain->Reactor() == &f.new_io && stream->NativeHandle() == fd &&
                stream->LocalEndpoint() == local && stream->RemoteEndpoint() == remote,
                "TCP commit did not preserve descriptor and endpoints on new reactor");
        co_return;
    });
    std::vector<uint8_t> received(bytes.size());
    auto receiving = net::co_spawn(f.control, [&]() -> net::awaitable<void> {
        co_await net::async_read(peer, net::buffer(received), net::use_awaitable);
    }, net::use_future);
    peer.write_some(net::buffer("r", 1));
    Require(Finish(std::move(reading)) == f.new_thread.get_id(), "TCP read resumed on old Worker");
    Finish(std::move(writing));
    Finish(std::move(receiving));
    Require(received == bytes && peer.available() == 0, "TCP scatter progress duplicated or lost bytes");
    f.OnDomain([&]() -> net::awaitable<void> { stream->ShutdownWrite(); co_return; });
    auto eof = net::co_spawn(f.control, [&]() -> net::awaitable<void> {
        char byte;
        IoErrorCode error;
        co_await peer.async_read_some(net::buffer(&byte, 1), net::redirect_error(net::use_awaitable, error));
        Require(error == io_error::eof, "migrated TCP half-close did not retain FIN semantics");
    }, net::use_future);
    Finish(std::move(eof));
    f.OnDomain([&]() -> net::awaitable<void> {
        auto dialed = co_await TcpStream::Connect(f.old_io, acceptor.local_endpoint(), 1s);
        Require(dialed.Ok(), "post-handoff TCP dial retained the stopped reactor");
        Require(co_await dialed.stream->AsyncWrite(net::buffer("n", 1)) == 1,
                "post-handoff TCP dial failed to write");
    });
    tcp::socket fresh_peer(f.control);
    acceptor.accept(fresh_peer);
    char fresh_byte = 0;
    Require(fresh_peer.read_some(net::buffer(&fresh_byte, 1)) == 1 && fresh_byte == 'n',
            "post-handoff TCP dial did not reach the peer");
    f.OnDomain([&]() -> net::awaitable<void> {
        stream.reset();
        f.domain->UnregisterResource(reject);
        co_return;
    });
}

void TcpCancellationDuringFreeze(bool parent_cancel) {
    Fixture f;
    tcp::acceptor acceptor(f.control, {net::ip::address_v4::loopback(), 0});
    tcp::socket socket(f.old_io), peer(f.control);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    std::unique_ptr<TcpStream> stream;
    net::cancellation_signal signal;
    f.OnDomain([&]() -> net::awaitable<void> {
        stream = std::make_unique<TcpStream>(std::move(socket));
        stream->ShutdownWrite(); // The read half remains usable through migration.
        co_return;
    });
    std::promise<void> armed;
    auto read = net::co_spawn(f.domain->Executor(), [&]() -> net::awaitable<bool> {
        armed.set_value();
        try { char byte; (void)co_await stream->AsyncRead(net::buffer(&byte, 1)); }
        catch (const IoSystemError& error) { co_return error.code() == io_error::operation_aborted; }
        co_return false;
    }, net::bind_cancellation_slot(signal.slot(), net::use_future));
    Finish(armed.get_future());
    auto handoff = f.Prepare();
    f.domain->Execute([&] {
        if (parent_cancel) signal.emit(net::cancellation_type::terminal);
        else stream->Cancel();
    });
    f.Commit(handoff);
    handoff.reset();
    Require(Finish(std::move(read)), "migration swallowed explicit TCP cancellation");
    f.OnDomain([&]() -> net::awaitable<void> {
        signal.slot().clear();
        Require(stream->IsOpen(), "read cancellation unexpectedly closed migrated TCP fd");
        bool shut = false;
        try { (void)co_await stream->AsyncWrite(net::buffer("x", 1)); }
        catch (const IoSystemError& error) { shut = error.code() == io_error::broken_pipe; }
        Require(shut, "handoff lost TCP write-half shutdown state");
        stream.reset();
        co_return;
    });
}

void TcpWriteCancellationDuringFreeze(bool parent_cancel) {
    Fixture f;
    tcp::acceptor acceptor(f.control, {net::ip::address_v4::loopback(), 0});
    tcp::socket socket(f.old_io), peer(f.control);
    socket.open(tcp::v4());
    socket.set_option(net::socket_base::send_buffer_size(4096));
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    std::unique_ptr<TcpStream> stream;
    net::cancellation_signal signal;
    f.OnDomain([&]() -> net::awaitable<void> {
        stream = std::make_unique<TcpStream>(std::move(socket));
        co_return;
    });
    std::vector<uint8_t> bytes(4 * 1024 * 1024, 'w');
    auto writing = net::co_spawn(f.domain->Executor(), [&]() -> net::awaitable<bool> {
        try { (void)co_await stream->AsyncWrite(net::buffer(bytes)); }
        catch (const IoSystemError& error) { co_return error.code() == io_error::operation_aborted; }
        co_return false;
    }, net::bind_cancellation_slot(signal.slot(), net::use_future));
    f.OnDomain([]() -> net::awaitable<void> { co_return; });
    Require(writing.wait_for(0s) != std::future_status::ready && peer.available() != 0,
            "TCP cancellation test did not block after partial send");
    auto handoff = f.Prepare();
    f.domain->Execute([&] {
        if (parent_cancel) signal.emit(net::cancellation_type::terminal);
        else stream->Cancel();
    });
    f.Commit(handoff);
    handoff.reset();
    Require(Finish(std::move(writing)), "migration swallowed TCP write cancellation");
    f.OnDomain([&]() -> net::awaitable<void> {
        signal.slot().clear();
        stream.reset();
        co_return;
    });
}

void DatagramSameFdAndCancellation() {
    Fixture f;
    udp::socket peer(f.control, udp::endpoint(net::ip::address_v4::loopback(), 0));
    std::unique_ptr<DatagramSocket> socket;
    udp::endpoint local;
    int fd = -1;
    f.OnDomain([&]() -> net::awaitable<void> {
        socket = std::make_unique<DatagramSocket>(f.old_io, net::ip::address_v4::loopback());
        local = socket->LocalEndpoint();
        fd = socket->NativeHandle();
        co_return;
    });
    std::promise<void> armed;
    auto read = net::co_spawn(f.domain->Executor(), [&]() -> net::awaitable<std::thread::id> {
        auto operation = socket->StartRead();
        armed.set_value();
        auto packet = co_await operation.Receive();
        Require(packet.source == peer.local_endpoint() && packet.payload.byte_size() == 1 &&
                (*packet.payload.begin())->Bytes()[0] == 'd', "migrated UDP receive changed datagram");
        co_return std::this_thread::get_id();
    }, net::use_future);
    Finish(armed.get_future());
    auto rollback = f.Prepare();
    f.Cancel(rollback);
    rollback.reset();
    Require(read.wait_for(0s) != std::future_status::ready, "UDP rollback cancelled business read");
    auto handoff = f.Prepare();
    f.Commit(handoff);
    handoff.reset();
    f.StopOldReactor();
    peer.send_to(net::buffer("d", 1), local);
    Require(Finish(std::move(read)) == f.new_thread.get_id(), "UDP read used the old Worker");
    f.OnDomain([&]() -> net::awaitable<void> {
        Require(socket->NativeHandle() == fd && socket->LocalEndpoint() == local,
                "UDP handoff changed source descriptor or tuple");
        auto send = socket->StartWrite();
        const std::array<net::const_buffer, 1> buffers{net::buffer("s", 1)};
        co_await send.SendTo(peer.local_endpoint(), buffers);
    });
    std::array<char, 1> bytes{};
    udp::endpoint source;
    Require(peer.receive_from(net::buffer(bytes), source) == 1 && bytes[0] == 's' && source == local,
            "migrated UDP send changed source port");
    f.OnDomain([&]() -> net::awaitable<void> {
        // Even a stale constructor argument must use the current domain reactor.
        DatagramSocket fresh(f.old_io, net::ip::address_v4::loopback());
        auto send = fresh.StartWrite();
        const std::array<net::const_buffer, 1> buffers{net::buffer("n", 1)};
        co_await send.SendTo(peer.local_endpoint(), buffers);
    });
    Require(peer.receive_from(net::buffer(bytes), source) == 1 && bytes[0] == 'n',
            "post-handoff socket construction retained stopped reactor");
    std::promise<void> cancelled_armed;
    auto cancelled = net::co_spawn(f.domain->Executor(), [&]() -> net::awaitable<bool> {
        auto operation = socket->StartRead();
        cancelled_armed.set_value();
        try { (void)co_await operation.Receive(); }
        catch (const transport::LinkError& error) { co_return error.code() == ErrorCode::CANCELLED; }
        co_return false;
    }, net::use_future);
    Finish(cancelled_armed.get_future());
    f.OnDomain([&]() -> net::awaitable<void> { socket->Cancel(); co_return; });
    Require(Finish(std::move(cancelled)), "UDP explicit cancellation was hidden");
    f.OnDomain([&]() -> net::awaitable<void> { socket.reset(); co_return; });
}

void RetiredMemberDuringHandoff(bool commit) {
    Fixture f;
    std::promise<std::thread::id> retired;
    auto retired_on = retired.get_future();
    auto hooks = std::shared_ptr<Hooks>(new Hooks, [&retired](Hooks* value) {
        delete value;
        retired.set_value(std::this_thread::get_id());
    });
    auto member = f.domain->CreateSibling(hooks);
    hooks->allocation.SetLeaseGroup(
        member->LeaseIdentity(), ExecutionDomain::SharesLeaseIdentity);
    hooks.reset();
    f.OnDomain([&]() -> net::awaitable<void> { co_await f.domain->Join(member); });
    Finish(net::co_spawn(member->Executor(), [&]() -> net::awaitable<void> {
        struct Event final : TimeoutEvent {
            void OnTimeout() override { Require(false, "cancelled member deadline fired"); }
        } event;
        Require(TimeoutScheduler::ForIoContext(f.old_io).ScheduleAfter(1h, event),
                "member deadline was not admitted");
        event.Cancel();
        co_await TimeoutScheduler::AsyncReleaseForIoContext(f.old_io);
    }, net::use_future));

    auto handoff = f.Prepare();
    const std::weak_ptr<ExecutionDomain> weak_member = member;
    member.reset();
    Require(!weak_member.expired(), "prepared handoff failed to pin its member");
    if (commit) f.Commit(handoff);
    else f.Cancel(handoff);
    handoff.reset();
    const auto expected_owner = commit ? f.new_thread.get_id() : f.old_thread.get_id();
    Require(Finish(std::move(retired_on)) == expected_owner,
            "retired member services were destroyed outside their owner Worker");
    Require(weak_member.expired(), "resolved handoff retained an unused member");
    Require(f.OnDomain([]() -> net::awaitable<std::thread::id> {
        co_return std::this_thread::get_id();
    }) == expected_owner, "surviving member lost its execution owner");
}
}  // namespace

TEST(NativeSocketHandoff, Contract) {
    TcpPendingReadAndScatterWrite();
    TcpCancellationDuringFreeze(false);
    TcpCancellationDuringFreeze(true);
    TcpWriteCancellationDuringFreeze(false);
    TcpWriteCancellationDuringFreeze(true);
    DatagramSameFdAndCancellation();
    std::puts("native socket handoff: fd/tuple, drain, rollback, scatter progress, cancellation, half-close passed");
}

TEST(NativeSocketHandoff, RetiredMemberDuringCommit) {
    RetiredMemberDuringHandoff(true);
}

TEST(NativeSocketHandoff, RetiredMemberDuringCancel) {
    RetiredMemberDuringHandoff(false);
}
