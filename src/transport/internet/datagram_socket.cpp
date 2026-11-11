#include "transport/internet/datagram_socket.hpp"

#include "common/allocator.hpp"
#include "connection_timeouts.hpp"
#include "common/buffer_util.hpp"
#include "transport/link.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <iterator>
#include <new>
#include <utility>

#include <cerrno>
#include <sys/socket.h>

namespace transport::internet {
namespace {
constexpr std::size_t kMaxActiveSockets = 4096;
constexpr std::size_t kMaxReceiveBuffers = 8;
constexpr std::size_t kMaxDatagramBytes = kMaxReceiveBuffers * buf::Buffer::kSize;
constexpr std::size_t kMaxUdpPayloadV4 = 65507;
constexpr std::size_t kMaxUdpPayloadV6 = 65527;
constexpr std::size_t kMaxNativeBuffers = 64;

std::size_t MaxUdpPayload(bool ipv6) noexcept {
    return ipv6 ? kMaxUdpPayloadV6 : kMaxUdpPayloadV4;
}

[[noreturn]] void ThrowLink(ErrorCode error) {
    throw transport::LinkError(error);
}

[[noreturn]] void ThrowCancelled(ErrorCode reason) {
    ThrowLink(reason == ErrorCode::OK ? ErrorCode::CANCELLED : reason);
}

void ValidateDestination(const udp::endpoint& destination, bool ipv6) {
    if (destination.port() == 0 || destination.address().is_v6() != ipv6)
        ThrowLink(ErrorCode::INVALID_ARGUMENT);
}


void ValidateBuffers(
    std::span<const net::const_buffer> buffers, std::size_t maximum, std::size_t& total) {
    total = 0;
    for (const auto& buffer : buffers) {
        if (buffer.size() != 0 && buffer.data() == nullptr)
            ThrowLink(ErrorCode::INVALID_ARGUMENT);
        if (buffer.size() > maximum - total)
            ThrowLink(ErrorCode::INVALID_ARGUMENT);
        total += buffer.size();
    }
}
}  // namespace

std::size_t PeekDatagramSize(udp::socket& socket, IoErrorCode& error) noexcept {
    for (;;) {
        const ssize_t size = ::recv(
            socket.native_handle(), nullptr, 0, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
        if (size >= 0) {
            error.clear();
            return static_cast<std::size_t>(size);
        }
        if (errno == EINTR) continue;
        error = IoErrorCode(errno, io_error::get_system_category());
        return 0;
    }
}

struct DatagramSocket::Impl final : memory::WorkerAllocated {
    using Timeouts = detail::ConnectionTimeouts<Impl>;

    Impl(memory::worker_memory& pool, net::io_context& io_context,
         const net::ip::address& bind_address)
        : pool(pool)
        , socket(io_context)
        , timeouts(io_context, *this)
        , ipv6(bind_address.is_v6()) {
        if (active_sockets >= kMaxActiveSockets)
            ThrowLink(ErrorCode::RESOURCE_EXHAUSTED);
        IoErrorCode ec;
        socket.open(ipv6 ? udp::v6() : udp::v4(), ec);
        if (ec) throw IoSystemError(ec);
        if (ipv6) {
            socket.set_option(net::ip::v6_only(true), ec);
            if (ec) throw IoSystemError(ec);
        }
        socket.bind(udp::endpoint(bind_address, 0), ec);
        if (ec) throw IoSystemError(ec);
        // Receive() takes a datagram synchronously after readiness; a stale
        // readiness must report would_block instead of blocking the Worker.
        socket.non_blocking(true, ec);
        if (ec) throw IoSystemError(ec);
        ++active_sockets;
        counted = true;
    }

    ~Impl() noexcept { Close(ErrorCode::CANCELLED); }

    void OnTimeout(ErrorCode reason) noexcept { Close(reason); }

    static constexpr uint8_t kReadDrainBudget = 16;

    void MarkCancelled() noexcept {
        ++cancellation_epoch_;
        read_drain_budget = 0;
    }

    net::awaitable<IoErrorCode> Wait(
        udp::socket::wait_type type, net::cancellation_slot cancellation) {
        return detail::WaitSocket(socket, type, cancellation, cancellation_epoch_);
    }
    void Close(ErrorCode reason) noexcept {
        if (closed) return;
        closed = true;
        cancellation_reason = reason == ErrorCode::OK ? ErrorCode::CANCELLED : reason;
        MarkCancelled();
        ++generation;
        cancellation.Stop(cancellation_reason);
        timeouts.Stop();
        IoErrorCode ignored;
        socket.cancel(ignored);
        socket.close(ignored);
        if (counted) {
            --active_sockets;
            counted = false;
        }
    }

    void Cancel() noexcept {
        if (closed) return;
        MarkCancelled();
        cancellation_reason = ErrorCode::CANCELLED;
        ++generation;
        cancellation.CancelPending(cancellation_reason);
        IoErrorCode ignored;
        socket.cancel(ignored);
    }

    [[nodiscard]] bool OperationCancelled(uint64_t captured) const noexcept {
        return closed || generation != captured;
    }
    [[nodiscard]] ErrorCode OperationReason(uint64_t captured) const noexcept {
        if (!OperationCancelled(captured)) return ErrorCode::OK;
        return cancellation_reason == ErrorCode::OK ? ErrorCode::CANCELLED : cancellation_reason;
    }

    net::awaitable<ReceivedDatagram> Receive(ReadOperation& operation);
    // `blocked`: the caller's send of these same buffers just hit EAGAIN
    // without suspending since, so the first pass waits instead of sending.
    net::awaitable<void> SendBuffers(
        WriteOperation& operation, udp::endpoint destination,
        std::span<const net::const_buffer> buffers, bool blocked);
    net::awaitable<void> SendMultiBuffer(
        WriteOperation& operation, udp::endpoint destination,
        buf::MultiBuffer payload);

    // Receive payload Buffers come from the owning Worker's pool.
    memory::worker_memory& pool;
    udp::socket socket;
    Timeouts timeouts;
    transport::CancellationSource cancellation;
    uint64_t generation = 0;
    uint64_t cancellation_epoch_ = 0;
    ErrorCode cancellation_reason = ErrorCode::OK;
    uint8_t read_drain_budget = 0;
    bool ipv6 = false;
    bool closed = false;
    bool counted = false;
    bool read_active = false;
    bool write_active = false;
    inline static thread_local std::size_t active_sockets = 0;
};

net::awaitable<ReceivedDatagram> DatagramSocket::Impl::Receive(ReadOperation& operation) {
    if (operation.Cancelled()) ThrowCancelled(operation.CancellationReason());
    if (closed) ThrowCancelled(cancellation_reason);
    const auto cancellation_state = co_await net::this_coro::cancellation_state;

    for (;;) {
        if (operation.Cancelled()) ThrowCancelled(operation.CancellationReason());
        if (cancellation_state.cancelled() != net::cancellation_type::none)
            throw IoSystemError(io_error::operation_aborted);
        bool fresh_wait = false;
        if (read_drain_budget != 0) {
            --read_drain_budget;
        } else {
            // An idle wait holds no payload buffer; buffers exist only between
            // readiness and the synchronous receive below.
            const auto wait_ec = co_await Wait(udp::socket::wait_read, cancellation_state.slot());
            if (wait_ec) {
                read_drain_budget = 0;
                if (operation.Cancelled()) ThrowCancelled(operation.CancellationReason());
                throw IoSystemError(wait_ec);
            }
            if (operation.Cancelled()) ThrowCancelled(operation.CancellationReason());
            fresh_wait = true;
        }

        IoErrorCode probe_ec;
        const std::size_t datagram_size = PeekDatagramSize(socket, probe_ec);
        if (probe_ec == io_error::would_block || probe_ec == io_error::try_again) {
            read_drain_budget = 0;
            continue;
        }
        if (probe_ec) {
            read_drain_budget = 0;
            throw IoSystemError(probe_ec);
        }
        const std::size_t wanted = std::clamp<std::size_t>(datagram_size, 1, kMaxDatagramBytes);
        const std::size_t count = (wanted + buf::Buffer::kSize - 1) / buf::Buffer::kSize;

        std::array<buf::BufferGuard, kMaxReceiveBuffers> guards;
        std::array<net::mutable_buffer, kMaxReceiveBuffers> buffers;
        for (std::size_t i = 0; i < count; ++i) {
            guards[i] = buf::BufferGuard(buf::Buffer::New(pool));
            if (!guards[i]) {
                read_drain_budget = 0;
                ThrowLink(ErrorCode::RESOURCE_EXHAUSTED);
            }
            buffers[i] = net::buffer(guards[i]->Tail().data(), guards[i]->Available());
        }

        udp::endpoint source;
        IoErrorCode receive_ec;
        // MSG_TRUNC makes Linux return the full datagram length, so a datagram
        // larger than kMaxDatagramBytes is detected and dropped, never
        // forwarded cut.
        const std::size_t received = socket.receive_from(
            std::span<net::mutable_buffer>(buffers.data(), count), source,
            MSG_TRUNC, receive_ec);
        if (receive_ec == io_error::would_block || receive_ec == io_error::try_again) {
            read_drain_budget = 0;
            continue;
        }
        if (receive_ec) {
            read_drain_budget = 0;
            throw IoSystemError(receive_ec);
        }
        if (fresh_wait) {
            read_drain_budget = kReadDrainBudget - 1;
        }
        if (received > count * buf::Buffer::kSize) continue;
        if (source.address().is_v6() != ipv6) ThrowLink(ErrorCode::INTERNAL);

        buf::MultiBuffer payload;
        std::size_t remaining = received;
        for (std::size_t i = 0; i < count && (remaining != 0 || i == 0); ++i) {
            const auto produced = std::min<std::size_t>(remaining, guards[i]->Available());
            guards[i]->Produce(static_cast<uint32_t>(produced));
            remaining -= produced;
            payload.push_back(std::move(guards[i]));
        }
        co_return ReceivedDatagram{std::move(source), std::move(payload)};
    }
}

net::awaitable<void> DatagramSocket::Impl::SendBuffers(
    WriteOperation& operation, udp::endpoint destination,
    std::span<const net::const_buffer> buffers, bool blocked) {
    if (operation.Cancelled()) ThrowCancelled(operation.CancellationReason());
    if (closed) ThrowCancelled(cancellation_reason);
    ValidateDestination(destination, ipv6);
    std::size_t total = 0;
    ValidateBuffers(buffers, MaxUdpPayload(ipv6), total);

    memory::ByteVector merged;
    std::array<net::const_buffer, 1> single{};
    if (buffers.size() > kMaxNativeBuffers) {
        try {
            merged.reserve(total);
            for (const auto& buffer : buffers) {
                if (buffer.size() == 0) continue;
                const auto* first = static_cast<const uint8_t*>(buffer.data());
                merged.insert(merged.end(), first, first + buffer.size());
            }
        } catch (const std::bad_alloc&) {
            ThrowLink(ErrorCode::RESOURCE_EXHAUSTED);
        }
        single[0] = net::buffer(merged.data(), merged.size());
        buffers = single;
    }
    if (buffers.empty()) buffers = single; // Preserve an actual zero-length datagram.
    const auto cancellation_state = co_await net::this_coro::cancellation_state;
    for (;; blocked = false) {
        if (operation.Cancelled()) ThrowCancelled(operation.CancellationReason());
        if (cancellation_state.cancelled() != net::cancellation_type::none)
            throw IoSystemError(io_error::operation_aborted);
        if (!blocked) {
            IoErrorCode send_ec;
            // Send synchronously on the owning Worker. Native readiness is needed
            // only for backpressure and never retains payload pointers.
            const auto sent = socket.send_to(buffers, destination, 0, send_ec);
            if (!send_ec) {
                if (sent != total) ThrowLink(ErrorCode::INTERNAL);
                break;
            }
            if (send_ec != io_error::would_block && send_ec != io_error::try_again)
                throw IoSystemError(send_ec);
        }
        const auto wait_ec = co_await Wait(udp::socket::wait_write, cancellation_state.slot());
        if (operation.Cancelled()) ThrowCancelled(operation.CancellationReason());
        if (wait_ec) throw IoSystemError(wait_ec);
    }
    timeouts.TouchActivity();
}

net::awaitable<void> DatagramSocket::Impl::SendMultiBuffer(
    WriteOperation& operation, udp::endpoint destination, buf::MultiBuffer payload) {
    if (operation.Cancelled()) ThrowCancelled(operation.CancellationReason());
    if (closed) ThrowCancelled(cancellation_reason);
    ValidateDestination(destination, ipv6);
    const auto maximum = MaxUdpPayload(ipv6);
    if (payload.byte_size() > maximum)
        ThrowLink(ErrorCode::INVALID_ARGUMENT);
    std::size_t total = 0;
    for (const auto* buffer : payload) {
        if (!buffer || buffer->Bytes().size() > maximum - total)
            ThrowLink(ErrorCode::INVALID_ARGUMENT);
        total += buffer->Bytes().size();
    }
    if (total != payload.byte_size()) ThrowLink(ErrorCode::INVALID_ARGUMENT);

    const auto cancellation_state = co_await net::this_coro::cancellation_state;
    if (operation.Cancelled()) ThrowCancelled(operation.CancellationReason());
    if (cancellation_state.cancelled() != net::cancellation_type::none)
        throw IoSystemError(io_error::operation_aborted);
    if (payload.size() <= buf::MultiBuffer::kInlineCapacity) {
        std::array<net::const_buffer, buf::MultiBuffer::kInlineCapacity> inline_buffers;
        std::size_t count = 0;
        for (const auto* buffer : payload) {
            const auto bytes = buffer->Bytes();
            if (!bytes.empty()) {
                inline_buffers[count++] = net::buffer(bytes.data(), bytes.size());
            }
        }
        const std::span<const net::const_buffer> buffers(inline_buffers.data(), count);
        IoErrorCode send_ec;
        std::size_t sent = 0;
        {
            const net::const_buffer empty_datagram{};
            sent = socket.send_to(
                count == 0 ? std::span<const net::const_buffer>(&empty_datagram, 1) : buffers,
                destination, 0, send_ec);
        }
        if (!send_ec) {
            if (sent != total) ThrowLink(ErrorCode::INTERNAL);
            timeouts.TouchActivity();
            co_return;
        }
        if (send_ec != io_error::would_block && send_ec != io_error::try_again) {
            throw IoSystemError(send_ec);
        }
        // Nothing suspended since the EAGAIN: wait before resending these descriptors.
        co_await SendBuffers(operation, std::move(destination), buffers, true);
        co_return;
    }
    ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> spans;
    try {
        spans.AppendMultiBuffer(payload);
    } catch (const std::bad_alloc&) {
        ThrowLink(ErrorCode::RESOURCE_EXHAUSTED);
    }
    co_await SendBuffers(operation, std::move(destination), spans.Span(), false);
}

DatagramSocket::ReadOperation::ReadOperation(Impl& impl)
    : impl_(&impl)
    , generation_(impl.generation) {
    if (impl.closed) ThrowCancelled(impl.cancellation_reason);
    if (impl.read_active) ThrowLink(ErrorCode::INVALID_ARGUMENT);
    try {
        impl.timeouts.BeginRead();
    } catch (const std::bad_alloc&) {
        ThrowLink(ErrorCode::RESOURCE_EXHAUSTED);
    }
    impl.read_active = true;
}

DatagramSocket::ReadOperation::~ReadOperation() noexcept {
    if (!impl_) return;
    impl_->read_active = false;
    impl_->timeouts.EndRead();
}

bool DatagramSocket::ReadOperation::Cancelled() const noexcept {
    return impl_->OperationCancelled(generation_);
}

ErrorCode DatagramSocket::ReadOperation::CancellationReason() const noexcept {
    return impl_->OperationReason(generation_);
}

net::awaitable<ReceivedDatagram> DatagramSocket::ReadOperation::Receive() {
    return impl_->Receive(*this);
}

DatagramSocket::WriteOperation::WriteOperation(Impl& impl)
    : impl_(&impl)
    , generation_(impl.generation) {
    if (impl.closed) ThrowCancelled(impl.cancellation_reason);
    if (impl.write_active) ThrowLink(ErrorCode::INVALID_ARGUMENT);
    try {
        impl.timeouts.BeginWrite();
    } catch (const std::bad_alloc&) {
        ThrowLink(ErrorCode::RESOURCE_EXHAUSTED);
    }
    impl.write_active = true;
}

DatagramSocket::WriteOperation::~WriteOperation() noexcept {
    if (!impl_) return;
    impl_->write_active = false;
    impl_->timeouts.EndWrite();
}

void DatagramSocket::WriteOperation::CheckAvailable() {
    if (Cancelled()) ThrowCancelled(CancellationReason());
    if (send_started_) ThrowLink(ErrorCode::INVALID_ARGUMENT);
    send_started_ = true;
}

bool DatagramSocket::WriteOperation::Cancelled() const noexcept {
    return impl_->OperationCancelled(generation_);
}

ErrorCode DatagramSocket::WriteOperation::CancellationReason() const noexcept {
    return impl_->OperationReason(generation_);
}

net::awaitable<void> DatagramSocket::WriteOperation::SendTo(
    udp::endpoint destination, std::span<const net::const_buffer> buffers) {
    CheckAvailable();
    return impl_->SendBuffers(*this, std::move(destination), buffers, false);
}

net::awaitable<void> DatagramSocket::WriteOperation::SendTo(
    udp::endpoint destination, buf::MultiBuffer payload) {
    CheckAvailable();
    return impl_->SendMultiBuffer(*this, std::move(destination), std::move(payload));
}

DatagramSocket::DatagramSocket(
    memory::worker_memory& pool, net::io_context& io_context,
    const net::ip::address& bind_address)
    : impl_(memory::MakeUnique<Impl>(pool, pool, io_context, bind_address)) {}

DatagramSocket::~DatagramSocket() noexcept { Close(); }

DatagramSocket::ReadOperation DatagramSocket::StartRead() { return ReadOperation(*impl_); }
DatagramSocket::WriteOperation DatagramSocket::StartWrite() { return WriteOperation(*impl_); }

void DatagramSocket::SetIdleTimeout(std::chrono::seconds timeout) {
    try { impl_->timeouts.SetIdleTimeout(timeout); }
    catch (const std::bad_alloc&) { ThrowLink(ErrorCode::RESOURCE_EXHAUSTED); }
}
void DatagramSocket::SetReadTimeout(std::chrono::seconds timeout) {
    try { impl_->timeouts.SetReadTimeout(timeout); }
    catch (const std::bad_alloc&) { ThrowLink(ErrorCode::RESOURCE_EXHAUSTED); }
}
void DatagramSocket::SetWriteTimeout(std::chrono::seconds timeout) {
    try { impl_->timeouts.SetWriteTimeout(timeout); }
    catch (const std::bad_alloc&) { ThrowLink(ErrorCode::RESOURCE_EXHAUSTED); }
}
PhaseDeadlineHandle DatagramSocket::StartPhaseDeadline(std::chrono::seconds timeout) {
    try { return impl_->timeouts.StartPhaseDeadline(timeout); }
    catch (const std::bad_alloc&) { ThrowLink(ErrorCode::RESOURCE_EXHAUSTED); }
}
void DatagramSocket::ClearPhaseDeadline() noexcept { impl_->timeouts.ClearPhaseDeadline(); }
bool DatagramSocket::ConsumeIdleTimeout() noexcept { return impl_->timeouts.ConsumeIdleTimeout(); }
bool DatagramSocket::ConsumeReadTimeout() noexcept { return impl_->timeouts.ConsumeReadTimeout(); }
bool DatagramSocket::ConsumeWriteTimeout() noexcept { return impl_->timeouts.ConsumeWriteTimeout(); }
bool DatagramSocket::ConsumePhaseDeadline() noexcept { return impl_->timeouts.ConsumePhaseDeadline(); }
void DatagramSocket::TouchActivity() noexcept { impl_->timeouts.TouchActivity(); }
CancellationSource& DatagramSocket::Cancellation() noexcept { return impl_->cancellation; }
void DatagramSocket::Cancel() noexcept { impl_->Cancel(); }
void DatagramSocket::Close() noexcept { impl_->Close(ErrorCode::CANCELLED); }
bool DatagramSocket::IsIPv6() const noexcept { return impl_->ipv6; }

udp::endpoint DatagramSocket::LocalEndpoint() const {
    IoErrorCode ec;
    auto endpoint = impl_->socket.local_endpoint(ec);
    if (ec) throw IoSystemError(ec);
    return endpoint;
}

std::size_t DatagramSocket::ActiveCount() noexcept {
    return Impl::active_sockets;
}

}  // namespace transport::internet
