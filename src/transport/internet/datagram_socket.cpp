#include "acppnode/transport/internet/datagram_socket.hpp"

#include "acppnode/common/allocator.hpp"
#include "connection_timeouts.hpp"
#include "acppnode/transport/link_error.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <iterator>
#include <new>
#include <utility>

namespace acpp::transport::internet {
namespace {
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

void ThrowIfCancelled(ErrorCode reason) {
    ThrowLink(reason == ErrorCode::OK ? ErrorCode::CANCELLED : reason);
}

void ValidateDestination(const udp::endpoint& destination, bool ipv6) {
    if (destination.port() == 0 || destination.address().is_v6() != ipv6)
        ThrowLink(ErrorCode::INVALID_ARGUMENT);
}

struct MultiBufferSequence {
    struct Iterator {
        using iterator_category = std::forward_iterator_tag;
        using value_type = net::const_buffer;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = value_type;

        buf::Buffer* const* current = nullptr;
        net::const_buffer operator*() const noexcept {
            const auto bytes = (*current)->Bytes();
            return net::buffer(bytes.data(), bytes.size());
        }
        Iterator& operator++() noexcept { ++current; return *this; }
        Iterator operator++(int) noexcept { auto copy = *this; ++*this; return copy; }
        friend bool operator==(const Iterator& lhs, const Iterator& rhs) noexcept {
            return lhs.current == rhs.current;
        }
    };

    const buf::MultiBuffer& payload;
    Iterator begin() const noexcept { return {payload.begin()}; }
    Iterator end() const noexcept { return {payload.end()}; }
};

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

struct DatagramSocket::Impl final : memory::DataAllocated {
    using Timeouts = detail::ConnectionTimeouts<Impl>;

    Impl(net::any_io_executor executor, const net::ip::address& bind_address)
        : socket(executor)
        , timeouts(executor, *this)
        , ipv6(bind_address.is_v6()) {
        IoErrorCode ec;
        socket.open(ipv6 ? udp::v6() : udp::v4(), ec);
        if (ec) throw IoSystemError(ec);
        // Some platforms default to buffers smaller than a valid UDP payload.
        // Preserve larger defaults, but allow one full datagram in each direction.
        const auto ensure_capacity = [this](auto option) {
            socket.get_option(option);
            if (option.value() < static_cast<int>(kMaxDatagramBytes)) {
                socket.set_option(decltype(option){static_cast<int>(kMaxDatagramBytes)});
            }
        };
        ensure_capacity(net::socket_base::send_buffer_size{});
        ensure_capacity(net::socket_base::receive_buffer_size{});
        if (ipv6) {
            socket.set_option(net::ip::v6_only(true), ec);
            if (ec) throw IoSystemError(ec);
        }
        socket.bind(udp::endpoint(bind_address, 0), ec);
        if (ec) throw IoSystemError(ec);
    }

    ~Impl() noexcept { Close(ErrorCode::CANCELLED); }

    void OnTimeout(ErrorCode reason) noexcept { Close(reason); }

    void Close(ErrorCode reason) noexcept {
        if (closed) return;
        closed = true;
        cancellation_reason = reason == ErrorCode::OK ? ErrorCode::CANCELLED : reason;
        ++generation;
        cancellation.Stop(cancellation_reason);
        timeouts.Stop();
        IoErrorCode ignored;
        socket.cancel(ignored);
        socket.close(ignored);
    }

    void Cancel(ErrorCode reason = ErrorCode::CANCELLED) noexcept {
        if (closed) return;
        cancellation_reason = reason == ErrorCode::OK ? ErrorCode::CANCELLED : reason;
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
    net::awaitable<void> SendBuffers(
        WriteOperation& operation, udp::endpoint destination,
        std::span<const net::const_buffer> buffers);
    net::awaitable<void> SendMultiBuffer(
        WriteOperation& operation, udp::endpoint destination, buf::MultiBuffer payload);

    udp::socket socket;
    Timeouts timeouts;
    transport::CancellationSource cancellation;
    uint64_t generation = 0;
    ErrorCode cancellation_reason = ErrorCode::OK;
    bool ipv6 = false;
    bool closed = false;
    bool read_active = false;
    bool write_active = false;

};

net::awaitable<ReceivedDatagram> DatagramSocket::Impl::Receive(ReadOperation& operation) {
    if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
    if (closed) ThrowIfCancelled(cancellation_reason);

    auto [wait_ec] = co_await socket.async_wait(
        udp::socket::wait_read,
        net::bind_allocator(memory::DataAllocator<std::byte>{},
            net::as_tuple(net::use_awaitable)));
    if (wait_ec) {
        if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
        throw IoSystemError(wait_ec);
    }
    if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());

    IoErrorCode available_ec;
    const std::size_t available = socket.available(available_ec);
    if (available_ec) throw IoSystemError(available_ec);
    const std::size_t wanted = std::clamp<std::size_t>(available, 1, kMaxDatagramBytes);
    const std::size_t count = (wanted + buf::Buffer::kSize - 1) / buf::Buffer::kSize;

    std::array<buf::BufferGuard, kMaxReceiveBuffers> guards;
    std::array<net::mutable_buffer, kMaxReceiveBuffers> buffers;
    for (std::size_t i = 0; i < count; ++i) {
        guards[i] = buf::BufferGuard(buf::Buffer::New());
        if (!guards[i]) ThrowLink(ErrorCode::RESOURCE_EXHAUSTED);
        buffers[i] = net::buffer(guards[i]->Tail().data(), guards[i]->Available());
    }

    udp::endpoint source;
    auto [receive_ec, received] = co_await socket.async_receive_from(
        std::span<net::mutable_buffer>(buffers.data(), count), source,
        net::bind_allocator(memory::DataAllocator<std::byte>{},
            net::as_tuple(net::use_awaitable)));
    if (receive_ec) {
        if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
        // In particular, never forward a truncated datagram.
        throw IoSystemError(receive_ec);
    }
    if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
    if (source.address().is_v6() != ipv6) ThrowLink(ErrorCode::INTERNAL);

    buf::MultiBuffer payload;
    std::size_t remaining = received;
    for (std::size_t i = 0; i < count && remaining != 0; ++i) {
        const auto produced = std::min<std::size_t>(remaining, guards[i]->Available());
        guards[i]->Produce(static_cast<uint32_t>(produced));
        remaining -= produced;
        payload.push_back(std::move(guards[i]));
    }
    if (remaining != 0) ThrowLink(ErrorCode::INTERNAL);
    co_return ReceivedDatagram{std::move(source), std::move(payload)};
}

net::awaitable<void> DatagramSocket::Impl::SendBuffers(
    WriteOperation& operation, udp::endpoint destination,
    std::span<const net::const_buffer> buffers) {
    if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
    if (closed) ThrowIfCancelled(cancellation_reason);
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
    auto [send_ec, sent] = co_await socket.async_send_to(
        buffers, destination,
        net::bind_allocator(memory::DataAllocator<std::byte>{},
            net::as_tuple(net::use_awaitable)));
    if (send_ec) {
        if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
        throw IoSystemError(send_ec);
    }
    if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
    if (sent != total) ThrowLink(ErrorCode::INTERNAL);
    timeouts.TouchActivity();
}

net::awaitable<void> DatagramSocket::Impl::SendMultiBuffer(
    WriteOperation& operation, udp::endpoint destination, buf::MultiBuffer payload) {
    if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
    if (closed) ThrowIfCancelled(cancellation_reason);
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

    memory::ByteVector merged;
    MultiBufferSequence sequence{payload};
    std::array<net::const_buffer, 1> single{};
    if (payload.size() > kMaxNativeBuffers) {
        try {
            merged.reserve(total);
            for (const auto* buffer : payload) {
                const auto bytes = buffer->Bytes();
                merged.insert(merged.end(), bytes.begin(), bytes.end());
            }
        } catch (const std::bad_alloc&) {
            ThrowLink(ErrorCode::RESOURCE_EXHAUSTED);
        }
        single[0] = net::buffer(merged.data(), merged.size());
    }
    IoErrorCode send_ec;
    std::size_t sent = 0;
    if (payload.size() > kMaxNativeBuffers) {
        auto [ec, bytes] = co_await socket.async_send_to(
            std::span<const net::const_buffer>(single.data(), 1), destination,
            net::bind_allocator(memory::DataAllocator<std::byte>{},
                net::as_tuple(net::use_awaitable)));
        send_ec = ec;
        sent = bytes;
    } else {
        auto [ec, bytes] = co_await socket.async_send_to(
            sequence, destination,
            net::bind_allocator(memory::DataAllocator<std::byte>{},
                net::as_tuple(net::use_awaitable)));
        send_ec = ec;
        sent = bytes;
    }
    if (send_ec) {
        if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
        throw IoSystemError(send_ec);
    }
    if (operation.Cancelled()) ThrowIfCancelled(operation.CancellationReason());
    if (sent != total) ThrowLink(ErrorCode::INTERNAL);
    timeouts.TouchActivity();
}

DatagramSocket::ReadOperation::ReadOperation(Impl& impl)
    : impl_(&impl)
    , generation_(impl.generation) {
    if (impl.closed) ThrowIfCancelled(impl.cancellation_reason);
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
    if (impl.closed) ThrowIfCancelled(impl.cancellation_reason);
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
    if (Cancelled()) ThrowIfCancelled(CancellationReason());
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
    return impl_->SendBuffers(*this, std::move(destination), buffers);
}

net::awaitable<void> DatagramSocket::WriteOperation::SendTo(
    udp::endpoint destination, buf::MultiBuffer payload) {
    CheckAvailable();
    return impl_->SendMultiBuffer(*this, std::move(destination), std::move(payload));
}

DatagramSocket::DatagramSocket(
    net::any_io_executor executor, const net::ip::address& bind_address)
    : impl_(std::make_unique<Impl>(executor, bind_address)) {}

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


}  // namespace acpp::transport::internet
