#include "acppnode/app/udp_session.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/udp_endpoint_key.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "udp_callback_router.hpp"
#include "udp_receive_buffer.hpp"

#include <new>
#include <optional>
#include <span>
#include <utility>

namespace acpp {

namespace {

static UdpEndpointKey MakeEndpointKey(const net::ip::address& addr, uint16_t port) {
    return {iputil::NormalizeAddress(addr), port};
}

static std::string EndpointKeyToString(const UdpEndpointKey& key) {
    return iputil::FormatEndpointForLog(
        iputil::NormalizeAddressString(key.address),
        key.port);
}

static std::optional<net::ip::address> SelectAddressForSocket(
    std::span<const net::ip::address> addresses,
    const udp::socket& socket) {
    if (addresses.empty()) {
        return std::nullopt;
    }

    IoErrorCode ec;
    const auto local_ep = socket.local_endpoint(ec);
    if (ec) {
        return addresses.front();
    }

    const bool want_v6 = local_ep.address().is_v6();
    for (const auto& addr : addresses) {
        if (addr.is_v6() == want_v6) {
            return addr;
        }
    }

    return addresses.front();
}

}  // namespace

struct UDPSession::Impl {
    static constexpr size_t kMaxIpv4UdpPayload = 65507;
    static constexpr size_t kMaxIpv6UdpPayload = 65527;

    Impl(net::io_context& io_context,
         const std::string& session_id,
         ::acpp::app::dns::DNS& dns_service)
        : io_context(io_context)
        , session_id(session_id)
        , dns_service(dns_service)
        , socket(io_context)
        , last_active(std::chrono::steady_clock::now()) {}

    void Touch() { last_active = std::chrono::steady_clock::now(); }
    static net::awaitable<void> RunReceive(std::shared_ptr<Impl> self);
    net::awaitable<void> DoReceive();
    net::awaitable<std::pair<ErrorCode, udp::endpoint>> ResolveEndpoint(
        const TargetAddress& target);

    template <typename ConstBufferSequence>
    net::awaitable<ErrorCode> SendResolved(
        udp::endpoint remote_ep,
        ConstBufferSequence buffers,
        size_t payload_size,
        uint64_t callback_id) {
        const size_t max_payload = remote_ep.address().is_v4()
            ? kMaxIpv4UdpPayload
            : kMaxIpv6UdpPayload;
        if (payload_size == 0) {
            co_return ErrorCode::SUCCESS;
        }
        if (payload_size > max_payload) {
            co_return ErrorCode::INVALID_ARGUMENT;
        }

        detail::UdpCallbackRouter::MappingToken mapping_token;
        try {
            if (callback_id > 0) {
                const UdpEndpointKey target_key = MakeEndpointKey(
                    remote_ep.address(), remote_ep.port());
                auto [mapping_error, token] = callbacks.TrackTarget(
                    target_key, callback_id, steady_clock::now());
                if (mapping_error != ErrorCode::OK) {
                    co_return mapping_error;
                }
                mapping_token = token;
            }

            const size_t sent = co_await socket.async_send_to(
                buffers, remote_ep, net::use_awaitable);
            if (sent != payload_size) {
                callbacks.RollbackTarget(mapping_token);
                co_return ErrorCode::NETWORK_IO_ERROR;
            }
            callbacks.CommitTarget(mapping_token);
            ++packets_sent;
            bytes_sent += sent;
            Touch();
            co_return ErrorCode::SUCCESS;
        } catch (const IoSystemError& e) {
            callbacks.RollbackTarget(mapping_token);
            LOG_ACCESS_DEBUG("UDP session {} SendTo error: {}", session_id, e.what());
            co_return ErrorCode::NETWORK_IO_ERROR;
        } catch (const std::bad_alloc&) {
            callbacks.RollbackTarget(mapping_token);
            co_return ErrorCode::RESOURCE_EXHAUSTED;
        }
    }

    net::io_context& io_context;
    std::string session_id;
    ::acpp::app::dns::DNS& dns_service;

    detail::UdpCallbackRouter callbacks;

    udp::socket socket;
    net::ip::address bind_address;
    uint16_t local_port = 0;
    udp::endpoint sender_endpoint;

    std::chrono::steady_clock::time_point last_active;
    bool running = false;
    bool receive_started = false;

    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
};

// ============================================================================
// UDPSession (Per-Worker, 单线程访问，无需锁)
// ============================================================================

UDPSession::UDPSession(net::io_context& io_context,
                       const std::string& session_id,
                       ::acpp::app::dns::DNS& dns_service)
    : impl_(std::make_shared<Impl>(io_context, session_id, dns_service)) {
}

UDPSession::~UDPSession() {
    if (impl_->running || impl_->receive_started || impl_->socket.is_open()) {
        LOG_ACCESS_DEBUG("UDP session {} destroyed without Stop(), forced close", impl_->session_id);
    }
    Stop();
}

ErrorCode UDPSession::Start(const net::ip::address& bind_address) {
    std::string last_error = "bind failed";

    try {
        udp::endpoint local_ep(bind_address, 0);  // 端口 0 = 自动分配
        udp::socket sock(impl_->io_context);
        sock.open(local_ep.protocol());
        sock.set_option(udp::socket::reuse_address(true));
        sock.bind(local_ep);

        impl_->socket = std::move(sock);
        impl_->bind_address = iputil::NormalizeAddress(bind_address);
        impl_->local_port = impl_->socket.local_endpoint().port();
        impl_->running = true;

        LOG_ACCESS_DEBUG("UDP session {} started on {}",
                         impl_->session_id,
                         iputil::FormatEndpointForLog(
                             bind_address.to_string(), impl_->local_port));
        return ErrorCode::SUCCESS;
    } catch (const IoSystemError& e) {
        last_error = e.what();
    }

    LOG_CONN_FAIL("UDP session {} start failed: {}", impl_->session_id, last_error);
    return ErrorCode::NETWORK_BIND_FAILED;
}

// ============================================================================
// UDP 发送接口实现
// ============================================================================

net::awaitable<std::pair<ErrorCode, udp::endpoint>>
UDPSession::Impl::ResolveEndpoint(const TargetAddress& target) {
    if (!target.IsValid()) {
        co_return std::make_pair(
            ErrorCode::PROTOCOL_INVALID_ADDRESS, udp::endpoint{});
    }
    if (target.resolved_addr) {
        co_return std::make_pair(
            ErrorCode::SUCCESS,
            udp::endpoint(*target.resolved_addr, target.port));
    }
    if (!target.IsDomain()) {
        co_return std::make_pair(
            ErrorCode::PROTOCOL_INVALID_ADDRESS, udp::endpoint{});
    }

    try {
        auto dns_result = co_await dns_service.Resolve(target.host);
        if (!dns_result.Ok()) {
            LOG_ACCESS_DEBUG(
                "UDP session {} DNS resolve failed for {}", session_id, target.host);
            co_return std::make_pair(
                ErrorCode::DNS_RESOLVE_FAILED, udp::endpoint{});
        }

        auto selected_addr = SelectAddressForSocket(dns_result.addresses, socket);
        if (!selected_addr || selected_addr->is_unspecified()) {
            co_return std::make_pair(
                ErrorCode::DNS_RESOLVE_FAILED, udp::endpoint{});
        }
        co_return std::make_pair(
            ErrorCode::SUCCESS, udp::endpoint(*selected_addr, target.port));
    } catch (const IoSystemError& e) {
        LOG_ACCESS_DEBUG(
            "UDP session {} endpoint resolve error: {}", session_id, e.what());
        co_return std::make_pair(
            ErrorCode::NETWORK_IO_ERROR, udp::endpoint{});
    }
}

net::awaitable<ErrorCode> UDPSession::SendTo(
    const TargetAddress& target,
    const uint8_t* data,
    size_t len,
    uint64_t callback_id) {

    if (!impl_->running) {
        co_return ErrorCode::CONNECTION_CLOSED;
    }
    if (len == 0) {
        co_return ErrorCode::SUCCESS;
    }
    if (!data) {
        co_return ErrorCode::INVALID_ARGUMENT;
    }

    auto [resolve_error, remote_ep] = co_await impl_->ResolveEndpoint(target);
    if (resolve_error != ErrorCode::SUCCESS) {
        co_return resolve_error;
    }
    co_return co_await impl_->SendResolved(
        remote_ep, net::buffer(data, len), len, callback_id);
}

net::awaitable<ErrorCode> UDPSession::SendTo(
    const TargetAddress& target,
    buf::MultiBuffer payload,
    uint64_t callback_id) {

    if (!impl_->running) {
        co_return ErrorCode::CONNECTION_CLOSED;
    }

    if (!buf::HasData(payload)) {
        co_return ErrorCode::SUCCESS;
    }

    try {
        std::array<net::const_buffer, buf::MultiBuffer::kInlineCapacity> inline_send_buffers{};
        memory::ThreadLocalVector<net::const_buffer> spill_send_buffers;
        size_t send_buffer_count = 0;
        size_t payload_size = 0;
        for (const auto* buffer : payload) {
            if (buffer && !buffer->IsEmpty()) {
                const auto bytes = buffer->Bytes();
                if (bytes.size() > Impl::kMaxIpv6UdpPayload - payload_size) {
                    co_return ErrorCode::INVALID_ARGUMENT;
                }
                payload_size += bytes.size();
                net::const_buffer send_buffer{bytes.data(), bytes.size()};
                if (send_buffer_count < inline_send_buffers.size()) {
                    inline_send_buffers[send_buffer_count++] = send_buffer;
                    continue;
                }
                if (spill_send_buffers.empty()) {
                    spill_send_buffers.reserve(payload.size());
                    spill_send_buffers.insert(
                        spill_send_buffers.end(),
                        inline_send_buffers.begin(),
                        inline_send_buffers.begin() + send_buffer_count);
                }
                spill_send_buffers.emplace_back(send_buffer);
                ++send_buffer_count;
            }
        }

        if (send_buffer_count == 0) {
            co_return ErrorCode::SUCCESS;
        }

        auto [resolve_error, remote_ep] = co_await impl_->ResolveEndpoint(target);
        if (resolve_error != ErrorCode::SUCCESS) {
            co_return resolve_error;
        }

        auto send_buffers = spill_send_buffers.empty()
            ? std::span<const net::const_buffer>(
                inline_send_buffers.data(),
                send_buffer_count)
            : std::span<const net::const_buffer>(
                spill_send_buffers.data(),
                spill_send_buffers.size());

        co_return co_await impl_->SendResolved(
            remote_ep, send_buffers, payload_size, callback_id);

    } catch (const std::bad_alloc&) {
        co_return ErrorCode::RESOURCE_EXHAUSTED;
    }
}

ErrorCode UDPSession::StartReceive() {
    if (!impl_->running || impl_->receive_started) {
        return ErrorCode::INTERNAL;
    }

    impl_->receive_started = true;
    try {
        net::co_spawn(
            impl_->io_context.get_executor(),
            Impl::RunReceive(impl_),
            [](std::exception_ptr) {});
    } catch (const std::bad_alloc&) {
        impl_->receive_started = false;
        return ErrorCode::RESOURCE_EXHAUSTED;
    } catch (...) {
        impl_->receive_started = false;
        return ErrorCode::INTERNAL;
    }
    return ErrorCode::SUCCESS;
}

// Per-Worker 简化版：无需 executor 参数
uint64_t UDPSession::RegisterCallback(PacketCallback callback) {
    if (!impl_->running || !callback ||
        impl_->callbacks.RegisteredCount() >=
            detail::UdpCallbackRouter::kMaxCallbacks) {
        LOG_ACCESS_DEBUG(
            "UDP session {} rejected Full Cone callback running={} registered={}",
            impl_->session_id,
            impl_->running,
            impl_->callbacks.RegisteredCount());
        return 0;
    }

    const uint64_t id = impl_->callbacks.Register(std::move(callback));
    if (id == 0) {
        return 0;
    }

    LOG_ACCESS_DEBUG("UDP session {} registered Full Cone callback {}", impl_->session_id, id);
    return id;
}

void UDPSession::UnregisterCallback(uint64_t callback_id) {
    if (impl_->callbacks.Unregister(callback_id)) {
        LOG_ACCESS_DEBUG("UDP session {} unregistered Full Cone callback {}", impl_->session_id, callback_id);
    }
}

net::awaitable<void> UDPSession::Impl::RunReceive(std::shared_ptr<Impl> self) {
    try {
        co_await self->DoReceive();
    } catch (const std::exception& e) {
        LOG_CONN_FAIL("UDP session {} receive loop failed: {}",
                      self->session_id, e.what());
    } catch (...) {
        LOG_CONN_FAIL("UDP session {} receive loop failed with unknown error",
                      self->session_id);
    }

    self->receive_started = false;
    if (self->running) {
        LOG_CONN_FAIL("UDP session {} receive loop stopped unexpectedly",
                      self->session_id);
        self->running = false;
        IoErrorCode ec;
        self->socket.cancel(ec);
        self->socket.close(ec);
    }
}

net::awaitable<void> UDPSession::Impl::DoReceive() {
    while (running) {
        auto [wait_ec] = co_await socket.async_wait(
            udp::socket::wait_read,
            net::as_tuple(net::use_awaitable));
        if (wait_ec == io_error::operation_aborted) {
            co_return;
        }
        if (wait_ec) {
            LOG_ACCESS_DEBUG("UDP session {} wait error: {} ({})",
                             session_id, wait_ec.message(), wait_ec.value());
            continue;
        }

        IoErrorCode available_ec;
        const size_t available_bytes = socket.available(available_ec);
        if (available_ec) {
            LOG_ACCESS_DEBUG("UDP session {} available error: {} ({})",
                             session_id,
                             available_ec.message(), available_ec.value());
            continue;
        }

        detail::UdpReceiveBuffer receive_buffer;
        const auto storage = receive_buffer.Prepare(available_bytes);
        if (storage.size() == 0) {
            co_return;
        }

        auto [ec, bytes] = co_await socket.async_receive_from(
            storage,
            sender_endpoint,
            net::as_tuple(net::use_awaitable));
        if (ec == io_error::operation_aborted) {
            co_return;
        }
        if (ec) {
            LOG_ACCESS_DEBUG("UDP session {} receive error: {} ({})",
                             session_id, ec.message(), ec.value());
            continue;
        }
        if (bytes == 0) {
            continue;
        }

        const UdpEndpointKey sender_key = MakeEndpointKey(
            sender_endpoint.address(), sender_endpoint.port());
        const auto now = steady_clock::now();
        callbacks.Prune(now);

        LOG_ACCESS_DEBUG("UDP session {} received {} bytes from {}",
                         session_id, bytes, EndpointKeyToString(sender_key));

        packets_received++;
        bytes_received += bytes;
        Touch();

        TargetAddress source;
        source.type = sender_endpoint.address().is_v6()
            ? AddressType::IPv6
            : AddressType::IPv4;
        source.resolved_addr = sender_endpoint.address();
        source.port = sender_endpoint.port();

        const auto received = receive_buffer.Data(bytes);
        UDPPacketView packet_view{
            source,
            received};

        const bool delivered = callbacks.Dispatch(
            sender_key, packet_view, now);

        if (!delivered) {
            LOG_ACCESS_DEBUG("UDP session {} no callback for {}",
                             session_id, EndpointKeyToString(sender_key));
        }
    }
    co_return;
}

void UDPSession::Stop() {
    const bool was_active = impl_->running || impl_->socket.is_open() ||
        impl_->callbacks.RegisteredCount() != 0 ||
        impl_->callbacks.TargetMappingCount() != 0;
    impl_->running = false;

    IoErrorCode ec;
    impl_->socket.cancel(ec);
    impl_->socket.close(ec);

    impl_->callbacks.Clear();

    if (was_active) {
        LOG_ACCESS_DEBUG("UDP session {} stopped, sent: {} pkts/{} bytes, recv: {} pkts/{} bytes",
                  impl_->session_id, impl_->packets_sent, impl_->bytes_sent,
                  impl_->packets_received, impl_->bytes_received);
    }
}

void UDPSession::Touch() {
    impl_->Touch();
}

bool UDPSession::IsRunning() const noexcept {
    return impl_->running && impl_->receive_started;
}

bool UDPSession::CanRetire(std::chrono::seconds timeout) const {
    return !IsRunning() ||
        std::chrono::steady_clock::now() - impl_->last_active > timeout;
}

uint16_t UDPSession::LocalPort() const {
    return impl_->local_port;
}

bool UDPSession::UsesBindAddress(
    const net::ip::address& bind_address) const {
    return impl_->bind_address == iputil::NormalizeAddress(bind_address);
}

// ============================================================================
// UDPSessionManager (Per-Worker, 单线程访问，无需锁)
// ============================================================================

struct UDPSessionManager::Impl {
    static constexpr size_t kMaxSessions = 4096;

    Impl(net::io_context& io_context,
         ::acpp::app::dns::DNS& dns_service,
         std::chrono::seconds session_timeout)
        : io_context(io_context)
        , dns_service(dns_service)
        , session_timeout(session_timeout) {}

    net::io_context& io_context;
    ::acpp::app::dns::DNS& dns_service;
    std::chrono::seconds session_timeout;
    memory::ThreadLocalUnorderedMap<
        std::string,
        std::shared_ptr<UDPSession>> sessions;
    TimeoutToken cleanup_token;
    bool running = false;
};

UDPSessionManager::UDPSessionManager(net::io_context& io_context,
                                     ::acpp::app::dns::DNS& dns_service,
                                     std::chrono::seconds session_timeout)
    : impl_(std::make_unique<Impl>(io_context, dns_service, session_timeout)) {
}

UDPSessionManager::~UDPSessionManager() {
    StopAll();
}

std::expected<std::shared_ptr<UDPSession>, ErrorCode>
UDPSessionManager::AcquireSession(
    const std::string& session_id,
    const net::ip::address& bind_address) {

    if (session_id.empty()) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    auto it = impl_->sessions.find(session_id);
    if (it != impl_->sessions.end()) {
        if (!it->second->IsRunning()) {
            if (it->second.use_count() != 1) {
                LOG_CONN_FAIL("UDP session {} stopped while owning handles are still attached",
                              session_id);
                return std::unexpected(ErrorCode::NETWORK_IO_ERROR);
            }
            LOG_CONN_FAIL("UDP session {} is no longer receiving; replacing it",
                          session_id);
            it->second->Stop();
            impl_->sessions.erase(it);
        } else {
            if (!it->second->UsesBindAddress(bind_address)) {
                LOG_CONN_FAIL("UDP session {} bind address conflict", session_id);
                return std::unexpected(ErrorCode::INVALID_ARGUMENT);
            }
            it->second->Touch();
            return it->second;
        }
    }
    if (impl_->sessions.size() >= Impl::kMaxSessions) {
        LOG_CONN_FAIL("UDP session capacity exhausted: {}", Impl::kMaxSessions);
        return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    // 创建新会话
    std::shared_ptr<UDPSession> session;
    try {
        session = std::allocate_shared<UDPSession>(
            memory::ThreadLocalAllocator<UDPSession>{},
            impl_->io_context,
            session_id,
            impl_->dns_service);
    } catch (const std::bad_alloc&) {
        return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    auto err = session->Start(bind_address);

    if (err != ErrorCode::SUCCESS) {
        LOG_CONN_FAIL("Failed to create UDP session {}: {}", session_id, ErrorCodeToString(err));
        return std::unexpected(err);
    }

    std::shared_ptr<UDPSession> session_handle;
    try {
        auto [inserted_it, inserted] =
            impl_->sessions.try_emplace(session_id, std::move(session));
        if (!inserted) {
            return std::unexpected(ErrorCode::INTERNAL);
        }
        session_handle = inserted_it->second;
    } catch (const std::bad_alloc&) {
        return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    const auto receive_error = session_handle->StartReceive();
    if (receive_error != ErrorCode::SUCCESS) {
        impl_->sessions.erase(session_id);
        return std::unexpected(receive_error);
    }

    LOG_ACCESS_DEBUG("Created UDP session {} on port {}, total sessions: {}",
             session_id, session_handle->LocalPort(), impl_->sessions.size());

    return session_handle;
}

void UDPSessionManager::StartCleanup() {
    if (impl_->running) {
        return;
    }
    impl_->running = true;
    CleanupExpiredSessions();
}

void UDPSessionManager::CleanupExpiredSessions() {
    if (!impl_->running) return;
    bool removed_session = false;
    for (auto it = impl_->sessions.begin(); it != impl_->sessions.end(); ) {
        if (it->second.use_count() == 1 &&
            it->second->CanRetire(impl_->session_timeout)) {
            LOG_ACCESS_DEBUG("UDP session {} inactive or expired, removing", it->first);
            it->second->Stop();
            it = impl_->sessions.erase(it);
            removed_session = true;
        } else {
            ++it;
        }
    }
    if (removed_session) {
        MaybeShrinkHashContainer(impl_->sessions, 64);
    }

    impl_->cleanup_token = TimeoutScheduler::ForIoContext(impl_->io_context).ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::seconds(defaults::kUdpSessionCleanupInterval)),
        [this]() {
        if (impl_->running) {
            CleanupExpiredSessions();
        }
    });
}

void UDPSessionManager::StopAll() {
    impl_->running = false;
    if (impl_->cleanup_token.Valid()) {
        TimeoutScheduler::ForIoContext(impl_->io_context).Cancel(impl_->cleanup_token);
    }

    for (const auto& [id, session] : impl_->sessions) {
        session->Stop();
    }
    impl_->sessions.clear();
    MaybeShrinkHashContainer(impl_->sessions, 64);
}

size_t UDPSessionManager::ActiveSessionCount() const {
    return impl_->sessions.size();
}

}  // namespace acpp
