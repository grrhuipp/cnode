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

#include <algorithm>
#include <optional>
#include <span>

namespace acpp {

namespace {

struct CallbackIdList {
    uint64_t first = 0;
    memory::ThreadLocalVector<uint64_t> overflow;

    void Push(uint64_t callback_id);
    [[nodiscard]] bool Remove(uint64_t callback_id) noexcept;
    [[nodiscard]] bool Empty() const noexcept { return first == 0; }
};

struct CallbackEntry {
    PacketCallback callback;
    memory::ThreadLocalUnorderedMap<
        UdpEndpointKey,
        steady_clock::time_point,
        UdpEndpointKeyHash> sent_targets;
};

void CallbackIdList::Push(uint64_t callback_id) {
    if (first == 0) {
        first = callback_id;
        return;
    }
    overflow.push_back(callback_id);
}

bool CallbackIdList::Remove(uint64_t callback_id) noexcept {
    if (first == callback_id) {
        if (!overflow.empty()) {
            first = overflow.back();
            overflow.pop_back();
        } else {
            first = 0;
        }
        return true;
    }

    auto it = std::find(overflow.begin(), overflow.end(), callback_id);
    if (it == overflow.end()) {
        return false;
    }
    *it = overflow.back();
    overflow.pop_back();
    return true;
}

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
    Impl(net::io_context& io_context,
         const std::string& session_id,
         ::acpp::app::dns::DNS& dns_service)
        : io_context(io_context)
        , session_id(session_id)
        , dns_service(dns_service)
        , socket(io_context)
        , last_active(std::chrono::steady_clock::now())
        , next_target_prune_at(steady_clock::now() + kTargetPruneInterval) {}

    void Touch() { last_active = std::chrono::steady_clock::now(); }
    net::awaitable<void> DoReceive();
    void AddTargetMapping(const UdpEndpointKey& target_key, uint64_t callback_id);
    void MaybePruneTargetMappings(steady_clock::time_point now);
    void RefreshTargetMapping(const UdpEndpointKey& target_key,
                              uint64_t callback_id,
                              steady_clock::time_point now);

    net::io_context& io_context;
    std::string session_id;
    ::acpp::app::dns::DNS& dns_service;

    memory::ThreadLocalUnorderedMap<uint64_t, CallbackEntry> registered_callbacks;
    memory::ThreadLocalUnorderedMap<
        UdpEndpointKey,
        CallbackIdList,
        UdpEndpointKeyHash> target_to_callbacks;
    uint64_t next_callback_id = 1;

    udp::socket socket;
    uint16_t local_port = 0;
    udp::endpoint sender_endpoint;

    std::chrono::steady_clock::time_point last_active;
    time_point next_target_prune_at{};
    bool running = false;

    static constexpr auto kTargetMappingTtl = std::chrono::seconds(defaults::kUdpTargetMappingTtl);
    static constexpr auto kTargetPruneInterval = std::chrono::seconds(defaults::kUdpTargetPruneInterval);

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
    : impl_(std::make_unique<Impl>(io_context, session_id, dns_service)) {
}

UDPSession::~UDPSession() {
    if (impl_->running) {
        IoErrorCode ec;
        impl_->socket.cancel(ec);
        impl_->socket.close(ec);
        impl_->running = false;
        LOG_ACCESS_DEBUG("UDP session {} destroyed without Stop(), forced close", impl_->session_id);
    }
}

ErrorCode UDPSession::Start(const std::string& bind_address) {
    const std::string primary_bind = bind_address.empty()
        ? std::string(constants::network::kAnyIpv4)
        : bind_address;
    std::string last_error = "bind failed";

    try {
        auto addr = net::ip::make_address(primary_bind);

        udp::endpoint local_ep(addr, 0);  // 端口 0 = 自动分配
        udp::socket sock(impl_->io_context);
        sock.open(local_ep.protocol());
        sock.set_option(udp::socket::reuse_address(true));
        sock.bind(local_ep);

        impl_->socket = std::move(sock);
        impl_->local_port = impl_->socket.local_endpoint().port();
        impl_->running = true;

        LOG_ACCESS_DEBUG("UDP session {} started on {}",
                         impl_->session_id,
                         iputil::FormatEndpointForLog(primary_bind, impl_->local_port));
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

net::awaitable<ErrorCode> UDPSession::SendTo(
    const TargetAddress& target,
    const uint8_t* data,
    size_t len,
    uint64_t callback_id) {

    if (!impl_->running) {
        co_return ErrorCode::CONNECTION_CLOSED;
    }

    try {
        udp::endpoint remote_ep;

        if (target.resolved_addr) {
            remote_ep = udp::endpoint(*target.resolved_addr, target.port);
        } else if (target.type == AddressType::Domain) {
            auto dns_result = co_await impl_->dns_service.Resolve(target.host);

            if (!dns_result.Ok()) {
                LOG_ACCESS_DEBUG("UDP session {} DNS resolve failed for {}", impl_->session_id, target.host);
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }

            auto selected_addr = SelectAddressForSocket(dns_result.addresses, impl_->socket);
            if (!selected_addr || selected_addr->is_unspecified()) {
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }

            remote_ep = udp::endpoint(*selected_addr, target.port);
        } else {
            co_return ErrorCode::PROTOCOL_INVALID_ADDRESS;
        }

        // 记录目标映射（用于 Full Cone 回包路由）
        if (callback_id > 0) {
            const UdpEndpointKey target_key = MakeEndpointKey(
                remote_ep.address(), remote_ep.port());
            impl_->AddTargetMapping(target_key, callback_id);
        }

        size_t sent = co_await impl_->socket.async_send_to(
            net::buffer(data, len),
            remote_ep,
            net::use_awaitable);

        impl_->packets_sent++;
        impl_->bytes_sent += sent;
        Touch();

        co_return ErrorCode::SUCCESS;

    } catch (const IoSystemError& e) {
        LOG_ACCESS_DEBUG("UDP session {} SendTo error: {}", impl_->session_id, e.what());
        co_return ErrorCode::NETWORK_IO_ERROR;
    }
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
        udp::endpoint remote_ep;

        if (target.resolved_addr) {
            remote_ep = udp::endpoint(*target.resolved_addr, target.port);
        } else if (target.type == AddressType::Domain) {
            auto dns_result = co_await impl_->dns_service.Resolve(target.host);

            if (!dns_result.Ok()) {
                LOG_ACCESS_DEBUG("UDP session {} DNS resolve failed for {}", impl_->session_id, target.host);
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }

            auto selected_addr = SelectAddressForSocket(dns_result.addresses, impl_->socket);
            if (!selected_addr || selected_addr->is_unspecified()) {
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }

            remote_ep = udp::endpoint(*selected_addr, target.port);
        } else {
            co_return ErrorCode::PROTOCOL_INVALID_ADDRESS;
        }

        if (callback_id > 0) {
            const UdpEndpointKey target_key = MakeEndpointKey(
                remote_ep.address(), remote_ep.port());
            impl_->AddTargetMapping(target_key, callback_id);
        }

        std::array<net::const_buffer, buf::MultiBuffer::kInlineCapacity> inline_send_buffers{};
        memory::ThreadLocalVector<net::const_buffer> spill_send_buffers;
        size_t send_buffer_count = 0;
        for (const auto* buffer : payload) {
            if (buffer && !buffer->IsEmpty()) {
                const auto bytes = buffer->Bytes();
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

        auto send_buffers = spill_send_buffers.empty()
            ? std::span<const net::const_buffer>(
                inline_send_buffers.data(),
                send_buffer_count)
            : std::span<const net::const_buffer>(
                spill_send_buffers.data(),
                spill_send_buffers.size());

        size_t sent = co_await impl_->socket.async_send_to(
            send_buffers,
            remote_ep,
            net::use_awaitable);

        impl_->packets_sent++;
        impl_->bytes_sent += sent;
        Touch();

        co_return ErrorCode::SUCCESS;

    } catch (const IoSystemError& e) {
        LOG_ACCESS_DEBUG("UDP session {} SendTo error: {}", impl_->session_id, e.what());
        co_return ErrorCode::NETWORK_IO_ERROR;
    }
}

net::awaitable<ErrorCode> UDPSession::SendTo(
    const TargetAddress& target,
    const uint8_t* data,
    size_t len) {
    co_return co_await SendTo(target, data, len, 0);
}

void UDPSession::StartReceive() {
    if (!impl_->running) return;
    net::co_spawn(
        impl_->io_context.get_executor(),
        impl_->DoReceive(),
        [](std::exception_ptr) {});
}

// Per-Worker 简化版：无需 executor 参数
uint64_t UDPSession::RegisterCallback(PacketCallback callback) {
    uint64_t id = impl_->next_callback_id++;
    impl_->registered_callbacks[id] = CallbackEntry{
        std::move(callback), {}};

    LOG_ACCESS_DEBUG("UDP session {} registered Full Cone callback {}", impl_->session_id, id);
    return id;
}

void UDPSession::UnregisterCallback(uint64_t callback_id) {
    auto it = impl_->registered_callbacks.find(callback_id);
    if (it != impl_->registered_callbacks.end()) {
        bool removed_reverse_key = false;

        // 清理 sent_targets 对应的反向索引
        for (const auto& [target, _] : it->second.sent_targets) {
            auto t_it = impl_->target_to_callbacks.find(target);
            if (t_it != impl_->target_to_callbacks.end()) {
                auto& callbacks = t_it->second;
                const bool removed = callbacks.Remove(callback_id);
                if (removed && callbacks.Empty()) {
                    impl_->target_to_callbacks.erase(t_it);
                    removed_reverse_key = true;
                }
            }
        }

        LOG_ACCESS_DEBUG("UDP session {} unregistered Full Cone callback {}", impl_->session_id, callback_id);
        impl_->registered_callbacks.erase(it);
        MaybeShrinkHashContainer(impl_->registered_callbacks, 16);
        if (removed_reverse_key) {
            MaybeShrinkHashContainer(impl_->target_to_callbacks, 16);
        }
    }
}

net::awaitable<void> UDPSession::Impl::DoReceive() {
    while (running) {
        buf::BufferGuard recv_guard{buf::Buffer::New()};
        if (!recv_guard) {
            co_return;
        }

        auto [ec, bytes] = co_await socket.async_receive_from(
            net::buffer(recv_guard->data, buf::Buffer::kSize),
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
        MaybePruneTargetMappings(now);

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

        UDPPacketView packet_view{
            source,
            std::span<const uint8_t>(recv_guard->data, bytes)};

        bool delivered = false;

        auto t_it = target_to_callbacks.find(sender_key);
        if (t_it != target_to_callbacks.end()) {
            const auto& callbacks = t_it->second;
            auto deliver = [&](uint64_t cb_id) {
                auto cb_it = registered_callbacks.find(cb_id);
                if (cb_it != registered_callbacks.end()) {
                    RefreshTargetMapping(sender_key, cb_id, now);
                    cb_it->second.callback(packet_view);
                    delivered = true;
                }
            };

            if (callbacks.first != 0) {
                deliver(callbacks.first);
            }
            for (uint64_t cb_id : callbacks.overflow) {
                deliver(cb_id);
            }
        } else if (registered_callbacks.size() == 1) {
            auto cb_it = registered_callbacks.begin();
            RefreshTargetMapping(sender_key, cb_it->first, now);
            cb_it->second.callback(packet_view);
            delivered = true;
        } else {
            std::string known_keys;
            for (const auto& [key, _] : target_to_callbacks) {
                if (!known_keys.empty()) known_keys += ", ";
                known_keys += EndpointKeyToString(key);
            }
            LOG_ACCESS_DEBUG("UDP session {} sender_key={} not found, known keys: [{}]",
                             session_id, EndpointKeyToString(sender_key), known_keys);
        }

        if (!delivered) {
            LOG_ACCESS_DEBUG("UDP session {} no callback for {}",
                             session_id, EndpointKeyToString(sender_key));
        }
    }
    co_return;
}

void UDPSession::Impl::AddTargetMapping(const UdpEndpointKey& target_key, uint64_t callback_id) {
    const auto now = steady_clock::now();
    MaybePruneTargetMappings(now);

    auto it = registered_callbacks.find(callback_id);
    if (it != registered_callbacks.end()) {
        auto insert_result = it->second.sent_targets.insert_or_assign(target_key, now);
        if (insert_result.second) {
            target_to_callbacks[target_key].Push(callback_id);
            LOG_ACCESS_DEBUG("UDP session {} added target mapping {} -> callback {}",
                     session_id, EndpointKeyToString(target_key), callback_id);
        }
    }
}

void UDPSession::Impl::MaybePruneTargetMappings(steady_clock::time_point now) {
    if (now < next_target_prune_at) {
        return;
    }

    next_target_prune_at = now + kTargetPruneInterval;
    const auto cutoff = now - kTargetMappingTtl;

    bool removed_reverse_key = false;
    for (auto& [callback_id, entry] : registered_callbacks) {
        bool pruned_entry_targets = false;
        for (auto it = entry.sent_targets.begin(); it != entry.sent_targets.end(); ) {
            if (it->second >= cutoff) {
                ++it;
                continue;
            }

            auto reverse_it = target_to_callbacks.find(it->first);
            if (reverse_it != target_to_callbacks.end()) {
                auto& callbacks = reverse_it->second;
                const bool removed = callbacks.Remove(callback_id);
                if (removed && callbacks.Empty()) {
                    target_to_callbacks.erase(reverse_it);
                    removed_reverse_key = true;
                }
            }
            it = entry.sent_targets.erase(it);
            pruned_entry_targets = true;
        }
        if (pruned_entry_targets) {
            MaybeShrinkHashContainer(entry.sent_targets, 16);
        }
    }
    if (removed_reverse_key) {
        MaybeShrinkHashContainer(target_to_callbacks, 16);
    }
}

void UDPSession::Impl::RefreshTargetMapping(
    const UdpEndpointKey& target_key,
    uint64_t callback_id,
    steady_clock::time_point now) {
    auto it = registered_callbacks.find(callback_id);
    if (it == registered_callbacks.end()) {
        return;
    }

    auto sent_it = it->second.sent_targets.find(target_key);
    if (sent_it != it->second.sent_targets.end()) {
        sent_it->second = now;
    }
}

void UDPSession::Stop() {
    if (!impl_->running) return;
    impl_->running = false;

    IoErrorCode ec;
    impl_->socket.cancel(ec);
    impl_->socket.close(ec);

    impl_->registered_callbacks.clear();
    impl_->target_to_callbacks.clear();
    MaybeShrinkHashContainer(impl_->registered_callbacks, 16);
    MaybeShrinkHashContainer(impl_->target_to_callbacks, 16);

    LOG_ACCESS_DEBUG("UDP session {} stopped, sent: {} pkts/{} bytes, recv: {} pkts/{} bytes",
              impl_->session_id, impl_->packets_sent, impl_->bytes_sent,
              impl_->packets_received, impl_->bytes_received);
}

void UDPSession::Touch() {
    impl_->Touch();
}

bool UDPSession::IsExpired(std::chrono::seconds timeout) const {
    return std::chrono::steady_clock::now() - impl_->last_active > timeout;
}

uint16_t UDPSession::LocalPort() const {
    return impl_->local_port;
}

const std::string& UDPSession::SessionId() const {
    return impl_->session_id;
}

uint64_t UDPSession::PacketsSent() const {
    return impl_->packets_sent;
}

uint64_t UDPSession::PacketsReceived() const {
    return impl_->packets_received;
}

uint64_t UDPSession::BytesSent() const {
    return impl_->bytes_sent;
}

uint64_t UDPSession::BytesReceived() const {
    return impl_->bytes_received;
}

// ============================================================================
// UDPSessionManager (Per-Worker, 单线程访问，无需锁)
// ============================================================================

struct UDPSessionManager::Impl {
    Impl(net::io_context& io_context,
         ::acpp::app::dns::DNS& dns_service,
         std::chrono::seconds session_timeout)
        : io_context(io_context)
        , dns_service(dns_service)
        , session_timeout(session_timeout) {}

    struct SessionDeleter {
        void operator()(UDPSession* session) const noexcept;
    };
    using SessionPtr = std::unique_ptr<UDPSession, SessionDeleter>;

    net::io_context& io_context;
    ::acpp::app::dns::DNS& dns_service;
    std::chrono::seconds session_timeout;
    memory::ThreadLocalUnorderedMap<std::string, SessionPtr> sessions;
    memory::ThreadLocalVector<SessionPtr> retired_sessions;
    TimeoutToken cleanup_token;
    bool running = false;
    uint64_t total_packets_sent = 0;
    uint64_t total_packets_received = 0;
};

void UDPSessionManager::Impl::SessionDeleter::operator()(UDPSession* session) const noexcept {
    if (!session) {
        return;
    }
    std::destroy_at(session);
    memory::ThreadLocalAllocator<UDPSession>{}.deallocate(session, 1);
}

UDPSessionManager::UDPSessionManager(net::io_context& io_context,
                                     ::acpp::app::dns::DNS& dns_service,
                                     std::chrono::seconds session_timeout)
    : impl_(std::make_unique<Impl>(io_context, dns_service, session_timeout)) {
}

UDPSessionManager::~UDPSessionManager() = default;

UDPSession* UDPSessionManager::GetOrCreateSession(
    const std::string& session_id,
    const std::string& bind_address) {

    auto it = impl_->sessions.find(session_id);
    if (it != impl_->sessions.end()) {
        it->second->Touch();
        return it->second.get();
    }

    // 创建新会话
    memory::ThreadLocalAllocator<UDPSession> alloc;
    UDPSession* raw_session = alloc.allocate(1);
    try {
        std::construct_at(raw_session, impl_->io_context, session_id, impl_->dns_service);
    } catch (...) {
        alloc.deallocate(raw_session, 1);
        throw;
    }
    Impl::SessionPtr session(raw_session);
    auto err = session->Start(bind_address);

    if (err != ErrorCode::SUCCESS) {
        LOG_CONN_FAIL("Failed to create UDP session {}: {}", session_id, ErrorCodeToString(err));
        return nullptr;
    }

    UDPSession* session_ptr = session.get();
    impl_->sessions[session_id] = std::move(session);
    session_ptr->StartReceive();

    LOG_ACCESS_DEBUG("Created UDP session {} on port {}, total sessions: {}",
             session_id, session_ptr->LocalPort(), impl_->sessions.size());

    return session_ptr;
}

UDPSession* UDPSessionManager::GetSession(const std::string& session_id) {
    auto it = impl_->sessions.find(session_id);
    if (it != impl_->sessions.end()) {
        return it->second.get();
    }
    return nullptr;
}

void UDPSessionManager::RemoveSession(const std::string& session_id) {
    auto it = impl_->sessions.find(session_id);
    if (it != impl_->sessions.end()) {
        it->second->Stop();
        impl_->retired_sessions.push_back(std::move(it->second));
        impl_->sessions.erase(it);
        MaybeShrinkHashContainer(impl_->sessions, 64);
        LOG_ACCESS_DEBUG("Removed UDP session {}, remaining: {}", session_id, impl_->sessions.size());
    }
}

void UDPSessionManager::StartCleanup() {
    impl_->running = true;
    CleanupExpiredSessions();
}

void UDPSessionManager::CleanupExpiredSessions() {
    if (!impl_->running) return;
    bool removed_session = false;
    for (auto it = impl_->sessions.begin(); it != impl_->sessions.end(); ) {
        if (it->second->IsExpired(impl_->session_timeout)) {
            LOG_ACCESS_DEBUG("UDP session {} expired, removing", it->first);
            impl_->total_packets_sent += it->second->PacketsSent();
            impl_->total_packets_received += it->second->PacketsReceived();
            it->second->Stop();
            impl_->retired_sessions.push_back(std::move(it->second));
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
    TimeoutScheduler::ForIoContext(impl_->io_context).Cancel(impl_->cleanup_token);

    for (const auto& [id, session] : impl_->sessions) {
        session->Stop();
    }
    for (const auto& session : impl_->retired_sessions) {
        session->Stop();
    }
    impl_->sessions.clear();
    impl_->retired_sessions.clear();
    MaybeShrinkHashContainer(impl_->sessions, 64);
    TryShrinkSequence(impl_->retired_sessions);
}

size_t UDPSessionManager::ActiveSessionCount() const {
    return impl_->sessions.size();
}

uint64_t UDPSessionManager::TotalPacketsSent() const {
    return impl_->total_packets_sent;
}

uint64_t UDPSessionManager::TotalPacketsReceived() const {
    return impl_->total_packets_received;
}

}  // namespace acpp
