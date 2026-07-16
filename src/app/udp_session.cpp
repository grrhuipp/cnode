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
#include "udp_receive_buffer.hpp"

#include <algorithm>
#include <new>
#include <optional>
#include <span>
#include <utility>

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
    static constexpr size_t kMaxIpv4UdpPayload = 65507;
    static constexpr size_t kMaxIpv6UdpPayload = 65527;
    static constexpr size_t kMaxCallbacks = 1024;
    static constexpr size_t kMaxTargetsPerCallback = 256;
    static constexpr size_t kMaxTargetMappings = 4096;

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
    static net::awaitable<void> RunReceive(std::shared_ptr<Impl> self);
    net::awaitable<void> DoReceive();
    net::awaitable<std::pair<ErrorCode, udp::endpoint>> ResolveEndpoint(
        const TargetAddress& target);
    [[nodiscard]] std::pair<ErrorCode, bool> AddTargetMapping(
        const UdpEndpointKey& target_key,
        uint64_t callback_id);
    void RemoveTargetMapping(
        const UdpEndpointKey& target_key,
        uint64_t callback_id) noexcept;
    void MaybePruneTargetMappings(steady_clock::time_point now);
    void RefreshTargetMapping(const UdpEndpointKey& target_key,
                              uint64_t callback_id,
                              steady_clock::time_point now);

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

        std::optional<UdpEndpointKey> new_target_mapping;
        try {
            if (callback_id > 0) {
                const UdpEndpointKey target_key = MakeEndpointKey(
                    remote_ep.address(), remote_ep.port());
                auto [mapping_error, inserted] =
                    AddTargetMapping(target_key, callback_id);
                if (mapping_error != ErrorCode::OK) {
                    co_return mapping_error;
                }
                if (inserted) {
                    new_target_mapping = target_key;
                }
            }

            const size_t sent = co_await socket.async_send_to(
                buffers, remote_ep, net::use_awaitable);
            if (sent != payload_size) {
                if (new_target_mapping) {
                    RemoveTargetMapping(*new_target_mapping, callback_id);
                }
                co_return ErrorCode::NETWORK_IO_ERROR;
            }
            ++packets_sent;
            bytes_sent += sent;
            Touch();
            co_return ErrorCode::SUCCESS;
        } catch (const IoSystemError& e) {
            if (new_target_mapping) {
                RemoveTargetMapping(*new_target_mapping, callback_id);
            }
            LOG_ACCESS_DEBUG("UDP session {} SendTo error: {}", session_id, e.what());
            co_return ErrorCode::NETWORK_IO_ERROR;
        } catch (const std::bad_alloc&) {
            if (new_target_mapping) {
                RemoveTargetMapping(*new_target_mapping, callback_id);
            }
            co_return ErrorCode::RESOURCE_EXHAUSTED;
        }
    }

    net::io_context& io_context;
    std::string session_id;
    ::acpp::app::dns::DNS& dns_service;

    memory::ThreadLocalUnorderedMap<uint64_t, CallbackEntry> registered_callbacks;
    memory::ThreadLocalUnorderedMap<
        UdpEndpointKey,
        CallbackIdList,
        UdpEndpointKeyHash> target_to_callbacks;
    size_t target_mapping_count = 0;
    uint64_t next_callback_id = 1;

    udp::socket socket;
    net::ip::address bind_address;
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
    : impl_(std::make_shared<Impl>(io_context, session_id, dns_service)) {
}

UDPSession::~UDPSession() {
    if (impl_->running) {
        LOG_ACCESS_DEBUG("UDP session {} destroyed without Stop(), forced close", impl_->session_id);
        Stop();
    }
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
        Impl::RunReceive(impl_),
        [](std::exception_ptr) {});
}

// Per-Worker 简化版：无需 executor 参数
uint64_t UDPSession::RegisterCallback(PacketCallback callback) {
    if (!impl_->running || !callback ||
        impl_->registered_callbacks.size() >= Impl::kMaxCallbacks) {
        LOG_ACCESS_DEBUG(
            "UDP session {} rejected Full Cone callback running={} registered={}",
            impl_->session_id,
            impl_->running,
            impl_->registered_callbacks.size());
        return 0;
    }

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
        impl_->target_mapping_count -= std::min(
            impl_->target_mapping_count,
            it->second.sent_targets.size());

        LOG_ACCESS_DEBUG("UDP session {} unregistered Full Cone callback {}", impl_->session_id, callback_id);
        impl_->registered_callbacks.erase(it);
        MaybeShrinkHashContainer(impl_->registered_callbacks, 16);
        if (removed_reverse_key) {
            MaybeShrinkHashContainer(impl_->target_to_callbacks, 16);
        }
    }
}

net::awaitable<void> UDPSession::Impl::RunReceive(std::shared_ptr<Impl> self) {
    co_await self->DoReceive();
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

        const auto received = receive_buffer.Data(bytes);
        UDPPacketView packet_view{
            source,
            received};

        bool delivered = false;

        auto t_it = target_to_callbacks.find(sender_key);
        if (t_it != target_to_callbacks.end()) {
            const auto& callbacks = t_it->second;
            auto deliver = [&](uint64_t cb_id) {
                auto cb_it = registered_callbacks.find(cb_id);
                if (cb_it != registered_callbacks.end()) {
                    RefreshTargetMapping(sender_key, cb_id, now);
                    if (cb_it->second.callback(packet_view)) {
                        delivered = true;
                    } else {
                        LOG_ACCESS_DEBUG(
                            "UDP session {} callback {} rejected packet from {}",
                            session_id, cb_id, EndpointKeyToString(sender_key));
                    }
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
            if (cb_it->second.callback(packet_view)) {
                delivered = true;
            } else {
                LOG_ACCESS_DEBUG(
                    "UDP session {} callback {} rejected packet from {}",
                    session_id, cb_it->first, EndpointKeyToString(sender_key));
            }
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

std::pair<ErrorCode, bool> UDPSession::Impl::AddTargetMapping(
    const UdpEndpointKey& target_key,
    uint64_t callback_id) {
    const auto now = steady_clock::now();
    MaybePruneTargetMappings(now);

    auto it = registered_callbacks.find(callback_id);
    if (it == registered_callbacks.end()) {
        return {ErrorCode::INVALID_ARGUMENT, false};
    }

    auto existing = it->second.sent_targets.find(target_key);
    if (existing != it->second.sent_targets.end()) {
        existing->second = now;
        return {ErrorCode::OK, false};
    }
    if (it->second.sent_targets.size() >= kMaxTargetsPerCallback ||
        target_mapping_count >= kMaxTargetMappings) {
        return {ErrorCode::RESOURCE_EXHAUSTED, false};
    }

    it->second.sent_targets.emplace(target_key, now);
    try {
        target_to_callbacks[target_key].Push(callback_id);
    } catch (...) {
        it->second.sent_targets.erase(target_key);
        auto reverse_it = target_to_callbacks.find(target_key);
        if (reverse_it != target_to_callbacks.end() && reverse_it->second.Empty()) {
            target_to_callbacks.erase(reverse_it);
        }
        throw;
    }
    ++target_mapping_count;
    LOG_ACCESS_DEBUG("UDP session {} added target mapping {} -> callback {}",
             session_id, EndpointKeyToString(target_key), callback_id);
    return {ErrorCode::OK, true};
}

void UDPSession::Impl::RemoveTargetMapping(
    const UdpEndpointKey& target_key,
    uint64_t callback_id) noexcept {
    auto callback_it = registered_callbacks.find(callback_id);
    if (callback_it == registered_callbacks.end() ||
        callback_it->second.sent_targets.erase(target_key) == 0) {
        return;
    }
    target_mapping_count -= std::min<size_t>(target_mapping_count, 1);

    auto reverse_it = target_to_callbacks.find(target_key);
    if (reverse_it == target_to_callbacks.end()) {
        return;
    }
    auto& callbacks = reverse_it->second;
    if (callbacks.Remove(callback_id) && callbacks.Empty()) {
        target_to_callbacks.erase(reverse_it);
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
            target_mapping_count -= std::min<size_t>(target_mapping_count, 1);
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
    impl_->target_mapping_count = 0;
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

    struct SessionDeleter {
        void operator()(UDPSession* session) const noexcept;
    };
    using SessionPtr = std::unique_ptr<UDPSession, SessionDeleter>;

    net::io_context& io_context;
    ::acpp::app::dns::DNS& dns_service;
    std::chrono::seconds session_timeout;
    memory::ThreadLocalUnorderedMap<std::string, SessionPtr> sessions;
    TimeoutToken cleanup_token;
    bool running = false;
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

UDPSessionManager::~UDPSessionManager() {
    StopAll();
}

std::expected<UDPSession*, ErrorCode> UDPSessionManager::AcquireSession(
    const std::string& session_id,
    const net::ip::address& bind_address) {

    if (session_id.empty()) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    auto it = impl_->sessions.find(session_id);
    if (it != impl_->sessions.end()) {
        if (!it->second->UsesBindAddress(bind_address)) {
            LOG_CONN_FAIL("UDP session {} bind address conflict", session_id);
            return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        it->second->Touch();
        return it->second.get();
    }
    if (impl_->sessions.size() >= Impl::kMaxSessions) {
        LOG_CONN_FAIL("UDP session capacity exhausted: {}", Impl::kMaxSessions);
        return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    // 创建新会话
    memory::ThreadLocalAllocator<UDPSession> alloc;
    UDPSession* raw_session = nullptr;
    try {
        raw_session = alloc.allocate(1);
        std::construct_at(raw_session, impl_->io_context, session_id, impl_->dns_service);
    } catch (const std::bad_alloc&) {
        if (raw_session) {
            alloc.deallocate(raw_session, 1);
        }
        return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (...) {
        if (raw_session) {
            alloc.deallocate(raw_session, 1);
        }
        throw;
    }
    Impl::SessionPtr session(raw_session);
    auto err = session->Start(bind_address);

    if (err != ErrorCode::SUCCESS) {
        LOG_CONN_FAIL("Failed to create UDP session {}: {}", session_id, ErrorCodeToString(err));
        return std::unexpected(err);
    }

    UDPSession* session_ptr = nullptr;
    try {
        auto [inserted_it, inserted] =
            impl_->sessions.try_emplace(session_id, std::move(session));
        if (!inserted) {
            return std::unexpected(ErrorCode::INTERNAL);
        }
        session_ptr = inserted_it->second.get();
    } catch (const std::bad_alloc&) {
        return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    session_ptr->StartReceive();

    LOG_ACCESS_DEBUG("Created UDP session {} on port {}, total sessions: {}",
             session_id, session_ptr->LocalPort(), impl_->sessions.size());

    return session_ptr;
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
        if (it->second->IsExpired(impl_->session_timeout)) {
            LOG_ACCESS_DEBUG("UDP session {} expired, removing", it->first);
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
