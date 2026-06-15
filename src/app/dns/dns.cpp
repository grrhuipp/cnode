#include "cache_internal.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/cancel_after.hpp>
#include <asio/ip/udp.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <random>
#include <span>

namespace acpp::app::dns {

namespace wire {

constexpr uint16_t FLAG_QR    = 0x8000;
constexpr uint16_t FLAG_RCODE = 0x000F;

constexpr uint16_t TYPE_A    = 1;
constexpr uint16_t TYPE_AAAA = 28;
constexpr uint8_t RCODE_OK         = 0;
constexpr uint8_t RCODE_NAME_ERROR = 3;

}  // namespace wire

namespace {

DnsResult MakeCachedResult(const DnsCacheEntry& entry) {
    DnsResult result;
    if (entry.negative) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NXDOMAIN (cached)";
    } else {
        result.addresses.assign(entry.addresses.begin(), entry.addresses.end());
        result.ttl = entry.ttl;
    }
    result.from_cache = true;
    return result;
}

void StoreResult(DnsCache& cache,
                 std::string_view domain,
                 const DnsResult& result) {
    if (result.Ok()) {
        cache.Put(domain, result.addresses, result.ttl);
    } else if (result.error == ErrorCode::DNS_NO_RECORD) {
        cache.PutNegative(domain, 60);
    }
}

}  // namespace

struct DNS::Impl {
    struct ResolveKey {
        memory::ThreadLocalString domain;

        bool operator==(const ResolveKey& other) const noexcept {
            return domain == other.domain;
        }
    };

    struct ResolveKeyHash {
        using is_transparent = void;

        size_t operator()(const ResolveKey& key) const noexcept {
            return (*this)(std::string_view(key.domain));
        }

        size_t operator()(std::string_view domain) const noexcept {
            return std::hash<std::string_view>{}(domain);
        }
    };

    struct ResolveKeyEq {
        using is_transparent = void;

        bool operator()(const ResolveKey& lhs, const ResolveKey& rhs) const noexcept {
            return lhs.domain == rhs.domain;
        }

        bool operator()(const ResolveKey& lhs, std::string_view rhs) const noexcept {
            return lhs.domain == rhs;
        }

        bool operator()(std::string_view lhs, const ResolveKey& rhs) const noexcept {
            return lhs == rhs.domain;
        }
    };

    struct ResolveWaiter {
        net::steady_timer* timer = nullptr;
        DnsResult result;
        bool completed = false;
    };

    struct InflightResolve {
        DnsResult result;
        bool completed = false;
        memory::ThreadLocalVector<ResolveWaiter*> waiters;
    };

    struct InflightDeleter {
        void operator()(InflightResolve* inflight) const noexcept;
    };
    using InflightPtr = std::unique_ptr<InflightResolve, InflightDeleter>;

    struct ParsedResponse : ResultStatus {
        std::vector<net::ip::address> addresses;
        uint32_t ttl = 60;
        bool negative_cacheable = false;

        [[nodiscard]] bool Ok() const noexcept {
            return ResultStatus::Ok() && !addresses.empty();
        }
    };

    Impl(net::io_context& io_context, const Config& config);

    net::awaitable<DnsResult> Resolve(std::string_view domain);
    DnsCacheStats GetCacheStats() const;
    void ClearCache();
    net::awaitable<void> Prefetch(const std::vector<std::string>& domains);

    net::awaitable<DnsResult> DoResolve(std::string_view domain);
    net::awaitable<DnsResult> QueryServer(
        const net::ip::udp::endpoint& server,
        std::string_view domain,
        bool query_aaaa);
    void BuildQueryTo(memory::ByteVector& query,
                      std::string_view domain,
                      uint16_t txid,
                      bool query_aaaa);
    ParsedResponse ParseResponse(
        std::span<const uint8_t> response,
        uint16_t expected_txid,
        uint32_t& out_ttl);

    net::io_context& io_context;
    Config config;
    DnsCache cache;
    memory::ThreadLocalVector<net::ip::udp::endpoint> servers;
    memory::ThreadLocalUnorderedMap<ResolveKey, InflightPtr, ResolveKeyHash, ResolveKeyEq>
        inflight_resolves;
    uint16_t txid_counter = 1;
};

DNS::Impl::Impl(net::io_context& io_context, const Config& config)
    : io_context(io_context)
    , config(config)
    , cache(config.cache_size, config.min_ttl, config.max_ttl) {
    constexpr net::ip::port_type kDnsPort = 53;
    servers.reserve(config.servers.size());
    for (const auto& server : config.servers) {
        IoErrorCode ec;
        auto addr = net::ip::make_address(server, ec);
        if (!ec) {
            servers.emplace_back(addr, kDnsPort);
        } else {
            LOG_WARN("Invalid DNS server address: {}", server);
        }
    }

    if (servers.empty()) {
        servers.emplace_back(net::ip::make_address("8.8.8.8"), kDnsPort);
        servers.emplace_back(net::ip::make_address("1.1.1.1"), kDnsPort);
    }

    std::random_device rd;
    txid_counter = static_cast<uint16_t>(rd() & 0xFFFF);
}

void DNS::Impl::InflightDeleter::operator()(InflightResolve* inflight) const noexcept {
    if (!inflight) {
        return;
    }
    std::destroy_at(inflight);
    memory::ThreadLocalAllocator<InflightResolve>{}.deallocate(inflight, 1);
}

net::awaitable<DnsResult> DNS::Impl::Resolve(
    std::string_view domain) {
    IoErrorCode ec;
    auto addr = net::ip::make_address(domain, ec);
    if (!ec) {
        DnsResult result;
        result.addresses.reserve(1);
        result.addresses.push_back(addr);
        co_return result;
    }

    if (auto cached = cache.Get(domain)) {
        co_return MakeCachedResult(*cached);
    }

    const std::string_view domain_ref(domain);
    auto existing = inflight_resolves.find(domain_ref);
    if (existing != inflight_resolves.end()) {
        auto* inflight = existing->second.get();
        if (inflight->completed) {
            co_return inflight->result;
        }

        net::steady_timer wait_timer(io_context);
        wait_timer.expires_at(net::steady_timer::time_point::max());
        ResolveWaiter waiter;
        waiter.timer = &wait_timer;
        inflight->waiters.push_back(&waiter);

        (void)co_await wait_timer.async_wait(
            net::as_tuple(net::use_awaitable));

        if (waiter.completed) {
            co_return waiter.result;
        }

        auto still_inflight = inflight_resolves.find(domain_ref);
        if (still_inflight != inflight_resolves.end()) {
            auto& waiters = still_inflight->second->waiters;
            std::erase(waiters, &waiter);
        }

        DnsResult cancelled;
        cancelled.error = ErrorCode::DNS_RESOLVE_FAILED;
        cancelled.error_msg = "DNS resolve waiter cancelled";
        co_return cancelled;
    }

    memory::ThreadLocalAllocator<InflightResolve> alloc;
    InflightResolve* raw_inflight = alloc.allocate(1);
    try {
        std::construct_at(raw_inflight);
    } catch (...) {
        alloc.deallocate(raw_inflight, 1);
        throw;
    }
    InflightPtr inflight(raw_inflight);
    auto* inflight_ptr = inflight.get();
    ResolveKey key{memory::ThreadLocalString(domain)};
    inflight_resolves.emplace(key, std::move(inflight));

    DnsResult result;
    try {
        result = co_await DoResolve(domain);
    } catch (const std::exception& e) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = e.what();
    } catch (...) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = "DNS resolve exception";
    }

    StoreResult(cache, domain, result);

    inflight_ptr->completed = true;
    inflight_ptr->result = result;
    auto waiters = std::move(inflight_ptr->waiters);
    if (auto done = inflight_resolves.find(domain_ref); done != inflight_resolves.end()) {
        inflight_resolves.erase(done);
    }

    for (auto* waiter : waiters) {
        if (!waiter || !waiter->timer) {
            continue;
        }
        waiter->result = result;
        waiter->completed = true;
        waiter->timer->cancel();
    }

    co_return result;
}

net::awaitable<DnsResult> DNS::Impl::DoResolve(
    std::string_view domain) {
    DnsResult last_result;
    last_result.error = ErrorCode::DNS_RESOLVE_FAILED;
    last_result.error_msg = "DNS server unavailable";

    for (const auto& server : servers) {
        auto a_result = co_await QueryServer(server, domain, false);
        auto aaaa_result = co_await QueryServer(server, domain, true);

        if (a_result.Ok() || aaaa_result.Ok()) {
            DnsResult result;
            result.ttl = UINT32_MAX;
            result.error = ErrorCode::OK;
            result.addresses.reserve(
                (a_result.Ok() ? a_result.addresses.size() : 0) +
                (aaaa_result.Ok() ? aaaa_result.addresses.size() : 0));

            if (a_result.Ok()) {
                result.addresses.insert(result.addresses.end(),
                                        a_result.addresses.begin(),
                                        a_result.addresses.end());
                result.ttl = std::min(result.ttl, a_result.ttl);
            }
            if (aaaa_result.Ok()) {
                result.addresses.insert(result.addresses.end(),
                                        aaaa_result.addresses.begin(),
                                        aaaa_result.addresses.end());
                result.ttl = std::min(result.ttl, aaaa_result.ttl);
            }
            if (result.ttl == UINT32_MAX) {
                result.ttl = config.min_ttl;
            }
            co_return result;
        }

        if (a_result.error == ErrorCode::DNS_NO_RECORD &&
            aaaa_result.error == ErrorCode::DNS_NO_RECORD) {
            co_return a_result;
        }

        last_result = a_result.error == ErrorCode::DNS_NO_RECORD
            ? std::move(aaaa_result)
            : std::move(a_result);
    }

    co_return last_result;
}

net::awaitable<DnsResult> DNS::Impl::QueryServer(
    const net::ip::udp::endpoint& server,
    std::string_view domain,
    bool query_aaaa) {
    DnsResult result;
    const uint16_t txid = txid_counter++;
    memory::ByteVector query;
    BuildQueryTo(query, domain, txid, query_aaaa);

    udp::socket socket(io_context);
    IoErrorCode ec;
    socket.open(server.protocol(), ec);
    if (ec) {
        result.error = ErrorCode::SOCKET_CREATE_FAILED;
        result.error_msg = ec.message();
        co_return result;
    }

    socket.connect(server, ec);
    if (ec) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = ec.message();
        co_return result;
    }

    auto [send_ec, sent] = co_await socket.async_send(
        net::buffer(query),
        net::as_tuple(net::use_awaitable));
    (void)sent;
    if (send_ec) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = send_ec.message();
        co_return result;
    }

    std::array<uint8_t, 512> response{};
    net::steady_timer timeout_timer(io_context);
    auto [recv_ec, received] = co_await socket.async_receive(
        net::buffer(response),
        net::cancel_after(
            timeout_timer,
            std::chrono::seconds(config.timeout_sec),
            net::as_tuple(net::use_awaitable)));

    if (recv_ec == io_error::operation_aborted &&
        timeout_timer.expiry() <= net::steady_timer::clock_type::now()) {
        result.error = ErrorCode::DNS_TIMEOUT;
        result.error_msg = "DNS query timed out";
        co_return result;
    }

    if (recv_ec) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = recv_ec.message();
        co_return result;
    }

    uint32_t ttl = config.min_ttl;
    auto parsed = ParseResponse(
        std::span<const uint8_t>(response.data(), received), txid, ttl);
    if (!parsed.Ok()) {
        result.error = parsed.error;
        result.error_msg = parsed.error_msg;
        co_return result;
    }

    result.addresses = std::move(parsed.addresses);
    result.ttl = parsed.ttl;
    result.error = ErrorCode::OK;
    co_return result;
}

void DNS::Impl::BuildQueryTo(
    memory::ByteVector& query,
    std::string_view domain,
    uint16_t txid,
    bool query_aaaa) {
    query.clear();
    query.reserve(18 + domain.size());

    query.push_back(static_cast<uint8_t>(txid >> 8));
    query.push_back(static_cast<uint8_t>(txid & 0xFF));

    query.push_back(0x01);
    query.push_back(0x00);

    query.push_back(0x00);
    query.push_back(0x01);

    query.push_back(0x00);
    query.push_back(0x00);

    query.push_back(0x00);
    query.push_back(0x00);

    query.push_back(0x00);
    query.push_back(0x00);

    size_t pos = 0;
    while (pos < domain.size()) {
        size_t dot = domain.find('.', pos);
        if (dot == std::string::npos) {
            dot = domain.size();
        }

        const size_t len = dot - pos;
        query.push_back(static_cast<uint8_t>(len));
        for (size_t i = pos; i < dot; ++i) {
            query.push_back(static_cast<uint8_t>(domain[i]));
        }

        pos = dot + 1;
    }
    query.push_back(0x00);

    const uint16_t qtype = query_aaaa ? wire::TYPE_AAAA : wire::TYPE_A;
    query.push_back(static_cast<uint8_t>(qtype >> 8));
    query.push_back(static_cast<uint8_t>(qtype & 0xFF));

    query.push_back(0x00);
    query.push_back(0x01);
}

DNS::Impl::ParsedResponse DNS::Impl::ParseResponse(
    std::span<const uint8_t> response,
    uint16_t expected_txid,
    uint32_t& out_ttl) {
    ParsedResponse result;

    if (response.size() < 12) {
        result.error = ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS response too short";
        return result;
    }

    const uint16_t txid =
        (static_cast<uint16_t>(response[0]) << 8) | response[1];
    if (txid != expected_txid) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = "DNS transaction ID mismatch";
        return result;
    }

    const uint16_t flags =
        (static_cast<uint16_t>(response[2]) << 8) | response[3];
    if (!(flags & wire::FLAG_QR)) {
        result.error = ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS packet is not a response";
        return result;
    }

    const uint8_t rcode = flags & wire::FLAG_RCODE;
    if (rcode == wire::RCODE_NAME_ERROR) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NXDOMAIN";
        result.negative_cacheable = true;
        return result;
    }
    if (rcode != wire::RCODE_OK) {
        switch (rcode) {
            case 2:
                result.error = ErrorCode::DNS_SERVER_FAILED;
                result.error_msg = "SERVFAIL";
                break;
            case 5:
                result.error = ErrorCode::DNS_REFUSED;
                result.error_msg = "REFUSED";
                break;
            default:
                result.error = ErrorCode::DNS_FORMAT_ERROR;
                result.error_msg = std::format(
                    "DNS response error rcode={}", rcode);
                break;
        }
        return result;
    }

    const uint16_t qdcount =
        (static_cast<uint16_t>(response[4]) << 8) | response[5];
    const uint16_t ancount =
        (static_cast<uint16_t>(response[6]) << 8) | response[7];
    if (ancount == 0) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NODATA";
        result.negative_cacheable = true;
        return result;
    }

    size_t pos = 12;
    for (uint16_t i = 0; i < qdcount; ++i) {
        while (pos < response.size()) {
            const uint8_t len = response[pos];
            if (len == 0) {
                ++pos;
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            pos += len + 1;
        }
        if (pos + 4 > response.size()) {
            result.error = ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS question section truncated";
            return result;
        }
        pos += 4;
    }

    std::vector<net::ip::address> addresses;
    addresses.reserve(ancount);
    uint32_t min_ttl = UINT32_MAX;

    for (uint16_t i = 0; i < ancount && pos < response.size(); ++i) {
        while (pos < response.size()) {
            const uint8_t len = response[pos];
            if (len == 0) {
                ++pos;
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            pos += len + 1;
        }

        if (pos + 10 > response.size()) {
            result.error = ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS answer header truncated";
            return result;
        }

        const uint16_t type =
            (static_cast<uint16_t>(response[pos]) << 8) | response[pos + 1];
        const uint32_t ttl =
            (static_cast<uint32_t>(response[pos + 4]) << 24) |
            (static_cast<uint32_t>(response[pos + 5]) << 16) |
            (static_cast<uint32_t>(response[pos + 6]) << 8) |
            response[pos + 7];
        const uint16_t rdlength =
            (static_cast<uint16_t>(response[pos + 8]) << 8) | response[pos + 9];

        pos += 10;
        if (pos + rdlength > response.size()) {
            result.error = ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS answer data truncated";
            return result;
        }

        min_ttl = std::min(min_ttl, ttl);

        if (type == wire::TYPE_A && rdlength == 4) {
            net::ip::address_v4::bytes_type bytes;
            std::memcpy(bytes.data(), &response[pos], 4);
            addresses.emplace_back(net::ip::address_v4(bytes));
        } else if (type == wire::TYPE_AAAA && rdlength == 16) {
            net::ip::address_v6::bytes_type bytes;
            std::memcpy(bytes.data(), &response[pos], 16);
            addresses.emplace_back(net::ip::address_v6(bytes));
        }

        pos += rdlength;
    }

    if (addresses.empty()) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = "No supported DNS records in response";
        result.negative_cacheable = true;
        return result;
    }

    out_ttl = (min_ttl == UINT32_MAX) ? 60 : min_ttl;
    result.addresses = std::move(addresses);
    result.ttl = out_ttl;
    return result;
}

DnsCacheStats DNS::Impl::GetCacheStats() const {
    return cache.GetStats();
}

void DNS::Impl::ClearCache() {
    cache.Clear();
}

net::awaitable<void> DNS::Impl::Prefetch(
    const std::vector<std::string>& domains) {
    if (domains.empty()) {
        co_return;
    }

    LOG_DEBUG("DNS prefetch starting for {} domains", domains.size());
    for (const auto& domain : domains) {
        if (domain.empty() || cache.Get(domain)) {
            continue;
        }

        try {
            auto result = co_await Resolve(domain);
            if (result.Ok()) {
                LOG_DEBUG("DNS prefetch: {} -> {} (ttl={}s)",
                          domain,
                          result.addresses.front().to_string(),
                          result.ttl);
            } else {
                LOG_DEBUG("DNS prefetch failed: {} - {}",
                          domain, result.error_msg);
            }
        } catch (const std::exception& e) {
            LOG_DEBUG("DNS prefetch exception: {} - {}", domain, e.what());
        }
    }
}

DNS::DNS(net::io_context& io_context, const Config& config)
    : impl_(std::make_unique<Impl>(io_context, config)) {
}

DNS::~DNS() = default;
DNS::DNS(DNS&&) noexcept = default;
DNS& DNS::operator=(DNS&&) noexcept = default;

net::awaitable<DnsResult> DNS::Resolve(std::string_view domain) {
    return impl_->Resolve(domain);
}

DnsCacheStats DNS::GetCacheStats() const {
    return impl_->GetCacheStats();
}

void DNS::ClearCache() {
    impl_->ClearCache();
}

net::awaitable<void> DNS::Prefetch(const std::vector<std::string>& domains) {
    return impl_->Prefetch(domains);
}

}  // namespace acpp::app::dns
