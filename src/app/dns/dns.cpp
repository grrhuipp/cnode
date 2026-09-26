#include "cache_internal.hpp"
#include "acppnode/app/dns/dns_worker.hpp"
#include "acppnode/app/worker_mailbox.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"
#include "global_cache.hpp"
#include "inflight_resolves.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/ip/udp.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <random>
#include <stdexcept>
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

constexpr size_t kAddressQueryAttempts = 3;

DnsResult MakeCachedResult(const DnsCacheEntry& entry) {
    DnsResult result;
    if (entry.negative) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NXDOMAIN (cached)";
    } else {
        result.addresses.assign(entry.addresses.begin(), entry.addresses.end());
    }
    result.ttl = entry.ttl;
    result.from_cache = true;
    return result;
}

void AppendUniqueAddresses(
    std::vector<net::ip::address>& out,
    std::span<const net::ip::address> addresses) {
    for (const auto& address : addresses) {
        if (std::ranges::find(out, address) == out.end()) {
            out.push_back(address);
        }
    }
}

}  // namespace

struct DNS::Impl {
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

    net::awaitable<DnsResult> ResolveUncached(std::string_view domain);
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
    const Config config;
    DnsCache cache;
    InflightResolves inflight_resolves;
    uint16_t txid_counter = 1;
};

DNS::Impl::Impl(net::io_context& io_context, const Config& config)
    : io_context(io_context)
    , config(config)
    , cache(config.cache_size, config.min_ttl, config.max_ttl)
    , inflight_resolves(io_context) {
    if (config.servers.empty()) {
        throw std::invalid_argument("DNS requires at least one server endpoint");
    }
    for (const auto& server : config.servers) {
        if (server.port() == 0) throw std::invalid_argument("DNS server port must be positive");
    }
    GlobalDnsCache::Configure(
        config.global_cache_size,
        config.min_ttl,
        config.max_ttl);

    std::random_device rd;
    txid_counter = static_cast<uint16_t>(rd() & 0xFFFF);
}

net::awaitable<DnsResult> DNS::Impl::Resolve(
    std::string_view domain) {
    if (const auto address = iputil::ParseLiteral(domain)) {
        DnsResult result;
        result.addresses.reserve(1);
        result.addresses.push_back(*address);
        co_return result;
    }
    if (!acpp::domain::IsValidDnsHostname(
            domain, acpp::domain::TrailingDotPolicy::Allow)) {
        DnsResult result;
        result.error = ErrorCode::INVALID_ARGUMENT;
        co_return result;
    }

    if (auto cached = cache.Get(domain)) {
        co_return MakeCachedResult(*cached);
    }

    if (auto cached = GlobalDnsCache::Lookup(domain)) {
        try {
            cache.Store(domain, *cached);
        } catch (const std::bad_alloc&) {
            // Optional L1 warming must not discard an available L2 answer.
        }
        co_return std::move(*cached);
    }

    co_return co_await inflight_resolves.Run(domain, [this, domain] {
        return ResolveUncached(domain);
    });
}

net::awaitable<DnsResult> DNS::Impl::ResolveUncached(std::string_view domain) {
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

    try {
        cache.Store(domain, result);
    } catch (const std::bad_alloc&) {
        // Cache storage is optional; resolution completion is not.
    }
    try {
        GlobalDnsCache::PublishResult(domain, result);
    } catch (const std::bad_alloc&) {
        // A failed snapshot allocation must not strand inflight subscribers.
    }

    co_return result;
}

net::awaitable<DnsResult> DNS::Impl::DoResolve(
    std::string_view domain) {
    DnsResult last_result;
    last_result.error = ErrorCode::DNS_RESOLVE_FAILED;
    last_result.error_msg = "DNS server unavailable";

    for (const auto& server : config.servers) {
        DnsResult a_result;
        a_result.error = ErrorCode::DNS_RESOLVE_FAILED;
        a_result.error_msg = "DNS A query failed";

        for (size_t attempt = 0; attempt < kAddressQueryAttempts; ++attempt) {
            auto attempt_result = co_await QueryServer(server, domain, false);
            if (attempt_result.Ok()) {
                if (!a_result.Ok()) {
                    a_result = std::move(attempt_result);
                } else {
                    AppendUniqueAddresses(a_result.addresses, attempt_result.addresses);
                    a_result.ttl = std::min(a_result.ttl, attempt_result.ttl);
                }
                continue;
            }
            if (!a_result.Ok()) {
                a_result = std::move(attempt_result);
            }
        }

        auto aaaa_result = co_await QueryServer(server, domain, true);

        if (a_result.Ok() || aaaa_result.Ok()) {
            DnsResult result;
            result.ttl = UINT32_MAX;
            result.error = ErrorCode::OK;
            result.addresses.reserve(
                (a_result.Ok() ? a_result.addresses.size() : 0) +
                (aaaa_result.Ok() ? aaaa_result.addresses.size() : 0));

            if (a_result.Ok()) {
                AppendUniqueAddresses(result.addresses, a_result.addresses);
                result.ttl = std::min(result.ttl, a_result.ttl);
            }
            if (aaaa_result.Ok()) {
                AppendUniqueAddresses(result.addresses, aaaa_result.addresses);
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
    bool timed_out = false;
    TimeoutToken timeout_token = TimeoutScheduler::ForIoContext(io_context).ScheduleAfter(
        std::chrono::seconds(config.timeout_sec),
        [&socket, &timed_out]() {
            timed_out = true;
            IoErrorCode ignored;
            socket.cancel(ignored);
        });
    auto [recv_ec, received] = co_await socket.async_receive(
        net::buffer(response),
        net::as_tuple(net::use_awaitable));
    TimeoutScheduler::ForIoContext(io_context).Cancel(timeout_token);

    if (recv_ec == io_error::operation_aborted && timed_out) {
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

struct DNSWorker::Impl {
    Impl(net::io_context& main_context,
         const DNS::Config& config, size_t mailbox_capacity)
        : server(main_context, config)
        , mailbox(main_context, mailbox_capacity) {}

    net::awaitable<DnsResult> ResolveOwned(std::string domain) {
        co_return co_await server.Resolve(domain);
    }

    net::awaitable<DnsCacheStats> ReadCacheStats() {
        co_return server.GetCacheStats();
    }

    DNS server;
    WorkerMailbox mailbox;
};

DNSWorker::DNSWorker(net::io_context& main_context,
                     const DNS::Config& config, size_t mailbox_capacity)
    : impl_(std::make_unique<Impl>(main_context, config, mailbox_capacity)) {}

DNSWorker::~DNSWorker() = default;

net::awaitable<DnsResult> DNSWorker::Resolve(std::string domain) {
    try {
        co_return co_await impl_->mailbox.Post(impl_->ResolveOwned(std::move(domain)));
    } catch (const WorkerMailboxFull&) {
        DnsResult rejected;
        rejected.error = ErrorCode::RESOURCE_EXHAUSTED;
        co_return rejected;
    }
}

net::awaitable<DnsCacheStats> DNSWorker::GetCacheStats() {
    co_return co_await impl_->mailbox.Post(impl_->ReadCacheStats());
}

DNS::DNS(net::io_context& io_context, const Config& config)
    : impl_(std::make_unique<Impl>(io_context, config)) {}

DNS::DNS(DNSWorker& worker) : dns_worker_(&worker) {}

DNS::~DNS() = default;

net::awaitable<DnsResult> DNS::Resolve(std::string_view domain) {
    if (dns_worker_) {
        co_return co_await dns_worker_->Resolve(std::string(domain));
    }
    co_return co_await impl_->Resolve(domain);
}

DnsCacheStats DNS::GetCacheStats() const {
    // Remote facades own no DNS cache. The dedicated service owns its stats.
    return impl_ ? impl_->GetCacheStats() : DnsCacheStats{};
}

DnsCacheStats DNS::GetGlobalCacheStats() {
    return GlobalDnsCache::GetStats();
}

}  // namespace acpp::app::dns
