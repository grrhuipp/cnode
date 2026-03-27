#include "acppnode/dns/dns_service.hpp"
#include "acppnode/infra/log.hpp"

#include <boost/asio/cancel_after.hpp>
#include <boost/asio/ip/udp.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <random>

namespace acpp {

namespace dns {

constexpr uint16_t FLAG_QR    = 0x8000;
constexpr uint16_t FLAG_RCODE = 0x000F;

constexpr uint16_t TYPE_A    = 1;
constexpr uint8_t RCODE_OK         = 0;
constexpr uint8_t RCODE_NAME_ERROR = 3;

}  // namespace dns

namespace {

DnsResult MakeCachedResult(const DnsCacheEntry& entry) {
    DnsResult result;
    if (entry.negative) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NXDOMAIN (cached)";
    } else {
        result.addresses = entry.addresses;
        result.ttl = entry.ttl;
    }
    result.from_cache = true;
    return result;
}

void StoreResult(DnsCache& cache,
                 const std::string& domain,
                 const DnsResult& result) {
    if (result.Ok()) {
        cache.Put(domain, result.addresses, result.ttl);
    } else if (result.error == ErrorCode::DNS_NO_RECORD) {
        cache.PutNegative(domain, 60);
    }
}

}  // namespace

DnsService::DnsService(net::any_io_executor executor, const Config& config)
    : executor_(std::move(executor))
    , config_(config)
    , cache_(std::allocate_shared<DnsCache>(
        memory::ThreadLocalAllocator<DnsCache>{},
        config.cache_size, config.min_ttl, config.max_ttl)) {
    servers_.reserve(config.servers.size());
    for (const auto& server : config.servers) {
        boost::system::error_code ec;
        auto addr = net::ip::make_address(server, ec);
        if (!ec) {
            servers_.emplace_back(addr, 53);
        } else {
            LOG_WARN("Invalid DNS server address: {}", server);
        }
    }

    if (servers_.empty()) {
        servers_.emplace_back(net::ip::make_address("8.8.8.8"), 53);
        servers_.emplace_back(net::ip::make_address("1.1.1.1"), 53);
    }

    std::random_device rd;
    txid_counter_.store(static_cast<uint16_t>(rd() & 0xFFFF),
                        std::memory_order_relaxed);
}

DnsService::~DnsService() = default;

cobalt::task<DnsResult> DnsService::Resolve(
    const std::string& domain) {
    boost::system::error_code ec;
    auto addr = net::ip::make_address(domain, ec);
    if (!ec) {
        if (!addr.is_v4()) {
            DnsResult result;
            result.error = ErrorCode::PROTOCOL_INVALID_ADDRESS;
            result.error_msg = "only IPv4 literals are supported";
            co_return result;
        }
        DnsResult result;
        result.addresses.reserve(1);
        result.addresses.push_back(addr);
        co_return result;
    }

    if (auto cached = cache_->Get(domain)) {
        co_return MakeCachedResult(*cached);
    }

    ResolveKey key{domain};
    auto existing = inflight_resolves_.find(key);
    if (existing != inflight_resolves_.end()) {
        auto inflight = existing->second;
        if (inflight->completed) {
            co_return inflight->result;
        }

        auto wait_timer = std::allocate_shared<net::steady_timer>(
            memory::ThreadLocalAllocator<net::steady_timer>{},
            executor_);
        wait_timer->expires_at(net::steady_timer::time_point::max());
        inflight->waiters.push_back(wait_timer);

        auto [wait_ec] = co_await wait_timer->async_wait(
            net::as_tuple(cobalt::use_op));
        (void)wait_ec;
        co_return inflight->result;
    }

    auto inflight = std::allocate_shared<InflightResolve>(
        memory::ThreadLocalAllocator<InflightResolve>{});
    inflight_resolves_.emplace(key, inflight);

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

    StoreResult(*cache_, domain, result);

    inflight->completed = true;
    inflight->result = result;
    auto waiters = std::move(inflight->waiters);
    inflight_resolves_.erase(key);

    for (auto& waiter : waiters) {
        waiter->cancel();
    }

    co_return result;
}

cobalt::task<DnsResult> DnsService::DoResolve(
    const std::string& domain) {
    DnsResult last_result;
    last_result.error = ErrorCode::DNS_RESOLVE_FAILED;
    last_result.error_msg = "DNS server unavailable";

    for (const auto& server : servers_) {
        auto result = co_await QueryServer(server, domain, false);
        if (result.Ok() || result.error == ErrorCode::DNS_NO_RECORD) {
            co_return result;
        }
        last_result = std::move(result);
    }

    co_return last_result;
}

cobalt::task<DnsResult> DnsService::QueryServer(
    const net::ip::udp::endpoint& server,
    const std::string& domain,
    bool query_aaaa) {
    DnsResult result;
    const uint16_t txid = txid_counter_.fetch_add(1, std::memory_order_relaxed);
    auto query = BuildQuery(domain, txid, query_aaaa);

    udp::socket socket(executor_);
    boost::system::error_code ec;
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
        net::as_tuple(cobalt::use_op));
    (void)sent;
    if (send_ec) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = send_ec.message();
        co_return result;
    }

    std::array<uint8_t, 512> response{};
    net::steady_timer timeout_timer(executor_);
    auto [recv_ec, received] = co_await socket.async_receive(
        net::buffer(response),
        net::cancel_after(
            timeout_timer,
            std::chrono::seconds(config_.timeout_sec),
            net::as_tuple(cobalt::use_op)));

    if (recv_ec == net::error::operation_aborted &&
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

    uint32_t ttl = config_.min_ttl;
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

memory::ByteVector DnsService::BuildQuery(
    const std::string& domain, uint16_t txid, bool query_aaaa) {
    memory::ByteVector query;
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

    const uint16_t qtype = dns::TYPE_A;
    query.push_back(static_cast<uint8_t>(qtype >> 8));
    query.push_back(static_cast<uint8_t>(qtype & 0xFF));

    query.push_back(0x00);
    query.push_back(0x01);

    return query;
}

DnsService::ParsedResponse DnsService::ParseResponse(
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
    if (!(flags & dns::FLAG_QR)) {
        result.error = ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS packet is not a response";
        return result;
    }

    const uint8_t rcode = flags & dns::FLAG_RCODE;
    if (rcode == dns::RCODE_NAME_ERROR) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NXDOMAIN";
        result.negative_cacheable = true;
        return result;
    }
    if (rcode != dns::RCODE_OK) {
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

        if (type == dns::TYPE_A && rdlength == 4) {
            net::ip::address_v4::bytes_type bytes;
            std::memcpy(bytes.data(), &response[pos], 4);
            addresses.emplace_back(net::ip::address_v4(bytes));
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

DnsCacheStats DnsService::GetCacheStats() const {
    return cache_->GetStats();
}

void DnsService::ClearCache() {
    cache_->Clear();
}

cobalt::task<void> DnsService::Prefetch(
    const std::vector<std::string>& domains) {
    if (domains.empty()) {
        co_return;
    }

    LOG_DEBUG("DNS prefetch starting for {} domains", domains.size());
    for (const auto& domain : domains) {
        if (domain.empty() || cache_->Get(domain)) {
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

std::unique_ptr<IDnsService> CreateDnsService(
    net::any_io_executor executor,
    const DnsService::Config& config) {
    return std::make_unique<DnsService>(std::move(executor), config);
}

}  // namespace acpp
