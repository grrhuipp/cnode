#include "app/dns/dns_internal.hpp"
#include "app/worker_mailbox.hpp"
#include "common/byte_reader.hpp"
#include "common/domain_name.hpp"
#include "common/ip_address.hpp"
#include "infra/log.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <stdexcept>
#include <span>

namespace app {

namespace {

constexpr uint16_t FLAG_QR    = 0x8000;
constexpr uint16_t FLAG_RCODE = 0x000F;

constexpr uint16_t TYPE_A     = 1;
constexpr uint16_t TYPE_CNAME = 5;
constexpr uint16_t TYPE_AAAA  = 28;
constexpr uint8_t RCODE_OK         = 0;
constexpr uint8_t RCODE_NAME_ERROR = 3;


constexpr size_t kAddressQueryAttempts = 3;

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

struct DNSWorker::Impl {
    Impl(net::io_context& io_context, const DnsConfig& config, size_t mailbox_capacity);

    net::awaitable<DnsResult> ResolveOwned(std::string domain);

    net::awaitable<DnsResult> ResolveUncached(std::string_view domain);
    net::awaitable<DnsResult> DoResolve(std::string_view domain);
    net::awaitable<DnsResult> QueryServer(
        DatagramExchange& server,
        std::string_view domain,
        bool query_aaaa);
    // Leaves the ID zero; DatagramExchange writes an unpredictable ID before send.
    static size_t BuildQueryTo(std::span<uint8_t, 280> query,
                               std::string_view domain,
                               bool query_aaaa) noexcept;
    DnsResult ParseResponse(std::span<const uint8_t> response,
                            uint16_t expected_txid,
                            bool query_aaaa);

    net::io_context& io_context;
    const DnsConfig config;
    DnsCache cache;
    InflightResolves inflight_resolves;
    std::vector<std::shared_ptr<DatagramExchange>> upstreams;
    WorkerMailbox mailbox;
    bool stopping = false;
};

DNSWorker::Impl::Impl(net::io_context& io_context, const DnsConfig& config,
                      size_t mailbox_capacity)
    : io_context(io_context)
    , config(config)
    , cache(config.cache_size, config.min_ttl, config.max_ttl,
        [](std::string_view domain, std::string_view reason, uint64_t hits,
           std::string_view event) {
            LOG_INFO("DNS negative cache {} event={} hits={} suppressed={} > {}",
                     domain, event, hits, hits, reason);
        })
    , inflight_resolves(io_context, mailbox_capacity)
    , mailbox(io_context, mailbox_capacity) {
    if (config.servers.empty()) {
        throw std::invalid_argument("DNS requires at least one server endpoint");
    }
    for (const auto& server : config.servers) {
        if (server.port() == 0) throw std::invalid_argument("DNS server port must be positive");
    }
    upstreams.reserve(config.servers.size());
    for (const auto& server : config.servers) {
        upstreams.push_back(std::make_shared<DatagramExchange>(io_context, server));
    }
}

net::awaitable<DnsResult> DNSWorker::Impl::ResolveOwned(std::string owned_domain) {
    // The only lookup entry owns input throughout cache/inflight/upstream I/O.
    std::string_view domain = owned_domain;
    if (stopping) {
        DnsResult cancelled;
        cancelled.error = common::ErrorCode::CANCELLED;
        co_return cancelled;
    }
    if (const auto address = common::ParseLiteral(domain)) {
        DnsResult result;
        result.addresses.reserve(1);
        result.addresses.push_back(*address);
        co_return result;
    }
    if (!common::IsValidDnsHostname(
            domain, common::TrailingDotPolicy::Allow)) {
        DnsResult result;
        result.error = common::ErrorCode::INVALID_ARGUMENT;
        co_return result;
    }

    common::NormalizeDnsHostnameInPlace(owned_domain);
    domain = owned_domain;
    auto cached = cache.GetResult(domain);
    auto result = cached ? std::move(*cached) :
        co_await inflight_resolves.Run(domain, [this](std::string_view query_domain) {
            return ResolveUncached(query_domain);
        });
    co_return result;
}

net::awaitable<DnsResult> DNSWorker::Impl::ResolveUncached(std::string_view domain) {
    DnsResult result;
    try {
        result = co_await DoResolve(domain);
    } catch (const IoSystemError& error) {
        result.error = error.code() == io_error::operation_aborted
            ? common::ErrorCode::CANCELLED : common::ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = error.code().message();
    } catch (const std::exception& e) {
        result.error = common::ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = e.what();
    } catch (...) {
        result.error = common::ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = "DNS resolve exception";
    }

    if (stopping) {
        result = {};
        result.error = common::ErrorCode::CANCELLED;
    }
    if (result.error == common::ErrorCode::CANCELLED) co_return result;
    // One upstream event per shared query; negative cache hits are counted and
    // summarized by the cache instead of warning once per connection.
    if (!result.Ok()) {
        LOG_WARN("failed to resolve {} (error={} source=upstream) > {}",
                 domain, common::ErrorCodeToString(result.error), result.error_msg);
    }

    try {
        cache.Store(domain, result);
    } catch (const std::bad_alloc&) {
        // Cache storage is optional; resolution completion is not.
    }
    co_return result;
}

net::awaitable<DnsResult> DNSWorker::Impl::DoResolve(
    std::string_view domain) {
    DnsResult last_result;
    last_result.error = common::ErrorCode::DNS_RESOLVE_FAILED;
    last_result.error_msg = "DNS server unavailable";

    for (size_t server_index = 0; server_index < upstreams.size(); ++server_index) {
        const auto& server = upstreams[server_index];
        if (stopping) {
            last_result.error = common::ErrorCode::CANCELLED;
            co_return last_result;
        }
        // Preserve three A samples (round-robin answer collection), but do not
        // serialize their RTTs or hold AAAA behind them. Join all children before
        // returning or moving to another upstream, including cancellation/OOM.
        std::array<DnsResult, kAddressQueryAttempts + 1> answers;
        auto collect = [&](size_t index) -> net::awaitable<void> {
            answers[index] = co_await QueryServer(*server, domain, index == kAddressQueryAttempts);
        };
        co_await common::RunAwaitableTaskGroup(co_await net::this_coro::executor, [&](common::AwaitableTaskGroup& group) {
            for (size_t i = 0; i < answers.size(); ++i) group.Spawn(collect(i));
        });
        if (stopping || std::ranges::any_of(answers, [](const DnsResult& answer) {
                return answer.error == common::ErrorCode::CANCELLED;
            })) {
            DnsResult cancelled;
            cancelled.error = common::ErrorCode::CANCELLED;
            co_return cancelled;
        }
        DnsResult a_result;
        a_result.error = common::ErrorCode::DNS_RESOLVE_FAILED;
        a_result.error_msg = "DNS A query failed";

        for (size_t attempt = 0; attempt < kAddressQueryAttempts; ++attempt) {
            auto attempt_result = std::move(answers[attempt]);
            if (attempt_result.Ok()) {
                if (!a_result.Ok()) {
                    a_result = std::move(attempt_result);
                } else {
                    AppendUniqueAddresses(a_result.addresses, attempt_result.addresses);
                    a_result.ttl = std::min(a_result.ttl, attempt_result.ttl);
                }
                continue;
            }
            if (!a_result.Ok() && a_result.error != common::ErrorCode::DNS_NO_RECORD) {
                a_result = std::move(attempt_result);
            }
        }

        auto aaaa_result = std::move(answers.back());

        if (a_result.Ok() || aaaa_result.Ok()) {
            DnsResult result;
            result.ttl = UINT32_MAX;
            result.error = common::ErrorCode::OK;
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

        const bool no_records = a_result.error == common::ErrorCode::DNS_NO_RECORD &&
                                aaaa_result.error == common::ErrorCode::DNS_NO_RECORD;
        const auto& endpoint = config.servers[server_index];
        auto reason = std::format(
            "server {} port {} > A: {} > {}; AAAA: {} > {}",
            common::AddressText(endpoint.address()).View(), endpoint.port(),
            common::ErrorCodeToString(a_result.error), a_result.error_msg,
            common::ErrorCodeToString(aaaa_result.error), aaaa_result.error_msg);
        last_result = a_result.error == common::ErrorCode::DNS_NO_RECORD && !no_records
            ? std::move(aaaa_result)
            : std::move(a_result);
        last_result.error_msg = std::move(reason);
        if (no_records) co_return last_result;
    }

    co_return last_result;
}

net::awaitable<DnsResult> DNSWorker::Impl::QueryServer(
    DatagramExchange& server,
    std::string_view domain,
    bool query_aaaa) {
    DnsResult result;
    // BuildQueryTo and Exchange write every byte of [0, query_size).
    std::array<uint8_t, 280> query;
    const size_t query_size = BuildQueryTo(query, domain, query_aaaa);
    auto response = co_await server.Exchange(
        std::span<uint8_t>(query.data(), query_size),
        std::chrono::seconds(config.timeout_sec));
    if (response.error) {
        result.error = response.error == io_error::timed_out ? common::ErrorCode::DNS_TIMEOUT :
            response.error == io_error::operation_aborted ? common::ErrorCode::CANCELLED :
            response.error == io_error::no_buffer_space ? common::ErrorCode::RESOURCE_EXHAUSTED :
            common::ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = response.error.message();
        co_return result;
    }
    const uint16_t txid = common::LoadU16BE(query.data());
    co_return ParseResponse(
        std::span<const uint8_t>(response.bytes.data(), response.size),
        txid,
        query_aaaa);
}

size_t DNSWorker::Impl::BuildQueryTo(
    std::span<uint8_t, 280> query,
    std::string_view domain,
    bool query_aaaa) noexcept {
    query[2] = 0x01;
    query[3] = 0x00;
    query[4] = 0x00;
    query[5] = 0x01;
    std::memset(query.data() + 6, 0, 6);

    size_t out = 12;
    size_t pos = 0;
    while (pos < domain.size()) {
        size_t dot = domain.find('.', pos);
        if (dot == std::string_view::npos) {
            dot = domain.size();
        }
        const size_t len = dot - pos;
        query[out++] = static_cast<uint8_t>(len);
        std::memcpy(query.data() + out, domain.data() + pos, len);
        out += len;
        pos = dot + 1;
    }
    query[out++] = 0x00;

    const uint16_t qtype = query_aaaa ? TYPE_AAAA : TYPE_A;
    common::StoreU16BE(query.data() + out, qtype);
    common::StoreU16BE(query.data() + out + 2, 1);
    return out + 4;
}

DnsResult DNSWorker::Impl::ParseResponse(
    std::span<const uint8_t> response, uint16_t expected_txid, bool query_aaaa) {
    DnsResult result;

    if (response.size() < 12) {
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS response too short";
        return result;
    }

    const uint16_t txid = common::LoadU16BE(response.data());
    if (txid != expected_txid) {
        result.error = common::ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = "DNS transaction ID mismatch";
        return result;
    }

    const uint16_t flags = common::LoadU16BE(response.data() + 2);
    if (!(flags & FLAG_QR) || (flags & 0x0200)) {
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS packet is not a complete response";
        return result;
    }

    const uint8_t rcode = flags & FLAG_RCODE;
    if (rcode != RCODE_OK && rcode != RCODE_NAME_ERROR) {
        switch (rcode) {
            case 2:
                result.error = common::ErrorCode::DNS_SERVER_FAILED;
                result.error_msg = "SERVFAIL";
                break;
            case 5:
                result.error = common::ErrorCode::DNS_REFUSED;
                result.error_msg = "REFUSED";
                break;
            default:
                result.error = common::ErrorCode::DNS_FORMAT_ERROR;
                result.error_msg = std::format(
                    "DNS response error rcode={}", rcode);
                break;
        }
        return result;
    }

    const uint16_t qdcount = common::LoadU16BE(response.data() + 4);
    if (qdcount != 1) {
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS question count is not 1";
        return result;
    }

    size_t pos = 12;
    if (!DatagramExchange::SkipWireName(response, pos) || pos + 4 > response.size()) {
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS question section truncated";
        return result;
    }
    const uint16_t qtype = common::LoadU16BE(response.data() + pos);
    const uint16_t qclass = common::LoadU16BE(response.data() + pos + 2);
    if (qtype != (query_aaaa ? TYPE_AAAA : TYPE_A) || qclass != 1) {
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS question section invalid";
        return result;
    }
    pos += 4;

    if (rcode == RCODE_NAME_ERROR) {
        result.error = common::ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NXDOMAIN";
        return result;
    }

    const uint16_t ancount = common::LoadU16BE(response.data() + 6);
    if (ancount == 0) {
        result.error = common::ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NODATA";
        return result;
    }

    if (ancount > (response.size() - pos) / 11) {
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS answer count exceeds packet";
        return result;
    }
    std::vector<net::ip::address> addresses;
    addresses.reserve(ancount);
    uint32_t min_ttl = UINT32_MAX;

    for (uint16_t i = 0; i < ancount; ++i) {
        if (!DatagramExchange::SkipWireName(response, pos) || pos + 10 > response.size()) {
            result.error = common::ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS answer header truncated";
            return result;
        }

        const uint16_t type = common::LoadU16BE(response.data() + pos);
        if (response[pos + 2] != 0 || response[pos + 3] != 1) {
            result.error = common::ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS answer class is not IN";
            return result;
        }
        const uint32_t wire_ttl = common::LoadU32BE(response.data() + pos + 4);
        // RFC 2181 §8：收到最高位置位的 TTL 时，整个值按零处理。
        const uint32_t ttl = (wire_ttl & 0x80000000u) != 0 ? 0 : wire_ttl;
        const uint16_t rdlength = common::LoadU16BE(response.data() + pos + 8);

        pos += 10;
        if (pos + rdlength > response.size()) {
            result.error = common::ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS answer data truncated";
            return result;
        }

        if ((type == TYPE_A && rdlength != 4) ||
            (type == TYPE_AAAA && rdlength != 16)) {
            result.error = common::ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = std::format("DNS {} record has invalid RDLENGTH {} (expected {})",
                type == TYPE_A ? "A" : "AAAA", rdlength,
                type == TYPE_A ? 4 : 16);
            return result;
        }

        if (!query_aaaa && type == TYPE_A) {
            min_ttl = std::min(min_ttl, ttl);
            net::ip::address_v4::bytes_type bytes;
            std::memcpy(bytes.data(), &response[pos], 4);
            addresses.emplace_back(net::ip::address_v4(bytes));
        } else if (query_aaaa && type == TYPE_AAAA) {
            min_ttl = std::min(min_ttl, ttl);
            net::ip::address_v6::bytes_type bytes;
            std::memcpy(bytes.data(), &response[pos], 16);
            addresses.emplace_back(net::ip::address_v6(bytes));
        } else if (type == TYPE_CNAME) {
            min_ttl = std::min(min_ttl, ttl);
        }
        pos += rdlength;
    }

    if (addresses.empty()) {
        result.error = common::ErrorCode::DNS_NO_RECORD;
        result.error_msg = "No supported DNS records in response";
        return result;
    }

    result.addresses = std::move(addresses);
    result.ttl = (min_ttl == UINT32_MAX) ? 60 : min_ttl;
    return result;
}

DNSWorker::DNSWorker(net::io_context& main_context,
                     const DnsConfig& config, size_t mailbox_capacity)
    : impl_(std::make_unique<Impl>(main_context, config, mailbox_capacity)) {}

DNSWorker::~DNSWorker() = default;

void DNSWorker::RequestStop() noexcept {
    impl_->mailbox.CloseAdmission();
    impl_->stopping = true;
    impl_->inflight_resolves.RequestStop();
    for (const auto& upstream : impl_->upstreams) upstream->RequestStop();
}

net::awaitable<void> DNSWorker::AsyncJoin() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    co_await net::this_coro::throw_if_cancelled(false);
    RequestStop();
    co_await impl_->mailbox.AsyncJoinAccepted();
    co_await impl_->inflight_resolves.AsyncJoin();
    // A query can finish before its shared socket's cancelled receive callback.
    // Both boundaries must pass while the DNS executor and scheduler still live.
    for (const auto& upstream : impl_->upstreams) co_await upstream->AsyncJoin();
}

net::awaitable<DnsResult> DNSWorker::Resolve(std::string domain) {
    try {
        co_return co_await impl_->mailbox.Post(impl_->ResolveOwned(std::move(domain)));
    } catch (const WorkerMailboxFull&) {
        DnsResult rejected;
        rejected.error = common::ErrorCode::RESOURCE_EXHAUSTED;
        co_return rejected;
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::operation_aborted) throw;
        DnsResult cancelled;
        cancelled.error = common::ErrorCode::CANCELLED;
        co_return cancelled;
    }
}

net::awaitable<DnsCacheStats> DNSWorker::GetCacheStats() {
    return impl_->mailbox.PostCall([impl = impl_.get()] { return impl->cache.GetStats(); });
}

}  // namespace app
