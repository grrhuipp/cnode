#include "app/dns_internal.hpp"
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
constexpr uint16_t FLAG_TC    = 0x0200;
constexpr uint16_t FLAG_RCODE = 0x000F;

constexpr uint16_t TYPE_A     = 1;
constexpr uint16_t TYPE_CNAME = 5;
constexpr uint16_t TYPE_SOA   = 6;
constexpr uint16_t TYPE_AAAA  = 28;
constexpr uint16_t TYPE_OPT   = 41;
constexpr uint8_t RCODE_OK         = 0;
constexpr uint8_t RCODE_NAME_ERROR = 3;

// Root owner, TYPE, CLASS, TTL and RDLENGTH of the RFC 6891 OPT record.
constexpr size_t kOptRecordSize = 11;
// Header, longest wire QNAME, QTYPE/QCLASS and the OPT record.
constexpr size_t kQueryCapacity = 12 + 255 + 4 + kOptRecordSize;
// Local budget, not a protocol limit: a TCP answer may hold thousands of
// addresses, which the dedupe, cache entries and per-hit copies must not carry.
constexpr size_t kMaxAnswerAddresses = 64;
// CNAME hops followed within one answer; matches the BIND and Unbound
// default of 11 query restarts.
constexpr size_t kMaxCnameChain = 11;


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

// Uncompressed, lowercased wire-format name (RFC 4034 §6.2 canonical form),
// compared octet-wise after case folding as RFC 1035 §2.3.3 / RFC 4343 require.
struct WireName {
    std::array<uint8_t, 255> bytes;
    size_t size = 0;

    [[nodiscard]] bool operator==(const WireName& other) const noexcept {
        return size == other.size &&
               std::equal(bytes.begin(), bytes.begin() + size, other.bytes.begin());
    }
};

// Same compression rules as UpstreamExchange::SkipWireName: only strictly
// backward pointers, so traversal is bounded by the packet length.
[[nodiscard]] bool ReadWireName(std::span<const uint8_t> packet, size_t& offset,
                                WireName& out) noexcept {
    size_t current = offset;
    size_t resume = 0;
    bool jumped = false;
    out.size = 0;
    while (current < packet.size()) {
        const uint8_t len = packet[current];
        if (len == 0) {
            out.bytes[out.size++] = 0;
            offset = jumped ? resume : current + 1;
            return true;
        }
        if ((len & 0xC0) == 0xC0) {
            if (current + 1 >= packet.size()) return false;
            const size_t ptr = common::LoadU16BE(packet.data() + current) & 0x3FFFu;
            if (ptr < 12 || ptr >= current) return false;
            if (!jumped) {
                resume = current + 2;
                jumped = true;
            }
            current = ptr;
            continue;
        }
        if ((len & 0xC0) != 0) return false;
        if (packet.size() - current <= static_cast<size_t>(len) + 1) return false;
        // Keep one octet for the root label: whole names are at most 255.
        if (out.size + len + 1 >= out.bytes.size()) return false;
        out.bytes[out.size++] = len;
        for (size_t i = 1; i <= len; ++i) {
            out.bytes[out.size++] = common::ToLowerAscii(packet[current + i]);
        }
        current += static_cast<size_t>(len) + 1;
    }
    return false;
}

// True when zone equals name or is one of its label-aligned ancestors.
[[nodiscard]] bool IsSameOrAncestor(const WireName& zone, const WireName& name) noexcept {
    for (size_t offset = 0; offset < name.size; offset += static_cast<size_t>(name.bytes[offset]) + 1) {
        if (name.size - offset == zone.size &&
            std::equal(zone.bytes.begin(), zone.bytes.begin() + zone.size, name.bytes.begin() + offset)) {
            return true;
        }
        if (name.bytes[offset] == 0) break;
    }
    return false;
}

// RFC 2181 §8: a TTL with the most significant bit set is treated as zero.
[[nodiscard]] uint32_t WireTtl(const uint8_t* data) noexcept {
    const uint32_t ttl = common::LoadU32BE(data);
    return (ttl & 0x80000000u) != 0 ? 0 : ttl;
}

}  // namespace

struct DNSWorker::Impl {
    Impl(net::io_context& io_context, const DnsConfig& config, size_t mailbox_capacity);

    net::awaitable<DnsResult> ResolveOwned(std::string domain);

    net::awaitable<DnsResult> ResolveUncached(std::string_view domain);
    net::awaitable<DnsResult> DoResolve(std::string_view domain);
    // Leaves out empty when a sibling sample already owns this family's TCP
    // retry: the stream answer is the complete RRset for every sample.
    net::awaitable<void> QueryServer(
        UpstreamExchange& server,
        std::string_view domain,
        bool query_aaaa,
        bool& stream_claimed,
        std::optional<DnsResult>& out);
    // Leaves the ID zero; UpstreamExchange writes an unpredictable ID before send.
    static size_t BuildQueryTo(std::span<uint8_t, kQueryCapacity> query,
                               std::string_view domain,
                               bool query_aaaa) noexcept;
    DnsResult ParseResponse(std::span<const uint8_t> response,
                            uint16_t expected_txid,
                            bool query_aaaa);

    net::io_context& io_context;
    const DnsConfig config;
    DnsCache cache;
    InflightResolves inflight_resolves;
    std::vector<std::shared_ptr<UpstreamExchange>> upstreams;
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
        upstreams.push_back(std::make_shared<UpstreamExchange>(io_context, server));
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
        std::array<std::optional<DnsResult>, kAddressQueryAttempts + 1> answers;
        std::array<bool, 2> stream_claimed{};  // A, AAAA
        co_await common::RunAwaitableTaskGroup(co_await net::this_coro::executor, [&](common::AwaitableTaskGroup& group) {
            for (size_t i = 0; i < answers.size(); ++i) {
                const bool query_aaaa = i == kAddressQueryAttempts;
                group.Spawn(QueryServer(*server, domain, query_aaaa, stream_claimed[query_aaaa], answers[i]));
            }
        });
        if (stopping || std::ranges::any_of(answers, [](const std::optional<DnsResult>& answer) {
                return answer && answer->error == common::ErrorCode::CANCELLED;
            })) {
            DnsResult cancelled;
            cancelled.error = common::ErrorCode::CANCELLED;
            co_return cancelled;
        }
        DnsResult a_result;
        a_result.error = common::ErrorCode::DNS_RESOLVE_FAILED;
        a_result.error_msg = "DNS A query failed";

        for (size_t attempt = 0; attempt < kAddressQueryAttempts; ++attempt) {
            if (!answers[attempt]) continue;  // Covered by the sibling's TCP retry.
            auto attempt_result = std::move(*answers[attempt]);
            if (attempt_result.Ok()) {
                if (!a_result.Ok()) {
                    a_result = std::move(attempt_result);
                } else {
                    AppendUniqueAddresses(a_result.addresses, attempt_result.addresses);
                    a_result.ttl = std::min(a_result.ttl, attempt_result.ttl);
                }
                continue;
            }
            if (attempt_result.error == common::ErrorCode::DNS_NO_RECORD &&
                a_result.error == common::ErrorCode::DNS_NO_RECORD) {
                // The negative answer may be cached only as long as every
                // sample allows (RFC 2308 §5).
                a_result.ttl = std::min(a_result.ttl, attempt_result.ttl);
            } else if (!a_result.Ok() && a_result.error != common::ErrorCode::DNS_NO_RECORD) {
                a_result = std::move(attempt_result);
            }
        }

        // The only AAAA query always owns its family's TCP retry.
        auto aaaa_result = std::move(*answers.back());

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
        // A name without either address family is cached for the shorter of
        // the two negative TTLs (0 when either lacked a SOA).
        const uint32_t negative_ttl = std::min(a_result.ttl, aaaa_result.ttl);
        last_result = a_result.error == common::ErrorCode::DNS_NO_RECORD && !no_records
            ? std::move(aaaa_result)
            : std::move(a_result);
        last_result.error_msg = std::move(reason);
        if (no_records) {
            last_result.ttl = negative_ttl;
            co_return last_result;
        }
    }

    co_return last_result;
}

net::awaitable<void> DNSWorker::Impl::QueryServer(
    UpstreamExchange& server,
    std::string_view domain,
    bool query_aaaa,
    bool& stream_claimed,
    std::optional<DnsResult>& out) {
    // BuildQueryTo and ExchangeDatagram write every byte of [0, query_size).
    std::array<uint8_t, kQueryCapacity> query;
    size_t query_size = BuildQueryTo(query, domain, query_aaaa);
    // One deadline bounds the datagram, the plain retry and the TCP retry.
    const auto deadline = common::steady_clock::now() + std::chrono::seconds(config.timeout_sec);
    const auto remaining = [deadline] {
        return std::chrono::ceil<std::chrono::milliseconds>(deadline - common::steady_clock::now());
    };
    auto response = co_await server.ExchangeDatagram(
        std::span<uint8_t>(query.data(), query_size), remaining());
    if (!response.error && UpstreamExchange::RejectsEdns(response.bytes)) {
        // Ask once more without the extension; the OPT record is last.
        common::StoreU16BE(query.data() + 10, 0);
        query_size -= kOptRecordSize;
        response = co_await server.ExchangeDatagram(
            std::span<uint8_t>(query.data(), query_size), remaining());
    }
    // A datagram longer than the advertised payload breaks RFC 6891 §6.2.5 and
    // was cut by the receive buffer; like TC, only TCP can deliver it whole.
    const bool truncated = !response.error && response.bytes.size() >= 4 &&
        ((common::LoadU16BE(response.bytes.data() + 2) & FLAG_TC) != 0 ||
         response.bytes.size() > kDnsUdpPayloadSize);
    if (truncated) {
        // RFC 7766 §5: a truncated UDP answer is retried over TCP, once per
        // family; samples run on one executor, so the first to see TC claims it.
        if (stream_claimed) co_return;
        stream_claimed = true;
        response = co_await server.ExchangeStream(
            std::span<const uint8_t>(query.data(), query_size), remaining());
    }
    if (response.error) {
        DnsResult& failed = out.emplace();
        failed.error = response.error == io_error::timed_out ? common::ErrorCode::DNS_TIMEOUT :
            response.error == io_error::operation_aborted ? common::ErrorCode::CANCELLED :
            response.error == io_error::no_buffer_space ? common::ErrorCode::RESOURCE_EXHAUSTED :
            common::ErrorCode::DNS_RESOLVE_FAILED;
        failed.error_msg = truncated
            ? std::format("TCP retry of truncated answer: {}", response.error.message())
            : response.error.message();
        co_return;
    }
    const uint16_t txid = common::LoadU16BE(query.data());
    out = ParseResponse(response.bytes, txid, query_aaaa);
}

size_t DNSWorker::Impl::BuildQueryTo(
    std::span<uint8_t, kQueryCapacity> query,
    std::string_view domain,
    bool query_aaaa) noexcept {
    query[2] = 0x01;
    query[3] = 0x00;
    common::StoreU16BE(query.data() + 4, 1);   // QDCOUNT
    std::memset(query.data() + 6, 0, 4);       // ANCOUNT, NSCOUNT
    common::StoreU16BE(query.data() + 10, 1);  // ARCOUNT: OPT

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
    out += 4;

    // RFC 6891 §6.1.2: root owner, CLASS carries the UDP payload size, TTL
    // carries extended RCODE/version/flags (all zero), empty RDATA.
    query[out] = 0x00;
    common::StoreU16BE(query.data() + out + 1, TYPE_OPT);
    common::StoreU16BE(query.data() + out + 3, static_cast<uint16_t>(kDnsUdpPayloadSize));
    std::memset(query.data() + out + 5, 0, 6);
    return out + kOptRecordSize;
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
    if (!(flags & FLAG_QR)) {
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS packet is not a response";
        return result;
    }
    if (flags & FLAG_TC) {
        // Only a TCP answer reaches here; UDP truncation was already retried.
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS response is truncated";
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
    // sname walks the CNAME chain from QNAME (RFC 1034 §5.3.3); the echoed
    // question already matched the query case-insensitively.
    std::array<WireName, kMaxCnameChain + 1> chain;
    size_t chain_size = 1;
    if (!ReadWireName(response, pos, chain[0]) || pos + 4 > response.size()) {
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

    const uint16_t ancount = common::LoadU16BE(response.data() + 6);
    const uint16_t nscount = common::LoadU16BE(response.data() + 8);
    if (ancount > (response.size() - pos) / 11) {
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS answer count exceeds packet";
        return result;
    }
    std::vector<net::ip::address> addresses;
    addresses.reserve(std::min<size_t>(ancount, kMaxAnswerAddresses));
    uint32_t chain_ttl = UINT32_MAX;
    uint32_t address_ttl = UINT32_MAX;
    WireName owner;
    WireName target;

    // RFC 1034 sets no order between RRsets: an address may precede the CNAME
    // that reaches its owner, and chain CNAMEs may appear out of order. Rescan
    // only when a pass extended the chain yet found no address at its end;
    // each rescan needs a new hop, so kMaxCnameChain bounds the passes and the
    // usual in-order answer stays a single pass.
    const size_t answers_begin = pos;
    for (;;) {
        pos = answers_begin;
        const size_t chain_before = chain_size;
        for (uint16_t i = 0; i < ancount; ++i) {
            if (!ReadWireName(response, pos, owner) || pos + 10 > response.size()) {
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
            const uint32_t ttl = WireTtl(response.data() + pos + 4);
            const uint16_t rdlength = common::LoadU16BE(response.data() + pos + 8);

            pos += 10;
            if (pos + rdlength > response.size()) {
                result.error = common::ErrorCode::DNS_FORMAT_ERROR;
                result.error_msg = "DNS answer data truncated";
                return result;
            }
            const size_t rdata_end = pos + rdlength;

            if ((type == TYPE_A && rdlength != 4) ||
                (type == TYPE_AAAA && rdlength != 16)) {
                result.error = common::ErrorCode::DNS_FORMAT_ERROR;
                result.error_msg = std::format("DNS {} record has invalid RDLENGTH {} (expected {})",
                    type == TYPE_A ? "A" : "AAAA", rdlength,
                    type == TYPE_A ? 4 : 16);
                return result;
            }

            // RFC 2181 §5.4.1: only records on the chain from QNAME answer the
            // question; anything else in the section is ignored, not trusted.
            const WireName& sname = chain[chain_size - 1];
            if (owner == sname && type == TYPE_CNAME) {
                size_t target_pos = pos;
                if (!ReadWireName(response, target_pos, target) || target_pos != rdata_end) {
                    result.error = common::ErrorCode::DNS_FORMAT_ERROR;
                    result.error_msg = "DNS CNAME target malformed";
                    return result;
                }
                const auto chain_end = chain.begin() + chain_size;
                if (std::find(chain.begin(), chain_end, target) != chain_end) {
                    result.error = common::ErrorCode::DNS_SERVER_FAILED;
                    result.error_msg = "DNS CNAME chain loops";
                    return result;
                }
                if (chain_size == chain.size()) {
                    result.error = common::ErrorCode::DNS_SERVER_FAILED;
                    result.error_msg = "DNS CNAME chain too long";
                    return result;
                }
                chain[chain_size++] = target;
                chain_ttl = std::min(chain_ttl, ttl);
                // An alias owns no other data (RFC 1034 §3.6.2); drop any
                // addresses that preceded its CNAME.
                addresses.clear();
                address_ttl = UINT32_MAX;
            } else if (owner == sname && type == (query_aaaa ? TYPE_AAAA : TYPE_A)) {
                // Records past the budget still bound the TTL.
                address_ttl = std::min(address_ttl, ttl);
                if (addresses.size() < kMaxAnswerAddresses) {
                    if (query_aaaa) {
                        net::ip::address_v6::bytes_type bytes;
                        std::memcpy(bytes.data(), &response[pos], 16);
                        addresses.emplace_back(net::ip::address_v6(bytes));
                    } else {
                        net::ip::address_v4::bytes_type bytes;
                        std::memcpy(bytes.data(), &response[pos], 4);
                        addresses.emplace_back(net::ip::address_v4(bytes));
                    }
                }
            }
            pos = rdata_end;
        }
        if (!addresses.empty() || chain_size == chain_before) break;
    }

    if (rcode != RCODE_NAME_ERROR && !addresses.empty()) {
        result.addresses = std::move(addresses);
        result.ttl = std::min(chain_ttl, address_ttl);
        return result;
    }

    // Negative answer for the end of the chain (RFC 2308 §2). Its cache TTL is
    // min(SOA TTL, SOA MINIMUM) from the authority section (§5), also bounded
    // by the chain; without a SOA it is not cached (TTL 0).
    if (nscount > (response.size() - pos) / 11) {
        result.error = common::ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS authority count exceeds packet";
        return result;
    }
    const WireName& sname = chain[chain_size - 1];
    std::optional<uint32_t> negative_ttl;
    for (uint16_t i = 0; i < nscount; ++i) {
        if (!ReadWireName(response, pos, owner) || pos + 10 > response.size()) {
            result.error = common::ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS authority header truncated";
            return result;
        }
        const uint16_t type = common::LoadU16BE(response.data() + pos);
        const uint16_t rr_class = common::LoadU16BE(response.data() + pos + 2);
        const uint32_t ttl = WireTtl(response.data() + pos + 4);
        const uint16_t rdlength = common::LoadU16BE(response.data() + pos + 8);
        pos += 10;
        if (pos + rdlength > response.size()) {
            result.error = common::ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS authority data truncated";
            return result;
        }
        const size_t rdata_end = pos + rdlength;
        // The SOA of the zone holding sname: its owner is sname or an ancestor.
        if (!negative_ttl && type == TYPE_SOA && rr_class == 1 && IsSameOrAncestor(owner, sname)) {
            size_t fields = pos;
            if (!UpstreamExchange::SkipWireName(response, fields) ||
                !UpstreamExchange::SkipWireName(response, fields) ||
                fields + 20 != rdata_end) {
                result.error = common::ErrorCode::DNS_FORMAT_ERROR;
                result.error_msg = "DNS SOA record malformed";
                return result;
            }
            negative_ttl = std::min({ttl, WireTtl(response.data() + rdata_end - 4), chain_ttl});
        }
        pos = rdata_end;
    }

    result.error = common::ErrorCode::DNS_NO_RECORD;
    result.error_msg = rcode == RCODE_NAME_ERROR ? "NXDOMAIN" : "NODATA";
    result.ttl = negative_ttl.value_or(0);
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
