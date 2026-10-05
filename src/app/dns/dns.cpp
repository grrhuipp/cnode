#include "cache_internal.hpp"
#include "acppnode/app/dns/dns_service.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"
#include "datagram_exchange.hpp"
#include "../../common/awaitable_task_group.hpp"
#include "inflight_resolves.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/experimental/channel_error.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/strand.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <format>
#include <optional>
#include <stdexcept>
#include <span>
#include <variant>

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

struct DNSService::Impl {
    using SignalChannel =
        net::experimental::concurrent_channel<void(std::exception_ptr)>;

    template <typename T>
    struct Completion {
        explicit Completion(net::any_io_executor executor)
            : result(executor, 1), cancel(std::move(executor), 1) {}

        net::experimental::concurrent_channel<void(std::exception_ptr, T)> result;
        SignalChannel cancel;
    };

    using PermitChannel = SignalChannel;

    class Admission {
    public:
        Admission() noexcept = default;
        explicit Admission(PermitChannel& permits) noexcept : permits_(&permits) {}
        Admission(Admission&& other) noexcept
            : permits_(std::exchange(other.permits_, nullptr)) {}
        Admission& operator=(Admission&& other) noexcept {
            if (this != &other) {
                Release();
                permits_ = std::exchange(other.permits_, nullptr);
            }
            return *this;
        }
        ~Admission() { Release(); }

        Admission(const Admission&) = delete;
        Admission& operator=(const Admission&) = delete;
        explicit operator bool() const noexcept { return permits_ != nullptr; }

    private:
        void Release() noexcept {
            if (!permits_) return;
            try {
                (void)permits_->try_send(std::exception_ptr{});
            } catch (...) {
                // The channel owns preallocated capacity; returning a token is
                // not expected to allocate. Destruction must remain noexcept.
            }
            permits_ = nullptr;
        }

        PermitChannel* permits_ = nullptr;
    };

    struct ResolveRequest {
        Admission admission;
        std::string domain;
        std::shared_ptr<Completion<DnsResult>> completion;
    };
    struct StatsRequest {
        Admission admission;
        std::shared_ptr<Completion<DnsCacheStats>> completion;
    };
    struct CloseRequest {
        std::shared_ptr<SignalChannel> completion;
    };
    using Request = std::variant<
        std::shared_ptr<ResolveRequest>,
        std::shared_ptr<StatsRequest>,
        CloseRequest>;
    using RequestChannel =
        net::experimental::concurrent_channel<void(std::exception_ptr, Request)>;

    Impl(net::any_io_executor executor, const Config& config, size_t request_capacity);

    net::awaitable<void> RunOwned();
    net::awaitable<void> ReceiveRequests(AwaitableTaskGroup& tasks);
    net::awaitable<void> ProcessResolve(std::shared_ptr<ResolveRequest> request);
    net::awaitable<void> ResolveForRequest(
        std::shared_ptr<ResolveRequest> request, std::optional<DnsResult>& result,
        std::exception_ptr& failure, bool& operation_finished);
    net::awaitable<void> WatchRequestCancellation(
        std::shared_ptr<Completion<DnsResult>> completion,
        bool& operation_finished, bool& caller_cancelled, AwaitableTaskGroup& tasks);
    net::awaitable<void> ProcessStats(std::shared_ptr<StatsRequest> request);
    net::awaitable<DnsResult> SubmitResolve(std::string domain);
    net::awaitable<DnsCacheStats> SubmitStats();
    net::awaitable<void> SubmitClose();

    net::awaitable<DnsResult> ResolveOwned(std::string domain);

    net::awaitable<DnsResult> ResolveUncached(std::string_view domain);
    net::awaitable<DnsResult> DoResolve(std::string_view domain);
    net::awaitable<DnsResult> QueryServer(
        DatagramExchange& server,
        std::string_view domain,
        bool query_aaaa);
    void BuildQueryTo(memory::ByteVector& query,
                      std::string_view domain,
                      uint16_t txid,
                      bool query_aaaa);
    DnsResult ParseResponse(std::span<const uint8_t> response, uint16_t expected_txid);

    [[nodiscard]] Admission TryAcquire();
    void Reject(Request request, ErrorCode error);
    net::awaitable<void> CloseUpstreams();

    net::any_io_executor executor;
    const Config config;
    DnsCache cache;
    InflightResolves inflight_resolves;
    std::vector<std::shared_ptr<DatagramExchange>> upstreams;
    PermitChannel permits;
    RequestChannel requests;
    std::shared_ptr<SignalChannel> close_completion;
    bool running = false;
    bool stopping = false;
};

DNSService::Impl::Impl(net::any_io_executor executor, const Config& config,
                       size_t request_capacity)
    : executor(net::make_strand(std::move(executor)))
    , config(config)
    , cache(config.cache_size, config.min_ttl, config.max_ttl)
    , inflight_resolves(this->executor)
    , permits(this->executor, std::max<size_t>(request_capacity, 1))
    , requests(this->executor, std::max<size_t>(request_capacity, 1) + 1) {
    if (config.servers.empty()) {
        throw std::invalid_argument("DNS requires at least one server endpoint");
    }
    for (const auto& server : config.servers) {
        if (server.port() == 0) throw std::invalid_argument("DNS server port must be positive");
    }
    upstreams.reserve(config.servers.size());
    for (const auto& server : config.servers) {
        upstreams.push_back(std::make_shared<DatagramExchange>(this->executor, server));
    }
    for (size_t i = 0; i < permits.capacity(); ++i) {
        if (!permits.try_send(std::exception_ptr{})) {
            throw std::logic_error("DNS admission channel initialization failed");
        }
    }
}

net::awaitable<DnsResult> DNSService::Impl::ResolveOwned(std::string owned_domain) {
    // The only lookup entry owns input throughout cache/inflight/upstream I/O.
    if (stopping) { DnsResult cancelled; cancelled.error = ErrorCode::CANCELLED; co_return cancelled; }
    std::string_view domain = owned_domain;
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

    memory::DataString canonical(domain);
    if (canonical.back() == '.') canonical.pop_back();
    for (char& c : canonical) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    domain = canonical;
    if (auto cached = cache.Get(domain)) {
        co_return MakeCachedResult(*cached);
    }

    co_return co_await inflight_resolves.Run(domain, [this, domain] {
        return ResolveUncached(domain);
    });
}

net::awaitable<DnsResult> DNSService::Impl::ResolveUncached(std::string_view domain) {
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
    co_return result;
}

net::awaitable<DnsResult> DNSService::Impl::DoResolve(
    std::string_view domain) {
    DnsResult last_result;
    last_result.error = ErrorCode::DNS_RESOLVE_FAILED;
    last_result.error_msg = "DNS server unavailable";

    for (const auto& server : upstreams) {
        // Preserve three A samples (round-robin answer collection), but do not
        // serialize their RTTs or hold AAAA behind them. Join all children before
        // returning or moving to another upstream, including cancellation/OOM.
        std::array<DnsResult, kAddressQueryAttempts + 1> answers;
        auto collect = [&](size_t index) -> net::awaitable<void> {
            answers[index] = co_await QueryServer(*server, domain, index == kAddressQueryAttempts);
        };
        co_await RunAwaitableTaskGroup(executor, [&](AwaitableTaskGroup& group) {
            for (size_t i = 0; i < answers.size(); ++i) group.Spawn(collect(i));
        });
        DnsResult a_result;
        a_result.error = ErrorCode::DNS_RESOLVE_FAILED;
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
            if (!a_result.Ok()) {
                a_result = std::move(attempt_result);
            }
        }

        auto aaaa_result = std::move(answers.back());

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

net::awaitable<DnsResult> DNSService::Impl::QueryServer(
    DatagramExchange& server,
    std::string_view domain,
    bool query_aaaa) {
    DnsResult result;
    memory::ByteVector query;
    BuildQueryTo(query, domain, 0, query_aaaa);
    auto response = co_await server.Exchange(query, std::chrono::seconds(config.timeout_sec));
    if (response.error) {
        result.error = response.error == io_error::timed_out ? ErrorCode::DNS_TIMEOUT :
            response.error == io_error::operation_aborted ? ErrorCode::CANCELLED :
            response.error == io_error::no_buffer_space ? ErrorCode::RESOURCE_EXHAUSTED :
            ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = response.error.message();
        co_return result;
    }
    const uint16_t txid = (query[0] << 8) | query[1];
    co_return ParseResponse(std::span<const uint8_t>(response.bytes.data(), response.size), txid);
}

void DNSService::Impl::BuildQueryTo(
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

DnsResult DNSService::Impl::ParseResponse(
    std::span<const uint8_t> response, uint16_t expected_txid) {
    DnsResult result;

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
    if (!(flags & wire::FLAG_QR) || (flags & 0x0200)) {
        result.error = ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS packet is not a complete response";
        return result;
    }

    const uint8_t rcode = flags & wire::FLAG_RCODE;
    if (rcode == wire::RCODE_NAME_ERROR) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NXDOMAIN";
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

    if (ancount > (response.size() - pos) / 11) {
        result.error = ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS answer count exceeds packet";
        return result;
    }
    std::vector<net::ip::address> addresses;
    addresses.reserve(ancount);
    uint32_t min_ttl = UINT32_MAX;

    for (uint16_t i = 0; i < ancount; ++i) {
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
        if (response[pos + 2] != 0 || response[pos + 3] != 1) {
            result.error = ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS answer class is not IN";
            return result;
        }
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
        return result;
    }

    result.addresses = std::move(addresses);
    result.ttl = (min_ttl == UINT32_MAX) ? 60 : min_ttl;
    return result;
}

DNSService::Impl::Admission DNSService::Impl::TryAcquire() {
    Admission admission;
    (void)permits.try_receive([&](std::exception_ptr failure) {
        if (!failure) admission = Admission(permits);
    });
    return admission;
}

void DNSService::Impl::Reject(Request request, ErrorCode error) {
    if (auto* resolve = std::get_if<std::shared_ptr<ResolveRequest>>(&request)) {
        DnsResult result;
        result.error = error;
        (*resolve)->completion->cancel.close();
        (void)(*resolve)->completion->result.try_send(
            std::exception_ptr{}, std::move(result));
        return;
    }
    if (auto* stats = std::get_if<std::shared_ptr<StatsRequest>>(&request)) {
        (*stats)->completion->cancel.close();
        (void)(*stats)->completion->result.try_send(
            std::make_exception_ptr(DNSServiceError(error)), DnsCacheStats{});
        return;
    }
    auto& close = std::get<CloseRequest>(request);
    (void)close.completion->try_send(
        std::make_exception_ptr(DNSServiceError(error)));
}

net::awaitable<void> DNSService::Impl::ResolveForRequest(
    std::shared_ptr<ResolveRequest> request, std::optional<DnsResult>& result,
    std::exception_ptr& failure, bool& operation_finished) {
    try {
        result.emplace(co_await ResolveOwned(std::move(request->domain)));
    } catch (...) {
        failure = std::current_exception();
    }
    operation_finished = true;
    request->completion->cancel.close();
}

net::awaitable<void> DNSService::Impl::WatchRequestCancellation(
    std::shared_ptr<Completion<DnsResult>> completion,
    bool& operation_finished, bool& caller_cancelled, AwaitableTaskGroup& tasks) {
    auto [cancel_failure] = co_await completion->cancel.async_receive(
        net::as_tuple(net::use_awaitable));
    if (!cancel_failure && !operation_finished) {
        caller_cancelled = true;
        tasks.Cancel();
    }
}

net::awaitable<void> DNSService::Impl::ProcessResolve(
    std::shared_ptr<ResolveRequest> request) {
    std::optional<DnsResult> result;
    std::exception_ptr failure;
    bool operation_finished = false;
    bool caller_cancelled = false;

    try {
        co_await RunAwaitableTaskGroup(
            executor,
            [&](AwaitableTaskGroup& tasks) {
                tasks.Spawn(ResolveForRequest(
                    request, result, failure, operation_finished));
                tasks.Spawn(WatchRequestCancellation(
                    request->completion, operation_finished, caller_cancelled, tasks));
            });
    } catch (...) {
        if (!failure) failure = std::current_exception();
    }

    request->completion->cancel.close();
    if (caller_cancelled) {
        failure = {};
        DnsResult cancelled;
        cancelled.error = ErrorCode::CANCELLED;
        result.emplace(std::move(cancelled));
    } else if (!result && !failure) {
        failure = std::make_exception_ptr(
            std::runtime_error("DNS request finished without a result"));
    }

    if (failure) {
        (void)request->completion->result.try_send(
            std::move(failure), DnsResult{});
    } else {
        (void)request->completion->result.try_send(
            std::exception_ptr{}, std::move(*result));
    }
}

net::awaitable<void> DNSService::Impl::ProcessStats(
    std::shared_ptr<StatsRequest> request) {
    bool cancelled = false;
    (void)request->completion->cancel.try_receive(
        [&](std::exception_ptr failure) { cancelled = !failure; });
    request->completion->cancel.close();
    if (cancelled) {
        (void)request->completion->result.try_send(
            std::make_exception_ptr(DNSServiceError(ErrorCode::CANCELLED)),
            DnsCacheStats{});
    } else {
        (void)request->completion->result.try_send(
            std::exception_ptr{}, cache.GetStats());
    }
    co_return;
}

net::awaitable<void> DNSService::Impl::CloseUpstreams() {
    for (const auto& server : upstreams) co_await server->Close();
}

net::awaitable<void> DNSService::Impl::ReceiveRequests(
    AwaitableTaskGroup& tasks) {
    for (;;) {
        Request request;
        try {
            request = co_await requests.async_receive(net::use_awaitable);
        } catch (const IoSystemError& error) {
            if (error.code() == net::experimental::error::channel_closed) break;
            throw;
        }

        if (auto* close = std::get_if<CloseRequest>(&request)) {
            stopping = true;
            close_completion = std::move(close->completion);
            co_await CloseUpstreams();
            continue;
        }
        if (stopping) {
            Reject(std::move(request), ErrorCode::CANCELLED);
            continue;
        }

        try {
            if (auto* resolve =
                    std::get_if<std::shared_ptr<ResolveRequest>>(&request)) {
                tasks.Spawn(ProcessResolve(*resolve));
            } else {
                tasks.Spawn(ProcessStats(
                    std::get<std::shared_ptr<StatsRequest>>(request)));
            }
        } catch (...) {
            if (auto* resolve =
                    std::get_if<std::shared_ptr<ResolveRequest>>(&request)) {
                (*resolve)->completion->cancel.close();
                (void)(*resolve)->completion->result.try_send(
                    std::current_exception(), DnsResult{});
            } else {
                auto stats = std::get<std::shared_ptr<StatsRequest>>(request);
                stats->completion->cancel.close();
                (void)stats->completion->result.try_send(
                    std::current_exception(), DnsCacheStats{});
            }
        }
    }
}

net::awaitable<void> DNSService::Impl::RunOwned() {
    if (running || stopping) {
        throw std::logic_error("DNS service may only run once");
    }
    running = true;
    std::exception_ptr failure;
    try {
        co_await RunAwaitableTaskGroup(
            executor,
            [&](AwaitableTaskGroup& tasks) {
                tasks.Spawn(ReceiveRequests(tasks));
            });
    } catch (...) {
        failure = std::current_exception();
    }

    const bool previous = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    stopping = true;
    requests.close();
    try {
        co_await CloseUpstreams();
    } catch (...) {
        if (!failure) failure = std::current_exception();
    }

    while (requests.try_receive(
        [&](std::exception_ptr receive_failure, Request request) {
            if (receive_failure) {
                if (!failure) failure = std::move(receive_failure);
                return;
            }
            if (auto* close = std::get_if<CloseRequest>(&request)) {
                close_completion = std::move(close->completion);
            } else {
                Reject(std::move(request), ErrorCode::CANCELLED);
            }
        })) {}
    upstreams.clear();
    running = false;
    if (close_completion) {
        (void)close_completion->try_send(failure);
    }
    co_await net::this_coro::throw_if_cancelled(previous);
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<DnsResult> DNSService::Impl::SubmitResolve(std::string domain) {
    auto admission = TryAcquire();
    if (!admission) {
        DnsResult rejected;
        rejected.error = requests.is_open()
            ? ErrorCode::RESOURCE_EXHAUSTED
            : ErrorCode::CANCELLED;
        co_return rejected;
    }

    const auto caller = co_await net::this_coro::executor;
    auto completion = std::make_shared<Completion<DnsResult>>(caller);
    auto request = std::make_shared<ResolveRequest>(ResolveRequest{
        std::move(admission), std::move(domain), completion});
    if (!requests.try_send(std::exception_ptr{}, Request{std::move(request)})) {
        DnsResult cancelled;
        cancelled.error = ErrorCode::CANCELLED;
        co_return cancelled;
    }

    std::exception_ptr failure;
    std::optional<DnsResult> result;
    bool received = false;
    try {
        auto [receive_failure, value] = co_await completion->result.async_receive(
            net::as_tuple(net::use_awaitable));
        received = true;
        failure = std::move(receive_failure);
        if (!failure) result.emplace(std::move(value));
    } catch (...) {
        failure = std::current_exception();
    }
    if (received) {
        if (failure) std::rethrow_exception(failure);
        co_return std::move(*result);
    }

    (void)completion->cancel.try_send(std::exception_ptr{});
    const bool previous = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    try {
        (void)co_await completion->result.async_receive(
            net::as_tuple(net::use_awaitable));
    } catch (...) {
        // The original receive failure takes precedence; consume completion/rejection.
    }
    co_await net::this_coro::throw_if_cancelled(previous);
    std::rethrow_exception(failure);
}

net::awaitable<DnsCacheStats> DNSService::Impl::SubmitStats() {
    auto admission = TryAcquire();
    if (!admission) {
        throw DNSServiceError(
            requests.is_open() ? ErrorCode::RESOURCE_EXHAUSTED
                               : ErrorCode::CANCELLED);
    }

    const auto caller = co_await net::this_coro::executor;
    auto completion = std::make_shared<Completion<DnsCacheStats>>(caller);
    auto request = std::make_shared<StatsRequest>(StatsRequest{
        std::move(admission), completion});
    if (!requests.try_send(std::exception_ptr{}, Request{std::move(request)})) {
        throw DNSServiceError(ErrorCode::CANCELLED);
    }

    std::exception_ptr failure;
    std::optional<DnsCacheStats> result;
    bool received = false;
    try {
        auto [receive_failure, value] = co_await completion->result.async_receive(
            net::as_tuple(net::use_awaitable));
        received = true;
        failure = std::move(receive_failure);
        if (!failure) result.emplace(std::move(value));
    } catch (...) {
        failure = std::current_exception();
    }
    if (received) {
        if (failure) std::rethrow_exception(failure);
        co_return std::move(*result);
    }

    (void)completion->cancel.try_send(std::exception_ptr{});
    const bool previous = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    try {
        (void)co_await completion->result.async_receive(
            net::as_tuple(net::use_awaitable));
    } catch (...) {
        // The original receive failure takes precedence; consume completion/rejection.
    }
    co_await net::this_coro::throw_if_cancelled(previous);
    std::rethrow_exception(failure);
}

net::awaitable<void> DNSService::Impl::SubmitClose() {
    const auto caller = co_await net::this_coro::executor;
    auto completion = std::make_shared<SignalChannel>(caller, 1);
    bool sent = false;
    try {
        sent = requests.try_send(
            std::exception_ptr{}, Request{CloseRequest{completion}});
    } catch (...) {
        requests.close();
        throw;
    }
    requests.close();
    if (!sent) co_return;
    co_await completion->async_receive(
        net::bind_cancellation_slot(
            net::cancellation_slot{}, net::use_awaitable));
}

DNSService::DNSService(net::any_io_executor base_executor,
                       const Config& config, size_t request_capacity)
    : impl_(std::make_unique<Impl>(
          std::move(base_executor), config, request_capacity)) {}

DNSService::~DNSService() = default;

net::awaitable<void> DNSService::Run() {
    co_await net::co_spawn(
        impl_->executor, impl_->RunOwned(), net::use_awaitable);
}

net::awaitable<DnsResult> DNSService::Resolve(std::string domain) {
    return impl_->SubmitResolve(std::move(domain));
}

net::awaitable<DnsCacheStats> DNSService::GetCacheStats() {
    return impl_->SubmitStats();
}

net::awaitable<void> DNSService::Close() {
    return impl_->SubmitClose();
}

net::awaitable<DnsResult> DNS::Resolve(std::string_view domain) {
    // Capture the caller's view now, before the bounded channel hands the
    // owned request to the DNS service strand. The client has no live DNS state.
    return service_.Resolve(std::string(domain));
}

}  // namespace acpp::app::dns
