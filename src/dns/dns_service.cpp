#include "acppnode/dns/dns_service.hpp"
#include "acppnode/infra/log.hpp"

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/cobalt.hpp>
#include <random>
#include <cstring>
#include <format>

namespace acpp {

// ============================================================================
// DNS 报文格式常量
// ============================================================================
namespace dns {

constexpr uint16_t FLAG_QR    = 0x8000;  // Query/Response
constexpr uint16_t FLAG_RCODE = 0x000F;  // Response Code

constexpr uint16_t TYPE_A    = 1;
constexpr uint16_t TYPE_AAAA = 28;

constexpr uint8_t RCODE_OK         = 0;
constexpr uint8_t RCODE_NAME_ERROR = 3;  // NXDOMAIN

}  // namespace dns

namespace {

std::string MakeSharedStateKey(const DnsService::Config& config) {
    std::string key = std::to_string(config.cache_size)
        + "|" + std::to_string(config.timeout_sec)
        + "|" + std::to_string(config.min_ttl)
        + "|" + std::to_string(config.max_ttl);
    for (const auto& server : config.servers) {
        key += "|" + server;
    }
    return key;
}

cobalt::task<void> PrefetchDomain(DnsService* service, std::string domain) {
    try {
        auto result = co_await service->Resolve(domain, false);
        if (result.Ok()) {
            LOG_DEBUG("DNS prefetch: {} -> {} (ttl={}s)",
                      domain,
                      result.addresses[0].to_string(),
                      result.ttl);
        } else {
            LOG_DEBUG("DNS prefetch failed: {} - {}",
                      domain, result.error_msg);
        }
    } catch (const std::exception& e) {
        LOG_DEBUG("DNS prefetch exception: {} - {}", domain, e.what());
    }
}

}  // namespace

// ============================================================================
// DnsService 实现
// ============================================================================

struct DnsService::InflightResolve {
    struct Waiter {
        net::any_io_executor executor;
        std::shared_ptr<net::steady_timer> timer;
    };

    std::mutex lock;
    DnsResult result;
    bool completed = false;
    std::vector<Waiter> waiters;
};

struct DnsService::SharedState {
    explicit SharedState(const Config& config)
        : cache(std::make_shared<DnsCache>(
            config.cache_size, config.min_ttl, config.max_ttl)) {}

    std::shared_ptr<DnsCache> cache;
    std::mutex inflight_lock;
    std::unordered_map<ResolveKey, std::shared_ptr<InflightResolve>, ResolveKeyHash>
        inflight_resolves;
};

std::shared_ptr<DnsService::SharedState> DnsService::AcquireSharedState(
    const Config& config) {
    static std::mutex shared_state_mu;
    static std::unordered_map<std::string, std::weak_ptr<SharedState>> shared_states;

    const std::string key = MakeSharedStateKey(config);

    std::lock_guard lock(shared_state_mu);
    if (auto it = shared_states.find(key); it != shared_states.end()) {
        if (auto shared_state = it->second.lock()) {
            return shared_state;
        }
    }

    auto shared_state = std::make_shared<SharedState>(config);
    shared_states[key] = shared_state;
    return shared_state;
}

DnsService::DnsService(net::any_io_executor executor, const Config& config)
    : executor_(executor), config_(config) {
    
    // 初始化缓存
    shared_state_ = AcquireSharedState(config);
    cache_ = shared_state_->cache;
    
    // 解析服务器地址
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
        // 添加默认服务器
        servers_.emplace_back(net::ip::make_address("8.8.8.8"), 53);
    }
    
    // 随机初始化 txid
    std::random_device rd;
    txid_counter_ = static_cast<uint16_t>(rd() & 0xFFFF);
}

DnsService::~DnsService() = default;

cobalt::task<DnsResult> DnsService::Resolve(
    const std::string& domain, bool prefer_ipv6) {
    
    // 先尝试解析为 IP（不需要 DNS）
    boost::system::error_code ec;
    auto addr = net::ip::make_address(domain, ec);
    if (!ec) {
        DnsResult result;
        result.addresses.push_back(addr);
        result.from_cache = false;
        co_return result;
    }
    
    // 查询缓存
    auto cached = cache_->Get(domain, prefer_ipv6);
    if (cached) {
        DnsResult result;
        if (cached->negative) {
            result.error = ErrorCode::DNS_NO_RECORD;
            result.error_msg = "NXDOMAIN (cached)";
        } else {
            result.addresses = cached->addresses;
            result.ttl = cached->ttl;
        }
        result.from_cache = true;
        co_return result;
    }

    ResolveKey key{domain, prefer_ipv6};
    std::shared_ptr<InflightResolve> inflight;
    bool is_leader = false;
    {
        std::lock_guard lock(shared_state_->inflight_lock);
        auto it = shared_state_->inflight_resolves.find(key);
        if (it == shared_state_->inflight_resolves.end()) {
            inflight = std::make_shared<InflightResolve>();
            shared_state_->inflight_resolves.emplace(key, inflight);
            is_leader = true;
        } else {
            inflight = it->second;
        }
    }

    if (!is_leader) {
        auto wait_timer = std::make_shared<net::steady_timer>(executor_);
        wait_timer->expires_at(net::steady_timer::time_point::max());

        {
            std::lock_guard lock(inflight->lock);
            if (inflight->completed) {
                co_return inflight->result;
            }
            inflight->waiters.push_back({executor_, wait_timer});
        }

        auto [wait_ec] = co_await wait_timer->async_wait(
            net::as_tuple(cobalt::use_op));
        (void)wait_ec;

        std::lock_guard lock(inflight->lock);
        co_return inflight->result;
    }

    DnsResult result;
    try {
        result = co_await DoResolve(domain, prefer_ipv6);
    } catch (const std::exception& e) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = e.what();
    } catch (...) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = "DNS resolve exception";
    }

    // 缓存结果（使用实际 TTL）
    if (result.Ok()) {
        cache_->Put(domain, result.addresses, result.ttl, prefer_ipv6);
    } else if (result.error == ErrorCode::DNS_NO_RECORD) {
        cache_->PutNegative(domain, 60, prefer_ipv6);
    }

    std::vector<InflightResolve::Waiter> waiters;
    {
        std::lock_guard lock(inflight->lock);
        inflight->completed = true;
        inflight->result = result;
        waiters = std::move(inflight->waiters);
    }

    for (auto& waiter : waiters) {
        net::post(waiter.executor, [timer = std::move(waiter.timer)]() mutable {
            timer->expires_at(net::steady_timer::clock_type::now());
        });
    }

    {
        std::lock_guard lock(shared_state_->inflight_lock);
        auto it = shared_state_->inflight_resolves.find(key);
        if (it != shared_state_->inflight_resolves.end() && it->second == inflight) {
            shared_state_->inflight_resolves.erase(it);
        }
    }

    co_return result;
}

cobalt::task<DnsResult> DnsService::DoResolve(
    const std::string& domain, bool prefer_ipv6) {
    
    // 遍历服务器尝试
    for (const auto& server : servers_) {
        DnsResult result;

        auto query_a = [this, server, domain]() -> cobalt::task<DnsResult> {
            co_return co_await QueryServer(server, domain, false);
        };

        auto query_aaaa = [this, server, domain]() -> cobalt::task<DnsResult> {
            co_return co_await QueryServer(server, domain, true);
        };

        // 默认同时查询 A 和 AAAA，行为对齐 sing-box：
        // - prefer_ipv6 = true  => AAAA 在前，A 在后
        // - prefer_ipv6 = false => A 在前，AAAA 在后
        // 同家族内保持 DNS 返回顺序，后续由拨号器决定如何尝试。
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
        auto [raw_a, raw_aaaa] = co_await cobalt::gather(query_a(), query_aaaa());
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

        // cobalt::gather 返回 result<T> 包装，需要解包
        DnsResult result_a = raw_a.has_value()
            ? std::move(*raw_a)
            : DnsResult{{}, ErrorCode::DNS_TIMEOUT, "gather exception"};
        DnsResult result_aaaa = raw_aaaa.has_value()
            ? std::move(*raw_aaaa)
            : DnsResult{{}, ErrorCode::DNS_TIMEOUT, "gather exception"};

        if (result_a.Ok() && result_aaaa.Ok()) {
            if (prefer_ipv6) {
                result = std::move(result_aaaa);
                result.addresses.insert(result.addresses.end(),
                    result_a.addresses.begin(),
                    result_a.addresses.end());
            } else {
                result = std::move(result_a);
                result.addresses.insert(result.addresses.end(),
                    result_aaaa.addresses.begin(),
                    result_aaaa.addresses.end());
            }
            co_return result;
        }

        if (prefer_ipv6) {
            if (result_aaaa.Ok()) {
                co_return result_aaaa;
            }
            if (result_a.Ok()) {
                co_return result_a;
            }
        } else {
            if (result_a.Ok()) {
                co_return result_a;
            }
            if (result_aaaa.Ok()) {
                co_return result_aaaa;
            }
        }

        // 只有 A/AAAA 都明确无记录时，才认为该服务器给出了确定的 no record。
        if (result_a.error == ErrorCode::DNS_NO_RECORD &&
            result_aaaa.error == ErrorCode::DNS_NO_RECORD) {
            result = prefer_ipv6 ? std::move(result_aaaa) : std::move(result_a);
            co_return result;
        }

        // 否则保留“首选族”的错误，继续尝试下一个 DNS 服务器。
        if (prefer_ipv6) {
            result = (result_aaaa.error != ErrorCode::DNS_NO_RECORD)
                ? std::move(result_aaaa)
                : std::move(result_a);
        } else {
            result = (result_a.error != ErrorCode::DNS_NO_RECORD)
                ? std::move(result_a)
                : std::move(result_aaaa);
        }
    }
    
    // 所有服务器都失败
    DnsResult result;
    result.error = ErrorCode::DNS_RESOLVE_FAILED;
    result.error_msg = "All DNS servers failed";
    co_return result;
}

cobalt::task<DnsResult> DnsService::QueryServer(
    const net::ip::udp::endpoint& server,
    const std::string& domain,
    bool query_aaaa) {
    
    DnsResult result;
    
    // 生成事务 ID
    uint16_t txid = txid_counter_.fetch_add(1, std::memory_order_relaxed);
    
    // 构建查询报文
    auto query = BuildQuery(domain, txid, query_aaaa);
    
    // 创建 UDP socket
    udp::socket socket(executor_);
    
    boost::system::error_code ec;
    socket.open(server.protocol(), ec);
    if (ec) {
        result.error = ErrorCode::SOCKET_CREATE_FAILED;
        result.error_msg = ec.message();
        co_return result;
    }
    
    // 发送查询
    co_await socket.async_send_to(
        net::buffer(query), server, cobalt::use_op);
    
    // 等待响应（带超时）- 使用定时器回调，避免 parallel_group
    std::vector<uint8_t> response(512);
    net::steady_timer timer(executor_);
    struct QueryTimeoutState {
        std::atomic<bool> timed_out{false};
        std::atomic<bool> active{true};
    };
    auto timeout_state = std::make_shared<QueryTimeoutState>();
    udp::socket* socket_ptr = &socket;
    
    timer.expires_after(std::chrono::seconds(config_.timeout_sec));
    timer.async_wait([timeout_state, socket_ptr](const boost::system::error_code& ec) {
        if (!ec && timeout_state->active.exchange(false, std::memory_order_acq_rel)) {
            timeout_state->timed_out.store(true, std::memory_order_release);
            boost::system::error_code close_ec;
            socket_ptr->close(close_ec);
        }
    });
    
    udp::endpoint sender;
    size_t received = 0;
    
    try {
        received = co_await socket.async_receive_from(
            net::buffer(response), sender, cobalt::use_op);
        timeout_state->active.store(false, std::memory_order_release);
        timer.cancel();
    } catch (const boost::system::system_error& e) {
        timeout_state->active.store(false, std::memory_order_release);
        timer.cancel();
        if (timeout_state->timed_out.load(std::memory_order_acquire)) {
            result.error = ErrorCode::DNS_TIMEOUT;
            result.error_msg = "DNS query timed out";
            co_return result;
        }
        ec = e.code();
    }
    
    if (ec) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = ec.message();
        co_return result;
    }
    
    response.resize(received);
    
    // 解析响应
    uint32_t ttl = config_.min_ttl;
    auto parsed = ParseResponse(response, txid, ttl);
    
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

std::vector<uint8_t> DnsService::BuildQuery(
    const std::string& domain, uint16_t txid, bool query_aaaa) {
    
    std::vector<uint8_t> query;
    query.reserve(64);
    
    // Header (12 bytes)
    // Transaction ID
    query.push_back(static_cast<uint8_t>(txid >> 8));
    query.push_back(static_cast<uint8_t>(txid & 0xFF));
    
    // Flags: Standard query, recursion desired
    query.push_back(0x01);  // RD = 1
    query.push_back(0x00);
    
    // QDCOUNT = 1
    query.push_back(0x00);
    query.push_back(0x01);
    
    // ANCOUNT = 0
    query.push_back(0x00);
    query.push_back(0x00);
    
    // NSCOUNT = 0
    query.push_back(0x00);
    query.push_back(0x00);
    
    // ARCOUNT = 0
    query.push_back(0x00);
    query.push_back(0x00);
    
    // Question section
    // Domain name in DNS format
    size_t pos = 0;
    while (pos < domain.size()) {
        size_t dot = domain.find('.', pos);
        if (dot == std::string::npos) {
            dot = domain.size();
        }
        
        size_t len = dot - pos;
        query.push_back(static_cast<uint8_t>(len));
        for (size_t i = pos; i < dot; ++i) {
            query.push_back(static_cast<uint8_t>(domain[i]));
        }
        
        pos = dot + 1;
    }
    query.push_back(0x00);  // 结束标记
    
    // QTYPE
    uint16_t qtype = query_aaaa ? dns::TYPE_AAAA : dns::TYPE_A;
    query.push_back(static_cast<uint8_t>(qtype >> 8));
    query.push_back(static_cast<uint8_t>(qtype & 0xFF));
    
    // QCLASS = IN
    query.push_back(0x00);
    query.push_back(0x01);
    
    return query;
}

DnsService::ParsedResponse DnsService::ParseResponse(
    const std::vector<uint8_t>& response, uint16_t expected_txid, uint32_t& out_ttl) {
    ParsedResponse result;

    if (response.size() < 12) {
        result.error = ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS response too short";
        return result;
    }
    
    // 检查事务 ID
    uint16_t txid = (static_cast<uint16_t>(response[0]) << 8) | response[1];
    if (txid != expected_txid) {
        result.error = ErrorCode::DNS_RESOLVE_FAILED;
        result.error_msg = "DNS transaction ID mismatch";
        return result;
    }
    
    // 检查 flags
    uint16_t flags = (static_cast<uint16_t>(response[2]) << 8) | response[3];
    if (!(flags & dns::FLAG_QR)) {
        result.error = ErrorCode::DNS_FORMAT_ERROR;
        result.error_msg = "DNS packet is not a response";
        return result;
    }
    
    uint8_t rcode = flags & dns::FLAG_RCODE;
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
                result.error_msg = std::format("DNS response error rcode={}", rcode);
                break;
        }
        return result;
    }
    
    // 解析 counts
    uint16_t qdcount = (static_cast<uint16_t>(response[4]) << 8) | response[5];
    uint16_t ancount = (static_cast<uint16_t>(response[6]) << 8) | response[7];
    
    if (ancount == 0) {
        result.error = ErrorCode::DNS_NO_RECORD;
        result.error_msg = "NODATA";
        result.negative_cacheable = true;
        return result;
    }
    
    // 跳过 Header (12 bytes)
    size_t pos = 12;
    
    // 跳过 Question section
    for (uint16_t i = 0; i < qdcount; ++i) {
        // 跳过域名
        while (pos < response.size()) {
            uint8_t len = response[pos];
            if (len == 0) {
                pos++;
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                // 压缩指针
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
        pos += 4;  // QTYPE + QCLASS
    }
    
    // 解析 Answer section
    std::vector<net::ip::address> addresses;
    uint32_t min_ttl = UINT32_MAX;
    
    for (uint16_t i = 0; i < ancount && pos < response.size(); ++i) {
        // 跳过域名
        while (pos < response.size()) {
            uint8_t len = response[pos];
            if (len == 0) {
                pos++;
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
        
        uint16_t type = (static_cast<uint16_t>(response[pos]) << 8) | response[pos + 1];
        // uint16_t cls = (static_cast<uint16_t>(response[pos + 2]) << 8) | response[pos + 3];
        uint32_t ttl = (static_cast<uint32_t>(response[pos + 4]) << 24) |
                       (static_cast<uint32_t>(response[pos + 5]) << 16) |
                       (static_cast<uint32_t>(response[pos + 6]) << 8) |
                       response[pos + 7];
        uint16_t rdlength = (static_cast<uint16_t>(response[pos + 8]) << 8) | response[pos + 9];
        
        pos += 10;
        
        if (pos + rdlength > response.size()) {
            result.error = ErrorCode::DNS_FORMAT_ERROR;
            result.error_msg = "DNS answer data truncated";
            return result;
        }
        
        min_ttl = std::min(min_ttl, ttl);
        
        if (type == dns::TYPE_A && rdlength == 4) {
            // IPv4
            net::ip::address_v4::bytes_type bytes;
            std::memcpy(bytes.data(), &response[pos], 4);
            addresses.emplace_back(net::ip::address_v4(bytes));
        } else if (type == dns::TYPE_AAAA && rdlength == 16) {
            // IPv6
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
        // 跳过空域名
        if (domain.empty()) {
            continue;
        }
        
        // 跳过已缓存的域名
        auto cached = cache_->Get(domain, false);
        if (cached) {
            continue;
        }
        
        // 并发发起解析，不等待结果
        cobalt::spawn(executor_,
            PrefetchDomain(this, domain),
            net::detached);
    }
    
    co_return;
}

// ============================================================================
// 工厂函数
// ============================================================================

std::unique_ptr<IDnsService> CreateDnsService(
    net::any_io_executor executor,
    const DnsService::Config& config) {
    return std::make_unique<DnsService>(executor, config);
}

}  // namespace acpp
