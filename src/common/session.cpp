#include "acppnode/common/session.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/network.hpp"

#include <array>
#include <chrono>
#include <format>
#include <iterator>
#include <optional>

namespace acpp {

namespace session {

ID NewID(uint32_t worker_id) noexcept {
    thread_local uint32_t local_counter = 0;
    const uint32_t seq = ++local_counter;
    return (static_cast<uint64_t>(worker_id) << 32) | seq;
}

void Context::InitSubstreamFrom(const Context& parent, uint16_t sub_source_port) {
    worker_id = parent.worker_id;
    conn_id = NewID(worker_id);
    accept_time_us = NowMicros();
    inbound = parent.inbound;
    if (sub_source_port != 0) {
        inbound.source_port = sub_source_port;
    }
    outbound.tag = parent.outbound.tag;
    content.speed_limit = parent.content.speed_limit;
    traffic = {};
}
}  // namespace session

std::string FormatAccessLog(const session::Context& ctx) {
    std::optional<iputil::AddressText> src_host_storage;
    std::string_view src_host = ctx.inbound.source_ip;
    if (src_host.empty()) {
        if (!ctx.inbound.source_addr.is_unspecified()) {
            src_host_storage.emplace(iputil::NormalizeAddress(ctx.inbound.source_addr));
            src_host = src_host_storage->View();
        } else {
            src_host = "unknown";
        }
    }
    const char* net_str = NetworkToString(ctx.content.network);

    const TargetAddress& t = ctx.outbound.target;
    std::optional<iputil::AddressText> target_host_storage;
    std::string_view target_host = t.host;
    if (target_host.empty()) {
        if (t.resolved_addr) {
            target_host_storage.emplace(iputil::NormalizeAddress(*t.resolved_addr));
            target_host = target_host_storage->View();
        } else {
            target_host = "unknown";
        }
    }

    const std::string_view in_tag = ctx.inbound.tag.empty()
        ? std::string_view("-")
        : ctx.inbound.tag;
    const std::string_view out_tag = ctx.outbound.tag.empty()
        ? std::string_view("-")
        : ctx.outbound.tag;

    // Only the final owning string crosses the logging queue. Do not use the
    // Worker PMR for it or retain connection-local formatting scratch.
    std::string access;
    access.reserve(128 + src_host.size() + target_host.size() +
                   in_tag.size() + out_tag.size() + ctx.inbound.user_email.size());
    auto endpoint = [&](std::string_view host, uint16_t port) {
        const bool brackets = iputil::NeedsIpv6Brackets(host);
        std::format_to(std::back_inserter(access), "{}{}{}:{}",
                       brackets ? "[" : "", host, brackets ? "]" : "", port);
    };
    access.append("from ");
    endpoint(src_host, ctx.inbound.source_port);
    access.append(" accepted ");
    access.append(net_str);
    access.push_back(':');
    endpoint(target_host, t.port);
    access.append(" [");
    access.append(in_tag);
    if (in_tag != out_tag) {
        access.append(" -> ");
        access.append(out_tag);
    }
    access.push_back(']');
    if (ctx.inbound.user_id > 0) {
        std::format_to(std::back_inserter(access), " user:{}", ctx.inbound.user_id);
    } else if (!ctx.inbound.user_email.empty()) {
        access.append(" user:");
        access.append(ctx.inbound.user_email);
    }
    if (ctx.outbound.connected_local_addr &&
        !ctx.outbound.connected_local_addr->is_unspecified()) {
        access.append(" sendThrough:");
        access.append(iputil::AddressText(iputil::NormalizeAddress(
            *ctx.outbound.connected_local_addr)).View());
    }
    return access;
}

// 格式化时间戳（本地时区，跨平台）
std::string FormatTimestamp(int64_t timestamp_us) {
    using namespace std::chrono;
    struct CachedTimestamp {
        int64_t sec = -1;
        std::string value;
    };

    constexpr size_t kTimestampCacheSize = 8;
    thread_local std::array<CachedTimestamp, kTimestampCacheSize> cache;
    thread_local size_t next_slot = 0;

    const auto sec = duration_cast<seconds>(microseconds{timestamp_us}).count();
    for (const auto& entry : cache) {
        if (entry.sec == sec) {
            return entry.value;
        }
    }

    const auto tp = system_clock::time_point{seconds{sec}};
    auto value = FormatLocalTime(tp, "%Y-%m-%d %H:%M:%S");
    cache[next_slot] = CachedTimestamp{
        .sec = sec,
        .value = value,
    };
    next_slot = (next_slot + 1) % kTimestampCacheSize;
    return value;
}

}  // namespace acpp
