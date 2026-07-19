#include "acppnode/common/session.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/network.hpp"

#include <array>
#include <chrono>
#include <format>

namespace acpp {

namespace session {

ID NewID(uint32_t worker_id) noexcept {
    return GenerateWorkerConnId(worker_id);
}

}  // namespace session

std::string FormatXrayAccessLog(const session::Context& ctx) {
    std::string src_host_storage;
    std::string_view src_host = ctx.inbound.source_ip;
    if (src_host.empty()) {
        if (!ctx.inbound.source_addr.is_unspecified()) {
            src_host_storage = iputil::NormalizeAddressString(ctx.inbound.source_addr);
            src_host = src_host_storage;
        } else {
            src_host = "unknown";
        }
    }
    std::string src = iputil::FormatEndpointForLog(src_host, ctx.inbound.source_port);

    const char* net_str = NetworkToString(ctx.content.network);

    const TargetAddress& t = ctx.outbound.target;
    std::string target_host_storage;
    std::string_view target_host = t.host;
    if (target_host.empty()) {
        if (t.resolved_addr) {
            target_host_storage = iputil::NormalizeAddressString(*t.resolved_addr);
            target_host = target_host_storage;
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

    std::string access = std::format(
        "from {} accepted {}:{} [{} -> {}]",
        src,
        net_str,
        iputil::FormatEndpointForLog(target_host, t.port),
        in_tag,
        out_tag);
    if (!ctx.inbound.user_email.empty()) {
        access.append(" email: ");
        access.append(ctx.inbound.user_email);
    } else if (ctx.inbound.user_id > 0) {
        access.append(std::format(" email: {}", ctx.inbound.user_id));
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

uint64_t GenerateWorkerConnId(uint32_t worker_id) {
    thread_local uint32_t local_counter = 0;
    const uint32_t seq = ++local_counter;
    return (static_cast<uint64_t>(worker_id) << 32) | seq;
}

}  // namespace acpp
