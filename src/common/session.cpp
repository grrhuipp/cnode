#include "acppnode/common/session.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/network.hpp"
#include "acppnode/core/constants.hpp"

#include <chrono>
#include <format>

namespace acpp {

namespace {

std::string_view DnsResultStateName(session::DnsResultState state) noexcept {
    switch (state) {
        case session::DnsResultState::Cache:
            return constants::state::kCache;
        case session::DnsResultState::Resolve:
            return constants::state::kResolve;
        case session::DnsResultState::Failed:
            return constants::state::kFailed;
        case session::DnsResultState::None:
        default:
            return constants::state::kNone;
    }
}

}  // namespace

namespace session {

ID NewID(uint32_t worker_id) noexcept {
    return GenerateWorkerConnId(worker_id);
}

}  // namespace session

std::string FormatAccessLog(
    const session::Context& ctx,
    const net::ip::address* resolved_ip,
    const net::ip::address* local_ip) {
    std::string timestamp = FormatTimestamp(ctx.accept_time_us);

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

    std::string resolved_str;
    if (resolved_ip && !resolved_ip->is_unspecified()) {
        resolved_str = iputil::NormalizeAddressString(*resolved_ip);
        resolved_str.insert(resolved_str.begin(), '(');
        resolved_str.push_back(')');
    }

    std::string local_storage;
    std::string_view local_str = "-";
    if (local_ip && !local_ip->is_unspecified()) {
        local_storage = iputil::NormalizeAddressString(*local_ip);
        local_str = local_storage;
    }

    std::string user_storage;
    std::string_view user_str = ctx.inbound.user_email;
    if (user_str.empty()) {
        if (ctx.inbound.user_id > 0) {
            user_storage = std::to_string(ctx.inbound.user_id);
            user_str = user_storage;
        } else {
            user_str = "-";
        }
    }

    const std::string_view dns_str = DnsResultStateName(ctx.content.dns_result);

    std::string sniff_storage;
    std::string_view sniff_str = constants::state::kNone;
    if (!ctx.content.protocol.empty()) {
        sniff_storage.reserve(
            ctx.content.protocol.size() + 1 + ctx.content.sniff_domain.size());
        sniff_storage.append(ctx.content.protocol);
        sniff_storage.push_back(':');
        sniff_storage.append(ctx.content.sniff_domain.data(), ctx.content.sniff_domain.size());
        sniff_str = sniff_storage;
    }

    const std::string_view in_tag = ctx.inbound.tag.empty()
        ? std::string_view("-")
        : ctx.inbound.tag;
    const std::string_view out_tag = ctx.outbound.tag.empty()
        ? std::string_view("-")
        : ctx.outbound.tag;

    return std::format("{} from {} accepted {}:{}{}:{} [{} -> {}] via {} email:{} dns:{} sniff:{}",
        timestamp, src, net_str, target_host, resolved_str, t.port,
        in_tag, out_tag, local_str, user_str, dns_str, sniff_str);
}

// 格式化时间戳（本地时区，跨平台）
std::string FormatTimestamp(int64_t timestamp_us) {
    using namespace std::chrono;
    const auto tp = floor<seconds>(system_clock::time_point{microseconds{timestamp_us}});
    return FormatLocalTime(tp, "%Y-%m-%d %H:%M:%S");
}

uint64_t GenerateWorkerConnId(uint32_t worker_id) {
    thread_local uint32_t local_counter = 0;
    const uint32_t seq = ++local_counter;
    return (static_cast<uint64_t>(worker_id) << 32) | seq;
}

}  // namespace acpp
