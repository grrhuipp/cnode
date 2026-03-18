#include "acppnode/app/session_context.hpp"
#include "acppnode/common.hpp"
#include "acppnode/common/ip_utils.hpp"

#include <chrono>
#include <atomic>
#include <format>

namespace acpp {

std::string SessionContext::ToAccessLog() const {
    std::string timestamp = FormatTimestamp(accept_time_us);

    std::string src = std::format("{}:{}",
        client_ip.empty() ? iputil::NormalizeAddressString(src_addr.address()) : client_ip,
        src_addr.port());

    std::string net_str = NetworkToString(network);

    const TargetAddress& t = EffectiveTarget();
    std::string target_host = t.host.empty() ? "unknown" : t.host;

    std::string resolved_str;
    if (!resolved_ip.is_unspecified()) {
        resolved_str = std::format("({})", iputil::NormalizeAddressString(resolved_ip));
    }

    std::string local_str = local_ip.is_unspecified()
        ? "-"
        : iputil::NormalizeAddressString(local_ip);

    std::string user_str = user_email.empty() ?
        (user_id > 0 ? std::to_string(user_id) : "-") : user_email;

    std::string dns_str = dns_result.empty() ? "none" : dns_result;

    std::string sniff_str = sniff_result.success ?
        std::format("{}:{}", sniff_result.protocol, sniff_result.domain) : "none";

    std::string in_tag  = inbound_tag.empty()  ? "-" : inbound_tag;
    std::string out_tag = outbound_tag.empty() ? "-" : outbound_tag;

    return std::format("{} from {} accepted {}:{}{}:{} [{} -> {}] via {} email:{} dns:{} sniff:{}",
        timestamp, src, net_str, target_host, resolved_str, t.port,
        in_tag, out_tag, local_str, user_str, dns_str, sniff_str);
}

std::string SessionContext::ToAccessLogComplete(
    std::string_view status,
    uint64_t bytes_up_val,
    uint64_t bytes_down_val,
    int64_t duration_ms) const {
    return std::format("{} {} {}/{} {}ms",
        ToAccessLog(), status, bytes_up_val, bytes_down_val, duration_ms);
}

// 格式化时间戳（本地时区，跨平台）
std::string FormatTimestamp(int64_t timestamp_us) {
    using namespace std::chrono;
    auto tp = floor<seconds>(system_clock::time_point{microseconds{timestamp_us}});
    auto zt = zoned_time{current_zone(), tp};
    return std::format("{:%Y-%m-%d %H:%M:%S}", zt);
}

// 生成唯一连接 ID
uint64_t GenerateConnId() {
    static std::atomic<uint64_t> counter{0};
    return counter.fetch_add(1, std::memory_order_relaxed) + 1;
}

}  // namespace acpp
