#include "acppnode/common/session.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/network.hpp"

#include <charconv>
#include <array>
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

std::string FormatAccessLog(const session::Context& ctx,
                            AccessStatus status,
                            std::string_view reason) {
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

    const std::string_view in_tag = ctx.inbound.tag;
    const std::string_view out_tag = ctx.outbound.tag;
    const bool accepted = status == AccessStatus::Accepted;
    const bool has_target = accepted || t.IsValid();

    // Only the final owning string crosses the logging queue. Do not use the
    // Worker PMR for it or retain connection-local formatting scratch.
    std::string access;
    access.reserve(128 + src_host.size() + target_host.size() +
                   in_tag.size() + out_tag.size() +
                   ctx.inbound.user_email.size() + reason.size());
    auto endpoint = [&](std::string_view host, uint16_t port) {
        const bool brackets = iputil::NeedsIpv6Brackets(host);
        std::format_to(std::back_inserter(access), "{}{}{}:{}",
                       brackets ? "[" : "", host, brackets ? "]" : "", port);
    };
    if (accepted || src_host != "unknown") {
        access.append("from ");
        endpoint(src_host, ctx.inbound.source_port);
        access.push_back(' ');
    }
    access.append(accepted ? "accepted" : "rejected");
    if (has_target) {
        access.push_back(' ');
        access.append(net_str);
        access.push_back(':');
        endpoint(target_host, t.port);
    }
    if (!accepted && !reason.empty()) {
        access.push_back(' ');
        access.append(reason);
    }
    if (!in_tag.empty() || !out_tag.empty()) {
        access.append(" [");
        access.append(in_tag);
        if (!out_tag.empty() && in_tag != out_tag) {
            if (!in_tag.empty()) access.append(" -> ");
            access.append(out_tag);
        }
        access.push_back(']');
    }
    std::array<char, 20> uid_buffer{};
    std::string_view uid;
    if (ctx.inbound.user_id > 0) {
        const auto result = std::to_chars(
            uid_buffer.data(), uid_buffer.data() + uid_buffer.size(), ctx.inbound.user_id);
        uid = {uid_buffer.data(), static_cast<size_t>(result.ptr - uid_buffer.data())};
        access.append(" user:").append(uid);
    }
    if (!ctx.inbound.user_email.empty() && ctx.inbound.user_email != uid) {
        access.append(" email:").append(ctx.inbound.user_email);
    }
    if (ctx.outbound.connected_local_addr &&
        !ctx.outbound.connected_local_addr->is_unspecified()) {
        access.append(" sendThrough:");
        access.append(iputil::AddressText(iputil::NormalizeAddress(
            *ctx.outbound.connected_local_addr)).View());
    }
    return access;
}

}  // namespace acpp
