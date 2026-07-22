#include "acppnode/app/access_log_session.hpp"

#include "acppnode/common/clock.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/network.hpp"
#include "acppnode/common/read_prefix_capture.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <string_view>

namespace acpp::app {

namespace {

accesslog::Network ToAccessNetwork(::acpp::Network network) noexcept {
    switch (network) {
        case ::acpp::Network::TCP:
            return accesslog::Network::Tcp;
        case ::acpp::Network::UDP:
            return accesslog::Network::Udp;
        case ::acpp::Network::MUX:
            return accesslog::Network::Mux;
        default:
            return accesslog::Network::Unknown;
    }
}

std::string AddressString(const net::ip::address& address) {
    if (address.is_unspecified()) {
        return {};
    }
    return iputil::NormalizeAddressString(address);
}

std::string TargetHostString(const TargetAddress& target) {
    if (!target.host.empty()) return target.host;
    return target.resolved_addr ? AddressString(*target.resolved_addr) : std::string{};
}

std::string FailureStage(ErrorCode error_code) {
    const int value = static_cast<int>(error_code);
    if (error_code == ErrorCode::OK) return {};
    if (error_code == ErrorCode::PROTOCOL_AUTH_FAILED ||
        error_code == ErrorCode::VMESS_INVALID_USER ||
        error_code == ErrorCode::PANEL_USER_DISABLED ||
        error_code == ErrorCode::PANEL_TRAFFIC_EXCEEDED ||
        error_code == ErrorCode::PANEL_RATE_LIMITED) return "auth";
    if (value >= 200 && value < 300) return "decode";
    if (value >= 300 && value < 400) return "route";
    if (value >= 400 && value < 500) return "dial";
    if (value >= 500 && value < 550) return "relay";
    if (value >= 550 && value < 600) return "sniff";
    if (value >= 600 && value < 700) return "transport";
    if (value >= 800 && value < 900) return "dns";
    if (error_code == ErrorCode::BLOCKED ||
        error_code == ErrorCode::CONNECTION_LIMITED ||
        error_code == ErrorCode::PERMISSION_DENIED) return "policy";
    if (value >= 100 && value < 200) return "socket";
    return "internal";
}

bool StartsWithAscii(std::span<const uint8_t> bytes, std::string_view prefix) {
    return bytes.size() >= prefix.size() && std::equal(
        prefix.begin(), prefix.end(), bytes.begin(),
        [](char lhs, uint8_t rhs) {
            return static_cast<unsigned char>(lhs) == rhs;
        });
}

std::string GuessRawProtocol(std::span<const uint8_t> bytes) {
    static constexpr std::array<uint8_t, 12> kProxyV2Signature{
        0x0d,0x0a,0x0d,0x0a,0x00,0x0d,0x0a,0x51,0x55,0x49,0x54,0x0a};
    if (bytes.size() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03) return "tls";
    for (const std::string_view method : {
             "GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ", "CONNECT ", "DELETE ", "PATCH "}) {
        if (StartsWithAscii(bytes, method)) return "http";
    }
    if (StartsWithAscii(bytes, "SSH-")) return "ssh";
    if (StartsWithAscii(bytes, "PROXY ") ||
        (bytes.size() >= 12 && std::equal(
             kProxyV2Signature.begin(),
             kProxyV2Signature.end(),
             bytes.begin()))) return "proxy_protocol";
    if (!bytes.empty() && (bytes[0] == 0x04 || bytes[0] == 0x05)) return "socks";
    return "unknown";
}

void RedactHttpCredentials(std::vector<uint8_t>& bytes, bool& redacted) {
    std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    size_t line_start = 0;
    while (line_start < text.size()) {
        const size_t line_end = text.find("\r\n", line_start);
        if (line_end == std::string_view::npos) break;
        const std::string_view line = text.substr(line_start, line_end - line_start);
        const size_t colon = line.find(':');
        if (colon != std::string_view::npos) {
            std::string name(line.substr(0, colon));
            std::ranges::transform(name, name.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            if (name == "authorization" || name == "proxy-authorization" ||
                name == "cookie" || name == "set-cookie") {
                for (size_t i = line_start + colon + 1; i < line_end; ++i) {
                    bytes[i] = static_cast<uint8_t>('*');
                }
                redacted = true;
            }
        }
        line_start = line_end + 2;
    }
}

void RedactProtocolCredential(
    std::vector<uint8_t>& bytes,
    std::string_view inbound_protocol,
    std::string_view guess,
    bool& redacted) {
    if (bytes.empty()) return;
    if (guess == "http") {
        RedactHttpCredentials(bytes, redacted);
        return;
    }
    if (guess == "tls" || guess == "ssh" || guess == "proxy_protocol") return;
    size_t count = 0;
    if (inbound_protocol == "vless") count = std::min<size_t>(17, bytes.size());
    else if (inbound_protocol == "trojan") count = std::min<size_t>(56, bytes.size());
    else if (inbound_protocol == "vmess" || inbound_protocol == "anytls" ||
             inbound_protocol == "shadowsocks" || inbound_protocol == "ssx") {
        count = std::min<size_t>(64, bytes.size());
    }
    if (count == 0) return;
    std::fill_n(bytes.begin(), count, uint8_t{0});
    redacted = true;
}

std::string Sha256Hex(std::span<const uint8_t> bytes) {
    if (bytes.empty()) return {};
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &digest_len,
                   EVP_sha256(), nullptr) != 1) return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string out(digest_len * 2, '0');
    for (unsigned int i = 0; i < digest_len; ++i) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    return out;
}

accesslog::Result ToAccessResult(ErrorCode error_code) noexcept {
    switch (error_code) {
        case ErrorCode::OK:
            return accesslog::Result::Completed;
        case ErrorCode::CANCELLED:
            return accesslog::Result::Cancelled;
        case ErrorCode::PERMISSION_DENIED:
        case ErrorCode::PROTOCOL_AUTH_FAILED:
        case ErrorCode::ROUTER_NO_MATCH:
        case ErrorCode::ROUTER_OUTBOUND_NOT_FOUND:
        case ErrorCode::BLOCKED:
        case ErrorCode::VMESS_INVALID_USER:
        case ErrorCode::PANEL_USER_DISABLED:
        case ErrorCode::PANEL_TRAFFIC_EXCEEDED:
        case ErrorCode::PANEL_RATE_LIMITED:
        case ErrorCode::CONNECTION_LIMITED:
            return accesslog::Result::Rejected;
        default:
            return accesslog::Result::Failed;
    }
}

}  // namespace

accesslog::Event BuildAccessLogEvent(
    const session::Context& ctx,
    accesslog::CloseSide close_side,
    uint64_t bytes_up,
    uint64_t bytes_down,
    ErrorCode error_code) {
    accesslog::Event event;
    event.source_ref = ctx.inbound.access_source_ref;
    event.conn_id = ctx.conn_id;
    event.worker_id = ctx.worker_id;
    event.user_id = ctx.inbound.user_id;
    event.started_at_unix_us = ctx.accept_time_us;
    event.ended_at_unix_us = NowMicros();
    if (event.ended_at_unix_us > event.started_at_unix_us) {
        event.duration_ms = static_cast<uint64_t>(
            (event.ended_at_unix_us - event.started_at_unix_us) / 1000);
    }

    event.user_email = ctx.inbound.user_email;
    event.inbound_tag.assign(ctx.inbound.tag);
    event.outbound_tag.assign(ctx.outbound.tag);
    event.protocol.assign(ctx.inbound.protocol);
    event.network = ToAccessNetwork(ctx.content.network);

    event.source_ip = ctx.inbound.source_ip.empty()
        ? AddressString(ctx.inbound.source_addr)
        : ctx.inbound.source_ip;
    event.source_port = ctx.inbound.source_port;
    if (ctx.inbound.local_endpoint) {
        event.inbound_port = ctx.inbound.local_endpoint->port();
        event.inbound_ip = AddressString(ctx.inbound.local_endpoint->address());
    }
    event.peer_ip = ctx.inbound.peer_ip;
    event.peer_port = ctx.inbound.peer_port;
    event.client_ip_source = ctx.inbound.client_ip_source;
    event.client_ip_trusted = ctx.inbound.client_ip_trusted;

    if (!ctx.content.multiple_targets) {
        const TargetAddress& target = ctx.outbound.target;
        event.target_host = target.host.empty() && target.resolved_addr
            ? AddressString(*target.resolved_addr)
            : target.host;
        event.target_port = target.port;
    }

    if (ctx.outbound.connected_target_addr) {
        event.remote_ip = AddressString(*ctx.outbound.connected_target_addr);
    }
    if (ctx.outbound.dial_target_addr) {
        event.dial_ip = AddressString(*ctx.outbound.dial_target_addr);
    }
    if (ctx.outbound.connected_local_addr) {
        event.local_ip = AddressString(*ctx.outbound.connected_local_addr);
    }
    event.local_port = ctx.outbound.connected_local_port;
    if (event.target_host.empty() && !ctx.content.multiple_targets) {
        event.target_host = event.remote_ip;
    }

    event.uplink_bytes = std::max(bytes_up, ctx.traffic.bytes_up);
    event.downlink_bytes = std::max(bytes_down, ctx.traffic.bytes_down);
    event.result = ToAccessResult(error_code);
    event.error_code = error_code;
    event.error_reason = ErrorCodeToString(error_code);
    if (error_code != ErrorCode::OK && ctx.inbound.read_prefix_capture) {
        event.raw_packet = ctx.inbound.read_prefix_capture->Bytes();
        event.raw_packet_original_len =
            ctx.inbound.read_prefix_capture->OriginalSize();
        event.raw_packet_truncated =
            ctx.inbound.read_prefix_capture->Truncated();
        event.raw_packet_protocol_guess = GuessRawProtocol(event.raw_packet);
        RedactProtocolCredential(
            event.raw_packet,
            ctx.inbound.protocol,
            event.raw_packet_protocol_guess,
            event.raw_packet_redacted);
        event.raw_packet_captured_len = event.raw_packet.size();
        event.raw_packet_sha256 = Sha256Hex(event.raw_packet);
    }
    event.close_side = close_side;
    event.dns_state = static_cast<uint8_t>(ctx.content.dns_result);
    event.sniff_protocol = ctx.content.protocol;
    event.sniff_domain = ctx.content.sniff_domain;
    event.inbound_transport.assign(ctx.inbound.transport);
    event.inbound_security.assign(ctx.inbound.security);
    event.failure_stage = FailureStage(error_code);
    event.failure_detail_code = ctx.outbound.failure_detail_code.empty()
        ? event.error_reason
        : ctx.outbound.failure_detail_code;
    event.os_error_code = ctx.outbound.os_error_code;
    event.tls_sni = ctx.inbound.tls_sni;
    event.tls_alpn = ctx.inbound.tls_alpn;
    event.tls_version = ctx.inbound.tls_version;
    event.tls_fingerprint = ctx.inbound.tls_fingerprint;
    event.http_host = ctx.inbound.http_host;
    event.transport_route_id = ctx.inbound.transport_route_id;
    event.original_target_host = TargetHostString(ctx.outbound.original_target);
    event.original_target_port = ctx.outbound.original_target.port;
    event.route_target_host = TargetHostString(ctx.outbound.route_target);
    event.route_target_port = ctx.outbound.route_target.port;
    event.final_target_host = TargetHostString(ctx.outbound.target);
    event.final_target_port = ctx.outbound.target.port;
    event.route_rule = ctx.outbound.route_rule;
    event.dns_latency_ms = ctx.outbound.dns_latency_ms;
    event.dns_answer_count = ctx.outbound.dns_answer_count;
    event.dial_attempt_count = ctx.outbound.dial_attempt_count;
    event.dial_ips.reserve(std::min<size_t>(ctx.outbound.dial_addresses.size(), 16));
    for (const auto& address : ctx.outbound.dial_addresses) {
        if (event.dial_ips.size() == 16) break;
        const auto value = AddressString(address);
        if (!value.empty() && std::ranges::find(event.dial_ips, value) == event.dial_ips.end()) {
            event.dial_ips.push_back(value);
        }
    }
    event.transport_handshake_ms = ctx.inbound.transport_handshake_ms;
    event.auth_ms = ctx.auth_ms;
    event.dial_ms = ctx.outbound.dial_ms;
    event.first_byte_ms = ctx.traffic.first_byte_ms;
    event.packet_count_up = ctx.traffic.packet_count_up;
    event.packet_count_down = ctx.traffic.packet_count_down;
    event.datagram_count = ctx.traffic.datagram_count;
    event.distinct_target_count = ctx.traffic.distinct_target_count;
    if (event.distinct_target_count == 0 && ctx.outbound.target.IsValid()) {
        event.distinct_target_count = 1;
    }
    event.parent_conn_id = ctx.parent_conn_id;
    event.stream_id = ctx.stream_id;
    event.runtime_generation = ctx.runtime_generation;
    event.config_generation = ctx.config_generation;
    return event;
}

}  // namespace acpp::app
