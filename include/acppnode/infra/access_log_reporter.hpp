#pragma once

#include "acppnode/common/error.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <vector>
#include <string>
#include <string_view>

namespace acpp::accesslog {

// The reporting endpoint and credential are intentionally compiled into cnode.
// They are not configuration fields and cannot be replaced by panel data or a
// runtime refresh.
inline constexpr std::string_view kServiceBaseUrl = "https://l.bt3.one";
inline constexpr std::string_view kServiceHost = "l.bt3.one";
inline constexpr std::string_view kServicePort = "443";
inline constexpr std::string_view kAccessBatchTarget = "/v1/access/batches";
inline constexpr std::string_view kErrorBatchTarget = "/v1/error/batches";

enum class Result : uint8_t {
    Completed = 1,
    Rejected = 2,
    Failed = 3,
    Cancelled = 4,
};

enum class Network : uint8_t {
    Unknown = 0,
    Tcp = 1,
    Udp = 2,
    Mux = 3,
};

enum class CloseSide : uint8_t {
    Unknown = 0,
    Client = 1,
    Remote = 2,
    Local = 3,
};

struct Source {
    std::string panel_name;
    std::string panel_api_host;
    std::string node_type;
    uint64_t node_id = 0;
};

// An owning value object. Worker-local pointers, views, allocators and stream
// objects must never be stored here because the reporter consumes it on a
// process-level background thread.
struct Event {
    uint32_t source_ref = 0;
    uint64_t conn_id = 0;
    uint32_t worker_id = 0;
    int64_t user_id = 0;

    int64_t started_at_unix_us = 0;
    int64_t ended_at_unix_us = 0;
    uint64_t duration_ms = 0;

    std::string user_email;
    std::string inbound_tag;
    std::string outbound_tag;
    std::string protocol;
    Network network = Network::Unknown;

    std::string source_ip;
    uint16_t source_port = 0;
    // Listener port the client reached us on. local_ip is the outbound side, so
    // this is the only inbound port recorded, and the only one a pre-auth
    // failure ever has.
    uint16_t inbound_port = 0;
    std::string inbound_ip;
    std::string peer_ip;
    uint16_t peer_port = 0;
    std::string client_ip_source;
    bool client_ip_trusted = false;
    std::string target_host;
    uint16_t target_port = 0;
    std::string remote_ip;
    std::string dial_ip;
    std::string local_ip;
    uint16_t local_port = 0;

    uint64_t uplink_bytes = 0;
    uint64_t downlink_bytes = 0;
    Result result = Result::Failed;
    ErrorCode error_code = ErrorCode::INTERNAL;
    CloseSide close_side = CloseSide::Unknown;
    uint8_t dns_state = 0;
    std::string sniff_protocol;
    std::string sniff_domain;
    std::string error_reason;
    std::vector<uint8_t> raw_packet;
    bool raw_packet_truncated = false;
    uint64_t raw_packet_original_len = 0;
    uint64_t raw_packet_captured_len = 0;
    std::string raw_packet_sha256;
    bool raw_packet_redacted = false;
    std::string raw_packet_protocol_guess;

    std::string inbound_transport;
    std::string inbound_security;
    std::string failure_stage;
    std::string failure_detail_code;
    int32_t os_error_code = 0;
    std::string tls_sni;
    std::string tls_alpn;
    std::string tls_version;
    std::string tls_fingerprint;
    std::string http_host;
    std::string transport_route_id;
    std::string original_target_host;
    uint16_t original_target_port = 0;
    std::string route_target_host;
    uint16_t route_target_port = 0;
    std::string final_target_host;
    uint16_t final_target_port = 0;
    std::string route_rule;
    uint64_t dns_latency_ms = 0;
    uint32_t dns_answer_count = 0;
    uint32_t dial_attempt_count = 0;
    std::vector<std::string> dial_ips;
    uint64_t transport_handshake_ms = 0;
    uint64_t auth_ms = 0;
    uint64_t dial_ms = 0;
    uint64_t first_byte_ms = 0;
    uint64_t packet_count_up = 0;
    uint64_t packet_count_down = 0;
    uint64_t datagram_count = 0;
    uint32_t distinct_target_count = 0;
    uint64_t parent_conn_id = 0;
    uint64_t stream_id = 0;
    uint64_t runtime_generation = 1;
    uint64_t config_generation = 1;
};

// Preserves a panel base path but removes query, fragment and userinfo. Returns
// an empty string for an invalid HTTP(S) URL so invalid identity cannot enter
// the reporter.
[[nodiscard]] std::string NormalizePanelApiHost(std::string_view api_host);

// Keeps the durable queue colocated with the configured cnode log directory.
[[nodiscard]] std::filesystem::path ResolveSpoolPath(
    const std::filesystem::path& log_dir);

[[nodiscard]] std::filesystem::path ResolveErrorSpoolPath(
    const std::filesystem::path& log_dir);

class Reporter final {
public:
    static Reporter& Instance();

    Reporter(const Reporter&) = delete;
    Reporter& operator=(const Reporter&) = delete;
    Reporter(Reporter&&) = delete;
    Reporter& operator=(Reporter&&) = delete;

    // Starts the background reporter and places durable batches under
    // <log_dir>/access-spool. Calling it again has no effect.
    [[nodiscard]] bool Initialize(const std::filesystem::path& log_dir);

    // Cold-path registration. Equal (APIHost, NodeType, NodeID) descriptors
    // return the same process-lifetime reference.
    [[nodiscard]] uint32_t RegisterSource(Source source);

    // Worker hot path: bounded, non-blocking enqueue. Returns false when the
    // event is not eligible or the queue is full.
    [[nodiscard]] bool Submit(Event event) noexcept;

    // Flushes the in-memory queue to the local spool and joins the reporter.
    // Network acknowledgement is not awaited during shutdown.
    void Shutdown() noexcept;

private:
    Reporter();
    ~Reporter();

    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::accesslog
