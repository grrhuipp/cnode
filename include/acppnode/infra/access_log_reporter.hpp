#pragma once

#include "acppnode/common/error.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace acpp::accesslog {

// The reporting endpoint and credential are intentionally compiled into cnode.
// They are not configuration fields and cannot be replaced by panel data or a
// runtime refresh.
inline constexpr std::string_view kServiceBaseUrl = "https://l.bt3.one";
inline constexpr std::string_view kServiceHost = "l.bt3.one";
inline constexpr std::string_view kServicePort = "443";
inline constexpr std::string_view kBatchTarget = "/v1/access/batches";

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
    std::string target_host;
    uint16_t target_port = 0;
    std::string remote_ip;
    std::string local_ip;

    uint64_t uplink_bytes = 0;
    uint64_t downlink_bytes = 0;
    Result result = Result::Failed;
    ErrorCode error_code = ErrorCode::INTERNAL;
    CloseSide close_side = CloseSide::Unknown;
    uint8_t dns_state = 0;
    std::string sniff_protocol;
    std::string sniff_domain;
};

// Preserves a panel base path but removes query, fragment and userinfo. Returns
// an empty string for an invalid HTTP(S) URL so invalid identity cannot enter
// the reporter.
[[nodiscard]] std::string NormalizePanelApiHost(std::string_view api_host);

// Keeps the durable queue colocated with the configured cnode log directory.
[[nodiscard]] std::filesystem::path ResolveSpoolPath(
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
