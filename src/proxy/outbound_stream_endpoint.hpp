#pragma once

#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"
#include "transport/internet/datagram_socket.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/internet/stream_settings.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace proxy {

class OutboundStreamEndpointBase
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    explicit OutboundStreamEndpointBase(AsyncStream& stream) noexcept
        : stream_(stream) {}

    bool ConsumeIdleTimeout() noexcept {
        return stream_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return stream_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return stream_.ConsumeWriteTimeout();
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        return stream_.StartPhaseDeadline(timeout);
    }

    void ClearPhaseDeadline() {
        stream_.ClearPhaseDeadline();
    }

    bool ConsumePhaseDeadline() noexcept {
        return stream_.ConsumePhaseDeadline();
    }

    void Cancel() noexcept {
        stream_.Cancel();
    }

    void SetWriteTimeout(std::chrono::seconds timeout) {
        stream_.SetWriteTimeout(timeout);
    }

    void Close() {
        stream_.Close();
    }

    void CloseAbortive() {
        stream_.CloseAbortive();
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return stream_.Cancellation();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return stream_.ReadEofAction();
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return stream_.WriteShutdownClosesLink();
    }

protected:
    AsyncStream& stream_;
};

class OutboundDatagramEndpointBase
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    OutboundDatagramEndpointBase(net::io_context& io,
                                 const net::ip::address& bind_address)
        : socket_(io, bind_address) {}

    net::awaitable<void> AsyncShutdownWrite() override {
        write_closed_ = true;
        co_return;
    }

    void Cancel() noexcept {
        socket_.Cancel();
    }

    void Close() noexcept {
        socket_.Close();
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return socket_.Cancellation();
    }

    void SetIdleTimeout(std::chrono::seconds value) {
        socket_.SetIdleTimeout(value);
    }

    void SetReadTimeout(std::chrono::seconds value) {
        socket_.SetReadTimeout(value);
    }

    void SetWriteTimeout(std::chrono::seconds value) {
        socket_.SetWriteTimeout(value);
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds value) {
        return socket_.StartPhaseDeadline(value);
    }

    void ClearPhaseDeadline() noexcept {
        socket_.ClearPhaseDeadline();
    }

    bool ConsumeIdleTimeout() noexcept {
        return socket_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return socket_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return socket_.ConsumeWriteTimeout();
    }

    bool ConsumePhaseDeadline() noexcept {
        return socket_.ConsumePhaseDeadline();
    }

protected:
    transport::internet::DatagramSocket socket_;
    bool write_closed_ = false;
};

// Cold-path result for a proxy protocol with a next hop: the validated server
// and the Handler's sender settings (sendThrough is applied by proxyman).
struct PreparedNextHop {
    OutboundServer server;
    OutboundSenderSettings sender;
};

// The one application of a protocol's stream defaults (TLS requirement,
// fallback SNI, ALPN) to the source streamSettings. Without an explicit
// fallback server name the next hop's address is used.
[[nodiscard]] inline StreamSettings PrepareOutboundStream(
    const infra::OutboundSourceConfig& source,
    const OutboundServer& server,
    OutboundStreamDefaults defaults) {
    if (defaults.fallback_server_name.empty()) {
        defaults.fallback_server_name = server.address;
    }
    auto settings = NormalizeOutboundStreamSettings(source.stream_settings, defaults);
    TransportSecurity::Prepare(settings, StreamEndpointRole::Outbound);
    return settings;
}

[[nodiscard]] inline std::optional<PreparedNextHop> PrepareNextHop(
    const infra::OutboundSourceConfig& source,
    std::string address,
    uint16_t port,
    const OutboundStreamDefaults& defaults) {
    auto server = MakeOutboundServer(std::move(address), port);
    if (!server) {
        LOG_ERROR("{} outbound '{}': {}", source.protocol, source.tag, server.error());
        return std::nullopt;
    }
    PreparedNextHop prepared{.server = std::move(*server), .sender = {}};
    prepared.sender.stream_settings = PrepareOutboundStream(source, prepared.server, defaults);
    return prepared;
}

// Validates an optional Xray-style single-element object array (e.g. "servers"
// or "vnext"). Returns nullptr when absent, the single object when valid, or
// std::nullopt on a malformed present field (Fail-Closed).
[[nodiscard]] inline std::optional<const json::object*>
ParseOptionalSingleObjectArray(
    const json::object& parent,
    std::string_view key,
    std::string_view protocol,
    std::string_view tag) {
    const auto* value = parent.if_contains(key);
    if (!value) {
        return static_cast<const json::object*>(nullptr);
    }
    if (!value->is_array() ||
        value->as_array().size() != 1 ||
        !value->as_array()[0].is_object()) {
        LOG_ERROR("{} outbound '{}': {} must be a single-element object array",
                  protocol, tag, key);
        return std::nullopt;
    }
    return &value->as_array()[0].as_object();
}

[[nodiscard]] inline const json::object*
ParseRequiredSingleObjectArray(
    const json::object& parent,
    std::string_view key,
    std::string_view protocol,
    std::string_view tag) {
    const auto parsed = ParseOptionalSingleObjectArray(parent, key, protocol, tag);
    if (!parsed) {
        return nullptr;
    }
    if (!*parsed) {
        LOG_ERROR("{} outbound '{}': {} must be a single-element object array",
                  protocol, tag, key);
        return nullptr;
    }
    return *parsed;
}

}  // namespace proxy
