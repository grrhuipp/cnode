#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/dial_target.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/transport/internet/transport_security.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <tl/expected.hpp>
#include <string_view>

namespace acpp::app::dns {
class DNS;
}  // namespace acpp::app::dns

namespace acpp {

namespace session {
struct Context;
}  // namespace session

struct OutboundTargetOptions {
    app::dns::DNS* dns_service = nullptr;
    std::string_view address{};
    std::optional<net::ip::address> literal_address = std::nullopt;
    uint16_t port = 0;
    const StreamSettings* stream_settings = nullptr;
    // The outbound handler's contexts for |stream_settings|; the XHTTP
    // download leg uses its XHttpDownload() contexts.
    const TransportSecurity* security = nullptr;
    std::chrono::seconds timeout{defaults::kDialTimeout};
    const OutboundBind* send_through = nullptr; // Borrowed from the outbound handler.
    const tcp::endpoint* inbound_local_addr = nullptr;
    std::string_view inbound_source_ip{};
    uint16_t inbound_source_port = 0;
    std::optional<OutboundBind::Selection> ordered_bind_v4 = std::nullopt;
    std::optional<OutboundBind::Selection> ordered_bind_v6 = std::nullopt;
    std::string_view tls_server_name{};
    std::string_view ws_host{};
};

[[nodiscard]] std::string_view ResolveOutboundTlsServerName(
    const StreamSettings& settings,
    std::string_view fallback_server_name);

[[nodiscard]]
net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>>
BuildOutboundTransportTarget(OutboundTargetOptions options);

void RecordOutboundStreamConnected(session::Context& ctx,
                                   const AsyncStream& stream);

[[nodiscard]]
net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
DialOutboundStream(net::io_context& io_context,
                   session::Context& ctx,
                   OutboundTargetOptions options);

}  // namespace acpp
