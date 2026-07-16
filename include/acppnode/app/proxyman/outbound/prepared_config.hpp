#pragma once

#include "acppnode/common/asio_types.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace acpp {
class Outbound;
class UDPSessionManager;
namespace app::dns {
class DNS;
}
}  // namespace acpp

namespace acpp::proxyman::outbound {

using PreparedOutboundCreator = std::function<std::unique_ptr<::acpp::Outbound>(
    std::string_view tag,
    ::acpp::net::io_context& io_context,
    ::acpp::app::dns::DNS& dns,
    ::acpp::UDPSessionManager* udp_mgr,
    std::chrono::seconds dial_timeout)>;

struct PreparedOutboundConfig {
    std::string tag;
    std::string protocol;
    PreparedOutboundCreator create;
};

}  // namespace acpp::proxyman::outbound
