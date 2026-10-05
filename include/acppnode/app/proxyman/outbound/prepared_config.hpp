#pragma once

#include "acppnode/common/asio_types.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace acpp {
class Outbound;
namespace app::dns {
class DNS;
}
}  // namespace acpp

namespace acpp::proxyman::outbound {

using PreparedOutboundCreator = std::function<std::unique_ptr<::acpp::Outbound>(
    std::string_view tag,
    ::acpp::net::any_io_executor executor,
    ::acpp::app::dns::DNS& dns,
    std::chrono::seconds dial_timeout)>;

struct PreparedOutboundConfig {
    std::string tag;
    std::string protocol;
    PreparedOutboundCreator create;
};

}  // namespace acpp::proxyman::outbound
