#pragma once

#include "acppnode/common/asio_types.hpp"

namespace acpp {
class Config;
class Controller;
namespace app::dns {
class DNS;
}
}

namespace acpp {

void SetupPanels(net::any_io_executor executor,
                 Controller& controller,
                 const Config& config,
                 app::dns::DNS& panel_dns_service);

}  // namespace acpp
