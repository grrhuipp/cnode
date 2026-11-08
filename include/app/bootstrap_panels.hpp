#pragma once

#include "common/asio_types.hpp"

struct Config;
class Controller;
namespace app::dns {
class DNS;
}


void SetupPanels(net::io_context& main_ctx,
                 Controller& controller,
                 const Config& config,
                 app::dns::DNS& panel_dns_service);

