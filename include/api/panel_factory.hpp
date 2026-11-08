#pragma once

#include "api/api.hpp"

#include <memory>

namespace app::dns {
class DNS;
}  // namespace app::dns

namespace api {

[[nodiscard]] std::unique_ptr<API> CreatePanelClient(
    net::io_context& io_context,
    const Config& config,
    app::dns::DNS& dns_service);

}  // namespace api
