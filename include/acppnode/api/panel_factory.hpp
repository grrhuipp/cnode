#pragma once

#include "acppnode/api/api.hpp"

#include <memory>

namespace acpp::app::dns {
class DNS;
}  // namespace acpp::app::dns

namespace acpp::api {

[[nodiscard]] std::unique_ptr<API> CreatePanelClient(
    net::io_context& io_context,
    const Config& config,
    app::dns::DNS& dns_service);

}  // namespace acpp::api
