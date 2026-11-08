#pragma once

#include "app/port_binding.hpp"
#include "app/proxyman/inbound/prepared_config.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"

#include <memory>
#include <span>


struct InboundSpec;
struct InboundUserSpec;

// Cold-path result shared by static and panel sources. Every field is
// immutable after preparation; Workers copy only what they install.
struct PreparedInbound {
    PortBinding binding;
    proxyman::inbound::ReceiverSettings receiver;
    proxyman::inbound::BuildRequest build_request;
    std::shared_ptr<const proxyman::inbound::UserSet> users;
};

// The single inbound builder: protocol settings, users, transport security,
// receiver settings and port binding. Throws std::invalid_argument on any
// invalid field; has no UserStore or Worker side effects.
[[nodiscard]] PreparedInbound PrepareInbound(const InboundSpec& spec);

// Rebuilds only the users of an already prepared inbound. Every user must be
// accepted; a partial authentication snapshot is rejected.
[[nodiscard]] std::shared_ptr<const proxyman::inbound::UserSet> PrepareInboundUsers(
    const proxyman::inbound::BuildRequest& request,
    std::span<const InboundUserSpec> users);

