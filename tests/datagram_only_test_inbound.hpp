#pragma once

#include "proxy/inbound_admission.hpp"

#include <stdexcept>

// Native-datagram fixtures deliberately have no stream protocol. A stream
// invocation is a fixture wiring error, not a second custom Process entry.
class DatagramOnlyTestInbound : public proxy::Inbound {
public:
    struct Session {
        Session() = default;
        Session(const Session&) = delete;
        Session(Session&&) = delete;
        net::awaitable<tl::expected<proxy::AuthenticatedInbound, common::ErrorCode>>
        Authenticate(transport::AsyncStream&, proxy::InboundAuthentication,
                     proxy::InboundContext&) {
            throw std::logic_error("unexpected datagram fixture stream authentication");
            co_return tl::unexpected(common::ErrorCode::NOT_SUPPORTED);
        }
        proxy::InboundPrepared Prepare(std::unique_ptr<transport::AsyncStream>&,
                                        proxy::InboundContext&) {
            throw std::logic_error("unexpected datagram fixture stream preparation");
        }
    };

    DatagramOnlyTestInbound() : Inbound(std::in_place_type<DatagramOnlyTestInbound>) {}
    const app::AdmissionEnvironment& Environment() const {
        throw std::logic_error("unexpected datagram fixture stream entry");
    }
    auto SessionArguments() const noexcept { return std::tuple{}; }
};
