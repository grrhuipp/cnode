#include "acppnode/app/proxyman/inbound/udp_worker.hpp"

#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string_view>
#include <utility>

namespace {

class DummyUdpHandler final : public acpp::proxyman::inbound::UdpHandler {
public:
    std::optional<acpp::proxyman::inbound::UdpDecodeResult> DecodeUdp(
        std::string_view,
        std::string_view,
        const uint8_t*,
        size_t) const override {
        return std::nullopt;
    }

    acpp::buf::MultiBuffer EncodeUdpResponse(
        acpp::UDPPacketView,
        const acpp::proxyman::inbound::UdpResponseContext&) const override {
        return {};
    }
};

static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().Close()));
static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().ReplaceHandler(
        std::declval<std::unique_ptr<acpp::proxyman::inbound::UdpHandler>>())));
static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().CleanupAllClientSessions()));
static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().CloseSocket(
        std::declval<const std::string&>())));
static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().CloseAllSockets()));

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

}  // namespace

int main() {
    acpp::net::io_context io_context;
    acpp::IoErrorCode ec;

    auto first = acpp::proxyman::inbound::UdpWorker::MakeSocket(io_context);
    first->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open first UDP socket");
    first->bind(acpp::udp::endpoint(acpp::net::ip::address_v4::loopback(), 0), ec);
    if (ec) Fail("failed to bind first UDP socket");
    const auto endpoint = first->local_endpoint(ec);
    if (ec || endpoint.port() == 0) Fail("failed to resolve first UDP endpoint");

    std::array<uint8_t, 1> receive_buffer{};
    acpp::udp::endpoint peer;
    bool receive_cancelled = false;
    first->async_receive_from(
        acpp::net::buffer(receive_buffer),
        peer,
        [&](acpp::IoErrorCode receive_ec, size_t) {
            receive_cancelled = receive_ec == acpp::io_error::operation_aborted;
        });
    first.reset();
    io_context.run();
    if (!receive_cancelled) {
        Fail("destroyed UDP socket did not cancel its pending receive");
    }
    io_context.restart();

    auto second = acpp::proxyman::inbound::UdpWorker::MakeSocket(io_context);
    second->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open second UDP socket");
    second->bind(endpoint, ec);
    if (ec) Fail("owned UDP socket did not release its bound port");

    acpp::proxyman::inbound::UdpWorker worker(
        "test-inbound", std::make_unique<DummyUdpHandler>());
    auto* attached = worker.AttachSocket("stable-socket", std::move(second));
    if (!attached || worker.FindSocket("stable-socket") != attached ||
        !attached->is_open()) {
        Fail("failed to attach initial UDP socket");
    }

    auto duplicate = acpp::proxyman::inbound::UdpWorker::MakeSocket(io_context);
    duplicate->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open duplicate UDP socket");
    if (worker.AttachSocket("stable-socket", std::move(duplicate)) != nullptr) {
        Fail("duplicate UDP socket attachment was accepted");
    }
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("duplicate attachment replaced the live UDP socket");
    }

    if (!worker.ReplaceHandler(std::make_unique<DummyUdpHandler>())) {
        Fail("valid UDP handler replacement was rejected");
    }
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("UDP handler replacement disturbed the live socket");
    }
    if (worker.ReplaceHandler(nullptr)) {
        Fail("null UDP handler replacement was accepted");
    }
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("rejected UDP handler replacement disturbed the live socket");
    }

    worker.CloseSocket("stable-socket");
    if (worker.FindSocket("stable-socket") != nullptr) {
        Fail("closed UDP socket remained registered");
    }

    return 0;
}
