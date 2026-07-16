#include "acppnode/app/proxyman/inbound/udp_worker.hpp"
#include "udp_receive_buffer.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

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

    acpp::udp::socket large_receiver(io_context, acpp::udp::v4());
    large_receiver.bind(
        acpp::udp::endpoint(acpp::net::ip::address_v4::loopback(), 0), ec);
    if (ec) Fail("failed to bind large UDP receiver");
    acpp::udp::socket large_sender(io_context, acpp::udp::v4());
    const auto large_endpoint = large_receiver.local_endpoint(ec);
    if (ec) Fail("failed to query large UDP receiver endpoint");

    std::vector<uint8_t> large_payload(acpp::buf::Buffer::kSize + 257, 0x6d);
    bool large_received = false;
    acpp::net::co_spawn(
        io_context,
        [&]() -> acpp::net::awaitable<void> {
            auto [wait_ec] = co_await large_receiver.async_wait(
                acpp::udp::socket::wait_read,
                acpp::net::as_tuple(acpp::net::use_awaitable));
            if (wait_ec) co_return;

            acpp::IoErrorCode available_ec;
            const size_t available = large_receiver.available(available_ec);
            if (available_ec) co_return;
            acpp::detail::UdpReceiveBuffer receive_buffer;
            const auto storage = receive_buffer.Prepare(available);
            acpp::udp::endpoint sender_endpoint;
            auto [receive_ec, bytes] = co_await large_receiver.async_receive_from(
                storage,
                sender_endpoint,
                acpp::net::as_tuple(acpp::net::use_awaitable));
            if (receive_ec) co_return;
            const auto received = receive_buffer.Data(bytes);
            large_received = received.size() == large_payload.size() &&
                std::equal(received.begin(), received.end(), large_payload.begin());
        },
        acpp::net::detached);
    large_sender.send_to(acpp::net::buffer(large_payload), large_endpoint, 0, ec);
    if (ec) Fail("failed to send large UDP datagram");
    io_context.run();
    if (!large_received) {
        Fail("UDP receive path truncated a datagram larger than one Buffer");
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
