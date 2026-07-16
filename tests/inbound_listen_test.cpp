#include "acppnode/transport/internet/inbound_listen.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/tcp_worker.hpp"

#include <array>
#include <string_view>

int main() {
    for (const auto value : std::array<std::string_view, 2>{"", "auto"}) {
        auto listen = acpp::InboundListen::Parse(value);
        if (!listen || !listen->IsAuto() || listen->Candidates().size() != 2 ||
            !listen->Candidates()[0].is_v4() || !listen->Candidates()[0].is_unspecified() ||
            !listen->Candidates()[1].is_v6() || !listen->Candidates()[1].is_unspecified()) {
            return 1;
        }
    }

    auto ipv4 = acpp::InboundListen::Parse("127.0.0.1");
    if (!ipv4 || ipv4->IsAuto() || ipv4->Candidates().size() != 1 ||
        !ipv4->Candidates()[0].is_v4() || !ipv4->Candidates()[0].is_loopback()) {
        return 2;
    }

    auto ipv6 = acpp::InboundListen::Parse("::1");
    if (!ipv6 || ipv6->IsAuto() || ipv6->Candidates().size() != 1 ||
        !ipv6->Candidates()[0].is_v6() || !ipv6->Candidates()[0].is_loopback()) {
        return 3;
    }

    auto mapped = acpp::InboundListen::Parse("::ffff:127.0.0.1");
    if (!mapped || mapped->Candidates().size() != 1 ||
        !mapped->Candidates()[0].is_v4() || !mapped->Candidates()[0].is_loopback()) {
        return 4;
    }

    for (const auto value :
         std::array<std::string_view, 4>{"not-an-ip", "127.0.0.1junk", "AUTO", " auto"}) {
        if (acpp::InboundListen::Parse(value)) return 5;
    }

    auto socket_binding = acpp::MakePortBinding(
        443, "vmess", "stable-inbound", *ipv4);
    auto protocol_update = acpp::MakePortBinding(
        443, "trojan", "stable-inbound", *ipv4);
    auto port_update = acpp::MakePortBinding(
        8443, "vmess", "stable-inbound", *ipv4);
    auto address_update = acpp::MakePortBinding(
        443, "vmess", "stable-inbound", *ipv6);
    auto tag_update = acpp::MakePortBinding(
        443, "vmess", "other-inbound", *ipv4);
    if (!socket_binding.UsesSameSocket(protocol_update) ||
        socket_binding.UsesSameSocket(port_update) ||
        socket_binding.UsesSameSocket(address_update) ||
        socket_binding.UsesSameSocket(tag_update)) {
        return 6;
    }

    acpp::net::io_context io_context;
    acpp::proxyman::inbound::TcpWorker worker("test-inbound");
    auto* acceptor = worker.CreateAcceptor("stable-listener", io_context);
    if (!acceptor || worker.FindAcceptor("stable-listener") != acceptor) return 7;

    acpp::IoErrorCode ec;
    acceptor->open(acpp::tcp::v4(), ec);
    if (ec || !acceptor->is_open()) return 8;

    if (worker.CreateAcceptor("stable-listener", io_context) != nullptr) return 9;
    if (worker.FindAcceptor("stable-listener") != acceptor ||
        !acceptor->is_open()) return 10;

    worker.CloseAcceptor("stable-listener");
    if (worker.FindAcceptor("stable-listener") != nullptr) return 11;

    return 0;
}
