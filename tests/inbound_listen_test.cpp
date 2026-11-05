#include "acppnode/transport/internet/inbound_listen.hpp"
#include "worker/tcp_listener.hpp"

#include <array>
#include <chrono>
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

    struct OverlapCase { std::string_view left, right; bool overlaps; };
    for (const auto& item : std::array{
             OverlapCase{"127.0.0.1", "127.0.0.1", true},
             OverlapCase{"127.0.0.1", "127.0.0.2", false},
             OverlapCase{"0.0.0.0", "127.0.0.1", true},
             OverlapCase{"::", "::1", true},
             OverlapCase{"::1", "127.0.0.1", false},
             OverlapCase{"::", "0.0.0.0", false},
             OverlapCase{"auto", "127.0.0.1", true},
             OverlapCase{"auto", "::1", true},
             OverlapCase{"auto", "auto", true},
             OverlapCase{"::ffff:127.0.0.1", "127.0.0.1", true},
             OverlapCase{"fe80::1%1", "fe80::1%2", false}}) {
        const auto left = acpp::InboundListen::Parse(item.left);
        const auto right = acpp::InboundListen::Parse(item.right);
        if (!left || !right || left->Overlaps(*right) != item.overlaps ||
            right->Overlaps(*left) != item.overlaps) return 16;
    }

    for (const auto value : std::array<std::string_view, 7>{"127.0.0.1:9", "[127.0.0.1]", "[::1]", "127.0.0.1 ",
             "fe80::1%invalid", std::string_view("127.0.0.1\0ignored", 17),
             std::string_view("::1\0ignored", 11)}) {
        if (acpp::InboundListen::Parse(value)) return 20;
    }

    acpp::net::io_context io_context;
    acpp::worker_detail::TcpListenerOwner worker;
    auto acceptor = worker.CreateAcceptor("stable-listener", io_context);
    if (!acceptor || !worker.OwnsAcceptor("stable-listener", acceptor.get())) return 7;

    acpp::IoErrorCode ec;
    acceptor->open(acpp::tcp::v4(), ec);
    if (ec || !acceptor->is_open()) return 8;
    acceptor->bind(
        acpp::tcp::endpoint(acpp::net::ip::address_v4::loopback(), 0), ec);
    if (ec) return 9;
    acceptor->listen(acpp::net::socket_base::max_listen_connections, ec);
    if (ec) return 10;

    if (worker.CreateAcceptor("stable-listener", io_context) != nullptr) return 11;
    if (!worker.OwnsAcceptor("stable-listener", acceptor.get()) ||
        !acceptor->is_open()) return 12;

    bool accept_cancelled = false;
    acceptor->async_accept(
        [&](acpp::IoErrorCode accept_ec, acpp::tcp::socket) {
            accept_cancelled =
                accept_ec == acpp::io_error::operation_aborted;
        });

    worker.CloseAcceptor("stable-listener");
    if (!acceptor || acceptor->is_open() ||
        worker.OwnsAcceptor("stable-listener", acceptor.get())) return 14;
    io_context.run();
    if (!accept_cancelled) return 15;
    acpp::worker_detail::TcpListenerOwner::AcceptorPtr retained;
    bool retired_accept_cancelled = false;
    {
        acpp::worker_detail::TcpListenerOwner retiring;
        retained = retiring.CreateAcceptor("retained-until-completion", io_context);
        retained->open(acpp::tcp::v4(), ec);
        if (ec) return 16;
        retained->bind(
            acpp::tcp::endpoint(acpp::net::ip::address_v4::loopback(), 0), ec);
        if (ec) return 17;
        retained->listen(acpp::net::socket_base::max_listen_connections, ec);
        if (ec) return 18;
        retained->async_accept(
            [&](acpp::IoErrorCode error, acpp::tcp::socket) {
                retired_accept_cancelled = error == acpp::io_error::operation_aborted;
            });
    }
    io_context.restart();
    io_context.run_for(std::chrono::milliseconds(500));
    if (!retired_accept_cancelled || retained->is_open()) return 19;

    return 0;
}
