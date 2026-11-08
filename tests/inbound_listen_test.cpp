#include <gtest/gtest.h>

#include "transport/internet/inbound_listen.hpp"
#include "worker/tcp_listener.hpp"

#include <array>
#include <chrono>
#include <string_view>

TEST(InboundListen, Contract) {
    for (const auto value : std::array<std::string_view, 2>{"", "auto"}) {
        auto listen = ::InboundListen::Parse(value);
        ASSERT_FALSE((!listen || !listen->IsAuto() || listen->Candidates().size() != 2 ||
            !listen->Candidates()[0].is_v4() || !listen->Candidates()[0].is_unspecified() ||
            !listen->Candidates()[1].is_v6() || !listen->Candidates()[1].is_unspecified()));
    }

    auto ipv4 = ::InboundListen::Parse("127.0.0.1");
    ASSERT_FALSE((!ipv4 || ipv4->IsAuto() || ipv4->Candidates().size() != 1 ||
        !ipv4->Candidates()[0].is_v4() || !ipv4->Candidates()[0].is_loopback()));

    auto ipv6 = ::InboundListen::Parse("::1");
    ASSERT_FALSE((!ipv6 || ipv6->IsAuto() || ipv6->Candidates().size() != 1 ||
        !ipv6->Candidates()[0].is_v6() || !ipv6->Candidates()[0].is_loopback()));

    auto mapped = ::InboundListen::Parse("::ffff:127.0.0.1");
    ASSERT_FALSE((!mapped || mapped->Candidates().size() != 1 ||
        !mapped->Candidates()[0].is_v4() || !mapped->Candidates()[0].is_loopback()));

    for (const auto value :
         std::array<std::string_view, 3>{"not-an-ip", "127.0.0.1junk", " auto"}) {
        ASSERT_FALSE((::InboundListen::Parse(value)));
    }
    auto upper = ::InboundListen::Parse("AUTO");
    ASSERT_FALSE((!upper || !upper->IsAuto()));

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
        const auto left = ::InboundListen::Parse(item.left);
        const auto right = ::InboundListen::Parse(item.right);
        ASSERT_FALSE((!left || !right || left->Overlaps(*right) != item.overlaps ||
            right->Overlaps(*left) != item.overlaps));
    }

    for (const auto value : std::array<std::string_view, 7>{"127.0.0.1:9", "[127.0.0.1]", "[::1]", "127.0.0.1 ",
             "fe80::1%invalid", std::string_view("127.0.0.1\0ignored", 17),
             std::string_view("::1\0ignored", 11)}) {
        ASSERT_FALSE((::InboundListen::Parse(value)));
    }

    ::net::io_context io_context;
    ::worker_detail::TcpListenerOwner worker;
    auto acceptor = worker.CreateAcceptor("stable-listener", io_context);
    ASSERT_FALSE((!acceptor || !worker.OwnsAcceptor("stable-listener", acceptor.get())));

    ::IoErrorCode ec;
    acceptor->open(::tcp::v4(), ec);
    ASSERT_FALSE((ec || !acceptor->is_open()));
    acceptor->bind(
        ::tcp::endpoint(::net::ip::address_v4::loopback(), 0), ec);
    ASSERT_FALSE((ec));
    acceptor->listen(::net::socket_base::max_listen_connections, ec);
    ASSERT_FALSE((ec));

    ASSERT_FALSE((worker.CreateAcceptor("stable-listener", io_context) != nullptr));
    ASSERT_FALSE((!worker.OwnsAcceptor("stable-listener", acceptor.get()) ||
        !acceptor->is_open()));

    bool accept_cancelled = false;
    acceptor->async_accept(
        [&](::IoErrorCode accept_ec, ::tcp::socket) {
            accept_cancelled =
                accept_ec == ::io_error::operation_aborted;
        });

    worker.CloseAcceptor("stable-listener");
    ASSERT_FALSE((!acceptor || acceptor->is_open() ||
        worker.OwnsAcceptor("stable-listener", acceptor.get())));
    io_context.run();
    ASSERT_FALSE((!accept_cancelled));
    ::worker_detail::TcpListenerOwner::AcceptorPtr retained;
    bool retired_accept_cancelled = false;
    {
        ::worker_detail::TcpListenerOwner retiring;
        retained = retiring.CreateAcceptor("retained-until-completion", io_context);
        retained->open(::tcp::v4(), ec);
        ASSERT_FALSE((ec));
        retained->bind(
            ::tcp::endpoint(::net::ip::address_v4::loopback(), 0), ec);
        ASSERT_FALSE((ec));
        retained->listen(::net::socket_base::max_listen_connections, ec);
        ASSERT_FALSE((ec));
        retained->async_accept(
            [&](::IoErrorCode error, ::tcp::socket) {
                retired_accept_cancelled = error == ::io_error::operation_aborted;
            });
    }
    io_context.restart();
    io_context.run_for(std::chrono::milliseconds(500));
    ASSERT_FALSE((!retired_accept_cancelled || retained->is_open()));

}
