#include <gtest/gtest.h>

#include "xhttp_packet_session_key.hpp"

#include <cstdlib>
#include <unordered_map>

TEST(XhttpPacketSessionKey, Contract) {
    using Key = ::detail::XHttpPacketSessionKey;
    using Map = std::unordered_map<
        Key,
        int,
        ::detail::XHttpPacketSessionKeyHash,
        ::detail::XHttpPacketSessionKeyEq>;
    Map sessions;

    Key first{.session_id = "shared-session", .session_namespace = "inbound-a"};
    Key second{.session_id = "second-session", .session_namespace = "inbound-a"};
    Key other_namespace{.session_id = "shared-session", .session_namespace = "inbound-b"};
    sessions.emplace(std::move(first), 1);
    sessions.emplace(std::move(second), 2);
    sessions.emplace(std::move(other_namespace), 3);

    const auto first_it = sessions.find(::detail::XHttpPacketSessionKeyRef{
        "shared-session", "inbound-a"});
    const auto second_it = sessions.find(::detail::XHttpPacketSessionKeyRef{
        "second-session", "inbound-a"});
    const auto other_it = sessions.find(::detail::XHttpPacketSessionKeyRef{
        "shared-session", "inbound-b"});
    if (sessions.size() != 3 || first_it == sessions.end() ||
        second_it == sessions.end() || other_it == sessions.end() ||
        first_it->second != 1 || second_it->second != 2 || other_it->second != 3) {
        { ASSERT_EQ((EXIT_FAILURE), 0); return; }
    }
    { ASSERT_EQ((EXIT_SUCCESS), 0); return; }
}
