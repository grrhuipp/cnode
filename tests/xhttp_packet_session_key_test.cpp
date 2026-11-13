#include <gtest/gtest.h>

#include "transport/xhttp_session.hpp"
#include <cstdlib>
#include <unordered_map>

TEST(XhttpPacketSessionKey, IsolatesSessionIdsAndInboundNamespaces) {
    using Key = ::transport::XHttpPacketSessionKey;
    using Map = std::unordered_map<
        Key,
        int,
        ::transport::XHttpPacketSessionKeyHash,
        ::transport::XHttpPacketSessionKeyEq>;
    Map sessions;

    Key first{.session_id = "shared-session", .session_namespace = "inbound-a"};
    Key second{.session_id = "second-session", .session_namespace = "inbound-a"};
    Key other_namespace{.session_id = "shared-session", .session_namespace = "inbound-b"};
    sessions.emplace(std::move(first), 1);
    sessions.emplace(std::move(second), 2);
    sessions.emplace(std::move(other_namespace), 3);

    const auto first_it = sessions.find(::transport::XHttpPacketSessionKeyRef{
        "shared-session", "inbound-a"});
    const auto second_it = sessions.find(::transport::XHttpPacketSessionKeyRef{
        "second-session", "inbound-a"});
    const auto other_it = sessions.find(::transport::XHttpPacketSessionKeyRef{
        "shared-session", "inbound-b"});
    ASSERT_EQ(sessions.size(), 3u);
    ASSERT_NE(first_it, sessions.end());
    ASSERT_NE(second_it, sessions.end());
    ASSERT_NE(other_it, sessions.end());
    EXPECT_EQ(first_it->second, 1);
    EXPECT_EQ(second_it->second, 2);
    EXPECT_EQ(other_it->second, 3);
}
