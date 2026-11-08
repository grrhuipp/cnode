#include <gtest/gtest.h>

#include "tls_policy.hpp"

TEST(InboundTlsPolicy, Contract) {
    ::api::NodeInfo node;

    ::PanelConfig panel;
    ASSERT_FALSE((::controller::ShouldEnableInboundTls(panel, node)));
    node.EnableTLS = true;
    ASSERT_FALSE((::controller::ShouldEnableInboundTls(panel, node)));

    panel.TLSEnable = true;
    ASSERT_FALSE((!::controller::ShouldEnableInboundTls(panel, node)));

    node.EnableTLS = false;
    ASSERT_FALSE((::controller::ShouldEnableInboundTls(panel, node)));

    node.NodeType = "anytls";
    ASSERT_FALSE((!::controller::ShouldEnableInboundTls(panel, node)));

    panel.TLSEnable = false;
    ASSERT_FALSE((::controller::ShouldEnableInboundTls(panel, node)));

    node.NodeType = "trojan";
    panel.TLSEnable = true;
    ASSERT_FALSE((!::controller::ShouldEnableInboundTls(panel, node)));

    panel.TLSEnable = false;
    ASSERT_FALSE((::controller::ShouldEnableInboundTls(panel, node)));

}
