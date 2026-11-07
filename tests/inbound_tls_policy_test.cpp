#include <gtest/gtest.h>

#include "tls_policy.hpp"

TEST(InboundTlsPolicy, Contract) {
    acpp::api::NodeInfo node;

    acpp::PanelConfig panel;
    ASSERT_FALSE((acpp::controller::ShouldEnableInboundTls(panel, node)));
    node.EnableTLS = true;
    ASSERT_FALSE((acpp::controller::ShouldEnableInboundTls(panel, node)));

    panel.TLSEnable = true;
    ASSERT_FALSE((!acpp::controller::ShouldEnableInboundTls(panel, node)));

    node.EnableTLS = false;
    ASSERT_FALSE((acpp::controller::ShouldEnableInboundTls(panel, node)));

    node.NodeType = "anytls";
    ASSERT_FALSE((!acpp::controller::ShouldEnableInboundTls(panel, node)));

    panel.TLSEnable = false;
    ASSERT_FALSE((acpp::controller::ShouldEnableInboundTls(panel, node)));

    node.NodeType = "trojan";
    panel.TLSEnable = true;
    ASSERT_FALSE((!acpp::controller::ShouldEnableInboundTls(panel, node)));

    panel.TLSEnable = false;
    ASSERT_FALSE((acpp::controller::ShouldEnableInboundTls(panel, node)));

}
