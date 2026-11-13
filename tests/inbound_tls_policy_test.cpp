#include <gtest/gtest.h>

#include "controller/node_transaction.hpp"
namespace {
struct TlsCase { const char* protocol; bool panel; bool node; bool enabled; };
class InboundTlsPolicy : public testing::TestWithParam<TlsCase> {};

TEST_P(InboundTlsPolicy, RequiresPanelPermissionAndProtocolTls) {
    const auto& item = GetParam();
    ::api::NodeInfo node;
    node.NodeType = item.protocol;
    node.EnableTLS = item.node;
    ::infra::PanelConfig panel;
    panel.TLSEnable = item.panel;
    EXPECT_EQ(::controller::ShouldEnableInboundTls(panel, node), item.enabled);
}

INSTANTIATE_TEST_SUITE_P(Protocols, InboundTlsPolicy, testing::Values(
    TlsCase{"vless", false, false, false}, TlsCase{"vless", false, true, false},
    TlsCase{"vless", true, false, false}, TlsCase{"vless", true, true, true},
    TlsCase{"anytls", false, false, false}, TlsCase{"anytls", true, false, true},
    TlsCase{"trojan", false, false, false}, TlsCase{"trojan", true, false, true}));
}  // namespace
