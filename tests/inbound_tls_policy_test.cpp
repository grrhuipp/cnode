#include "tls_policy.hpp"

int main() {
    acpp::api::NodeInfo node;

    acpp::PanelConfig panel;
    if (acpp::controller::ShouldEnableInboundTls(panel, node)) return 1;
    node.EnableTLS = true;
    if (acpp::controller::ShouldEnableInboundTls(panel, node)) return 2;

    panel.TLSEnable = true;
    if (!acpp::controller::ShouldEnableInboundTls(panel, node)) return 3;

    node.EnableTLS = false;
    if (acpp::controller::ShouldEnableInboundTls(panel, node)) return 4;

    node.NodeType = "anytls";
    if (!acpp::controller::ShouldEnableInboundTls(panel, node)) return 5;

    panel.TLSEnable = false;
    if (acpp::controller::ShouldEnableInboundTls(panel, node)) return 6;

    node.NodeType = "trojan";
    panel.TLSEnable = true;
    if (!acpp::controller::ShouldEnableInboundTls(panel, node)) return 7;

    panel.TLSEnable = false;
    if (acpp::controller::ShouldEnableInboundTls(panel, node)) return 8;

    return 0;
}
