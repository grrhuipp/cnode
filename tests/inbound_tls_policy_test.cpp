#include "tls_policy.hpp"

int main() {
    acpp::api::NodeInfo node;

    if (acpp::controller::ShouldEnableInboundTls(nullptr, node)) return 1;
    node.EnableTLS = true;
    if (!acpp::controller::ShouldEnableInboundTls(nullptr, node)) return 2;

    acpp::PanelConfig panel;
    if (acpp::controller::ShouldEnableInboundTls(&panel, node)) return 3;

    panel.TLSEnable = true;
    if (!acpp::controller::ShouldEnableInboundTls(&panel, node)) return 4;

    node.EnableTLS = false;
    if (acpp::controller::ShouldEnableInboundTls(&panel, node)) return 5;

    node.NodeType = "anytls";
    if (!acpp::controller::ShouldEnableInboundTls(&panel, node)) return 6;

    panel.TLSEnable = false;
    if (acpp::controller::ShouldEnableInboundTls(&panel, node)) return 7;

    node.NodeType = "trojan";
    panel.TLSEnable = true;
    if (!acpp::controller::ShouldEnableInboundTls(&panel, node)) return 8;

    panel.TLSEnable = false;
    if (acpp::controller::ShouldEnableInboundTls(&panel, node)) return 9;

    return 0;
}
