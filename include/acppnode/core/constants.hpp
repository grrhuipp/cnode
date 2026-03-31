#pragma once

#include <cstdint>
#include <string_view>

namespace acpp::constants {

namespace paths {
inline constexpr std::string_view kDefaultConfigFile = "config.json";
inline constexpr std::string_view kInboundFile = "inbound.json";
inline constexpr std::string_view kOutboundFile = "outbound.json";
inline constexpr std::string_view kRouteFile = "route.json";
inline constexpr std::string_view kGeoIpFile = "geoip.dat";
inline constexpr std::string_view kGeoSiteFile = "geosite.dat";
inline constexpr std::string_view kDefaultLogDir = "/var/log/acppnode";
}  // namespace paths

namespace logging {
inline constexpr std::string_view kDefaultLevel = "info";
}  // namespace logging

namespace network {
inline constexpr std::string_view kAnyIpv4 = "0.0.0.0";
}  // namespace network

namespace binding {
inline constexpr std::string_view kAuto = "auto";
inline constexpr std::string_view kRootPath = "/";
}  // namespace binding

namespace protocol {
inline constexpr std::string_view kTcp = "tcp";
inline constexpr std::string_view kUdp = "udp";
inline constexpr std::string_view kMux = "mux";
inline constexpr std::string_view kWs = "ws";
inline constexpr std::string_view kTls = "tls";
inline constexpr std::string_view kNone = "none";
inline constexpr std::string_view kHttp = "http";
inline constexpr std::string_view kHttps = "https";
inline constexpr std::string_view kAsIs = "AsIs";

inline constexpr std::string_view kVmess = "vmess";
inline constexpr std::string_view kDefaultNodeProtocol = kVmess;
inline constexpr std::string_view kTrojan = "trojan";
inline constexpr std::string_view kShadowsocks = "shadowsocks";
inline constexpr std::string_view kFreedom = "freedom";
inline constexpr std::string_view kBlackhole = "blackhole";
inline constexpr std::string_view kDirect = "direct";
inline constexpr std::string_view kNode = "node";

inline constexpr std::string_view kV2Board = "V2Board";
inline constexpr std::string_view kAes128Gcm = "aes-128-gcm";
inline constexpr std::string_view kAes256Gcm = "aes-256-gcm";
inline constexpr std::string_view kChacha20IetfPoly1305 = "chacha20-ietf-poly1305";
}  // namespace protocol

namespace panel {
inline constexpr std::string_view kV2BoardType = protocol::kV2Board;
inline constexpr std::string_view kDefaultNodeType = protocol::kDefaultNodeProtocol;
}  // namespace panel

namespace state {
inline constexpr std::string_view kNone = protocol::kNone;
inline constexpr std::string_view kCache = "cache";
inline constexpr std::string_view kResolve = "resolve";
inline constexpr std::string_view kFailed = "failed";
}  // namespace state

namespace test {
inline constexpr uint16_t kTestPort = 10086;
inline constexpr std::string_view kTestVmessUuid =
    "b831381d-6324-4d53-ad4f-8cda48b30811";
inline constexpr std::string_view kTestInboundTag = "test-vmess-10086";
}  // namespace test

}  // namespace acpp::constants
