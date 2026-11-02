#include "acppnode/transport/internet/stream_settings.hpp"

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <new>
#include <stdexcept>
#include <type_traits>

namespace {
thread_local std::ptrdiff_t fail_after = -1;
}

void* operator new(std::size_t size) {
    if (fail_after == 0) throw std::bad_alloc();
    if (fail_after > 0) --fail_after;
    if (void* memory = std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* memory, const std::nothrow_t&) noexcept {
    ::operator delete(memory);
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete[](void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
void operator delete[](void* memory, std::size_t) noexcept { std::free(memory); }

namespace {
using namespace acpp;
static_assert(std::is_nothrow_move_assignable_v<StreamSettings>);

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

bool Same(const StreamSettings& a, const StreamSettings& b) {
    return a.network == b.network && a.security == b.security &&
        a.network_mode == b.network_mode && a.security_mode == b.security_mode && a.flags == b.flags &&
        a.http.force_http2 == b.http.force_http2 && a.tls.min_version == b.tls.min_version &&
        a.tls.max_version == b.tls.max_version && a.tls.alpn == b.tls.alpn &&
        a.tls.server_name == b.tls.server_name && a.tls.allow_insecure == b.tls.allow_insecure;
}

void TestModes() {
    struct NetworkCase { const char* name; NetworkMode mode; };
    for (const auto& item : {
            NetworkCase{"", NetworkMode::Tcp}, {"TCP", NetworkMode::Tcp}, {"raw", NetworkMode::Tcp},
            {"WS", NetworkMode::Ws}, {"WebSocket", NetworkMode::Ws}, {"HTTPUpgrade", NetworkMode::HttpUpgrade},
            {"gRPC", NetworkMode::Grpc}, {"HTTP", NetworkMode::Http}, {"h2", NetworkMode::Http},
            {"XHTTP", NetworkMode::XHttp}, {"splithttp", NetworkMode::XHttp}, {"unknown", NetworkMode::Unsupported}}) {
        StreamSettings source;
        source.network = item.name;
        const auto result = NormalizeStreamSettings(source);
        Require(result.network_mode == item.mode, "network mode or alias changed");
        Require(result.IsWs() == (item.mode == NetworkMode::Ws) &&
            result.IsHttpUpgrade() == (item.mode == NetworkMode::HttpUpgrade) &&
            result.IsGrpc() == (item.mode == NetworkMode::Grpc) &&
            result.IsHttp() == (item.mode == NetworkMode::Http) &&
            result.IsXHttp() == (item.mode == NetworkMode::XHttp), "mode flags disagree");
        Require(Same(result, NormalizeStreamSettings(result)), "normalization must be idempotent");
        Require(source.network == item.name, "mode normalization changed its source");
    }
    struct SecurityCase { const char* name; SecurityMode mode; };
    for (const auto& item : {SecurityCase{"", SecurityMode::None}, {"NONE", SecurityMode::None},
                            {"TLS", SecurityMode::Tls}, {"Reality", SecurityMode::Reality},
                            {"unknown", SecurityMode::Unsupported}}) {
        StreamSettings source;
        source.security = item.name;
        const auto result = NormalizeStreamSettings(source);
        Require(result.security_mode == item.mode && result.IsTls() == (item.mode == SecurityMode::Tls) &&
            result.IsReality() == (item.mode == SecurityMode::Reality), "security mode or flags changed");
        if (item.mode == SecurityMode::Reality) {
            Require(result.tls.min_version == TlsVersion::V1_3 && result.tls.max_version == TlsVersion::V1_3,
                "Reality must constrain TLS version");
        }
    }
}

void TestAlpnAndDefaults() {
    struct AlpnCase { const char* network; const char* security; const char* mode; bool h2; };
    for (const auto& item : {AlpnCase{"grpc", "tls", "", true}, {"grpc", "none", "", false},
                            {"h2", "none", "", true}, {"http", "none", "", false},
                            {"http", "tls", "", true}, {"xhttp", "none", "auto", true},
                            {"xhttp", "none", "packet-up", false}, {"xhttp", "tls", "packet-up", true},
                            {"xhttp", "reality", "auto", false}}) {
        StreamSettings source;
        source.network = item.network;
        source.security = item.security;
        source.xhttp.mode = item.mode;
        const auto result = NormalizeStreamSettings(source);
        Require(result.tls.alpn == (item.h2 ? std::vector<std::string>{"h2"} : std::vector<std::string>{}),
            "transport ALPN defaults changed");
    }
    StreamSettings source;
    source.network = "grpc";
    source.security = "tls";
    source.tls.alpn = {"http/1.1"};
    auto result = NormalizeStreamSettings(source);
    Require(result.tls.alpn == std::vector<std::string>{"h2", "http/1.1"}, "gRPC must preserve explicit ALPN entries");
    source.network = "http";
    Require(NormalizeStreamSettings(source).tls.alpn == source.tls.alpn, "HTTP must preserve explicit ALPN selection");

    const std::vector<std::string> default_alpn{"custom"};
    const OutboundStreamDefaults defaults{true, "fallback.example", true, default_alpn};
    source = {};
    source.network.clear();
    source.security.clear();
    result = NormalizeOutboundStreamSettings(source, defaults);
    Require(result.network == "tcp" && result.security == "tls" && result.IsTls() &&
        result.tls.server_name == "fallback.example" && result.tls.allow_insecure &&
        result.tls.alpn == default_alpn, "outbound defaults were not applied");
    Require(source.network.empty() && source.security.empty() && source.tls.alpn.empty(), "outbound defaults changed source");
    source.network = "grpc";
    result = NormalizeOutboundStreamSettings(source, defaults);
    Require(result.tls.alpn == std::vector<std::string>{"h2"}, "transport ALPN must take precedence over fallback ALPN");
    source = {};
    source.tls.server_name = "explicit.example";
    source.tls.alpn = {"explicit"};
    result = NormalizeOutboundStreamSettings(source, defaults);
    Require(result.tls.server_name == source.tls.server_name && result.tls.alpn == source.tls.alpn,
        "outbound fallback replaced explicit TLS settings");
    Require(Same(result, NormalizeOutboundStreamSettings(result, defaults)), "outbound normalization must be idempotent");
}

template <typename Normalize>
std::ptrdiff_t TestFailures(const StreamSettings& source, Normalize normalize) {
    const auto original = source;
    const auto expected = normalize(source);
    StreamSettings published;
    published.network = "previous-value";
    const auto previous = published;
    for (std::ptrdiff_t limit = 1; limit < 512; ++limit) {
        bool completed = false;
        fail_after = limit;
        try { published = normalize(source); completed = true; }
        catch (const std::bad_alloc&) {}
        fail_after = -1;
        Require(Same(source, original), "failed normalization changed its source");
        if (completed) {
            Require(Same(published, expected) && limit > 0, "normalization failure fixture did not reach allocation boundaries");
            return limit;
        }
        Require(Same(published, previous), "failed normalization partially replaced the caller's value");
    }
    throw std::runtime_error("normalization never completed after allocation failures");
}

void TestQueries() {
    XHttpConfig xhttp;
    xhttp.path = "demo?x=1";
    Require(xhttp.NormalizedPath() == "/demo/", "XHTTP path normalization changed");
    xhttp.mode = "stream-up";
    Require(xhttp.AcceptsStreamOne() && xhttp.AcceptsStreamUp() && !xhttp.AcceptsPacketUp() && !xhttp.IsStreamOne(),
        "XHTTP mode predicates changed");
    GrpcConfig grpc;
    grpc.service_name = "service";
    Require(grpc.RequestPath() == "/service/Tun", "gRPC request path changed");
    grpc.multi_mode = true;
    Require(grpc.RequestPath() == "/service/TunMulti", "gRPC multiplexed path changed");
}
}

int main() {
    std::set_terminate([] {
        std::fputs("stream normalization terminated instead of reporting allocation failure\n", stderr);
        std::_Exit(71);
    });
    try {
        TestModes();
        TestAlpnAndDefaults();
        TestQueries();
        StreamSettings source;
        source.network = "gRPC";
        source.security = "tLS";
        source.tls.server_name = std::string(64, 'a');
        source.tls.alpn = {"http/1.1"};
        std::cout << "stream_settings_test: ok\n";
    } catch (const std::exception& error) {
        fail_after = -1;
        std::cerr << error.what() << '\n';
        return 1;
    }
}
