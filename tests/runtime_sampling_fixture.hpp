#pragma once

#include "app/dns/dns_worker.hpp"
#include "app/port_binding.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "../src/app/proxyman/outbound/registration.hpp"
#include "app/stats.hpp"
#include "app/worker.hpp"
#include "app/worker_runtime_config.hpp"
#include "app/worker_stats.hpp"
#include "infra/config_types.hpp"
#include "infra/outbound_source_config.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>
#include <array>
#include <chrono>
#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// The benchmark and regression use production VLESS authentication, dispatcher,
// Freedom dialing and relay over real loopback sockets. Only the endpoint peer
// is controlled here; it verifies requests and sends a distinct response.
namespace runtime_sampling {
inline void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class Fixture final {
public:
    explicit Fixture(std::string_view protocol = "vless")
        : dns(io, app::dns::Config{.servers = {{net::ip::address_v4::loopback(), 53}}}, 8),
          worker(0, io, Configuration(), totals, dns),
          destination(io, {net::ip::address_v4::loopback(), 0}), protocol_(protocol) {}

    void Start() {
        worker.StartRuntime();
        infra::OutboundSourceConfig outbound;
        outbound.tag = "sampling-direct";
        outbound.protocol = "freedom";
        outbound.settings["domainStrategy"] = "UseIP";
        auto prepared = proxyman::outbound::PrepareOutboundConfig(outbound);
        Require(prepared.has_value(), "Freedom preparation failed");
        worker.AddOutbound(std::move(*prepared));

        auto request = proxyman::inbound::PrepareBuildRequest("vless", "sampling", InboundProtocolSettings{});
        Require(request.has_value(), "VLESS preparation failed");
        const std::array users{InboundUserSpec{
            .user_id = 1, .email = "sampling",
            .credential = "00112233-4455-6677-8899-aabbccddeeff", .flow = {}}};
        auto credentials = proxyman::inbound::BuildUsers(*request, users);
        Require(credentials.has_value(), "VLESS user preparation failed");
        using Store = proxyman::inbound::UserStore;
        worker.InstallUserView(Store::PrepareWorkerView(Store::PrepareUsers("sampling", *credentials)));
        request->protocol = protocol_;
        proxyman::inbound::ReceiverSettings receiver{
            .inbound_tag = "sampling", .inbound_tags = {}, .protocol = std::string(protocol_),
            .stream_settings = {},
            .dispatch_policy = {{}, routing::ForceOutbound{"sampling-direct"}},
            .proxy_protocol = ProxyProtocolMode::Off};
        Require(worker.RegisterInbound(std::move(*request), std::move(receiver)), "VLESS registration failed");
        tcp::acceptor reservation(io, {net::ip::address_v4::loopback(), 0});
        port = reservation.local_endpoint().port();
        reservation.close();
        const auto listen = InboundListen::Parse("127.0.0.1");
        Require(listen.has_value(), "loopback listen parsing failed");
        Require(worker.AddListener(PortBinding{.port = port, .protocol = std::string(protocol_), .tag = "sampling", .listen = *listen}),
                "VLESS listener failed");
    }

    net::awaitable<void> Open() {
        tcp::socket client(io);
        co_await client.async_connect({net::ip::address_v4::loopback(), port}, net::use_awaitable);
        const auto target = destination.local_endpoint().port();
        const std::array<unsigned char, 27> request{
            0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0, 1, static_cast<unsigned char>(target >> 8), static_cast<unsigned char>(target),
            1, 127, 0, 0, 1, 'Q'};
        co_await net::async_write(client, net::buffer(request), net::use_awaitable);
        auto peer = co_await destination.async_accept(net::use_awaitable);
        std::array<char, 1> received{};
        co_await net::async_read(peer, net::buffer(received), net::use_awaitable);
        Require(received[0] == 'Q', "VLESS request was not forwarded");
        const std::array<char, 1> response{'R'};
        co_await net::async_write(peer, net::buffer(response), net::use_awaitable);
        std::array<unsigned char, 3> reply{};
        co_await net::async_read(client, net::buffer(reply), net::use_awaitable);
        Require(reply == std::array<unsigned char, 3>{0, 0, 'R'}, "VLESS response was not forwarded");
        clients.push_back(std::move(client));
        peers.push_back(std::move(peer));
    }

    net::awaitable<void> Transfer(size_t index, size_t upload, size_t download) {
        const std::string request(upload, 'U');
        std::string received(upload, '\0');
        co_await net::async_write(clients.at(index), net::buffer(request), net::use_awaitable);
        co_await net::async_read(peers.at(index), net::buffer(received), net::use_awaitable);
        Require(received == request, "upload tail changed");
        const std::string response(download, 'D');
        received.assign(download, '\0');
        co_await net::async_write(peers.at(index), net::buffer(response), net::use_awaitable);
        co_await net::async_read(clients.at(index), net::buffer(received), net::use_awaitable);
        Require(received == response, "download tail changed");
    }

    net::awaitable<WorkerRuntimeStatsSnapshot> WaitActive(size_t expected) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (;;) {
            auto snapshot = co_await worker.CollectRuntimeStats(true);
            if (snapshot.active_connections == expected) co_return snapshot;
            Require(std::chrono::steady_clock::now() < deadline, "physical session did not retire");
            co_await net::post(net::use_awaitable);
        }
    }

    net::awaitable<void> Stop() {
        worker.RequestStop();
        co_await worker.AsyncJoin();
        clients.clear();
        peers.clear();
        destination.close();
    }

    template<class Function>
    void Run(Function function) {
        auto task = [&]() -> net::awaitable<void> {
            std::exception_ptr failure;
            try {
                Start();
                co_await function();
            } catch (...) { failure = std::current_exception(); }
            co_await Stop();
            if (failure) std::rethrow_exception(failure);
        };
        auto completed = net::co_spawn(io, task(), net::use_future);
        io.run();
        completed.get();
    }

    net::io_context io;
    app::dns::DNSWorker dns;
    StatsShard totals;
    Worker worker;
    tcp::acceptor destination;
    std::vector<tcp::socket> clients;
    std::vector<tcp::socket> peers;
private:
    static WorkerRuntimeConfig Configuration() {
        WorkerRuntimeConfig config;
        config.workers = 1;
        config.timeouts.idle = 0;
        config.timeouts.read = 0;
        return config;
    }
    uint16_t port = 0;
    std::string_view protocol_;
};
} // namespace runtime_sampling
