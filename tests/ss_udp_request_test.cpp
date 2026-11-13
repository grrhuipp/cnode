#include <gtest/gtest.h>

#include "proxy/shadowsocks/ss_outbound.hpp"
#include "app/dns/dns.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/co_spawn.hpp>
#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <vector>

namespace {
using namespace std::chrono_literals;
using UdpRequest = proxy::SsUdpRequest;

struct ClassicCipher {
    proxy::SsCipherInfo info;
    proxy::KeyBytes key;
};

enum class Noise { ReadGarbage, IdleWrongPeer, IdleGarbage };

class SsUdpRequestFixture : public testing::Test {
protected:
    net::io_context io;
    app::DNSWorker dns_worker{
        io, app::DnsConfig{.servers = {{net::ip::address_v4::loopback(), 53}}}, 8};
    app::DNS dns{dns_worker};
    std::optional<ClassicCipher> cipher;
    std::vector<std::shared_ptr<UdpRequest>> requests;

    void ConfigureCipher(const char* method) {
        const auto info = proxy::ParseCipherMethod(method);
        ASSERT_TRUE(info.has_value());
        cipher.emplace(ClassicCipher{
            *info, proxy::DeriveKey("ss-udp-request-regression", info->key_size)});
    }

    UdpRequest& Request(const udp::endpoint& server) {
        requests.push_back(std::make_shared<UdpRequest>(
            io, dns, net::ip::address_v4::loopback(),
            common::TargetAddress(server.address(), server.port()), cipher->info, cipher->key,
            std::span<const proxy::KeyBytes>{}));
        return *requests.back();
    }

    template <typename Task>
    void Run(Task task) {
        std::exception_ptr failure;
        bool done = false;
        bool expired = false;
        net::cancellation_signal cancellation;
        net::steady_timer watchdog(io, 12s);
        auto cancel_requests = [&] {
            for (const auto& request : requests) request->RelayControl().Cancel();
        };
        watchdog.async_wait([&](const IoErrorCode& error) {
            if (!error) {
                expired = true;
                cancel_requests();
                cancellation.emit(net::cancellation_type::all);
            }
        });
        net::co_spawn(io, task(), net::bind_cancellation_slot(cancellation.slot(),
            [&](std::exception_ptr error) {
                failure = error;
                done = true;
                cancel_requests();
                watchdog.cancel();
            }));
        io.run();
        EXPECT_TRUE(done);
        EXPECT_FALSE(expired) << "request did not finish within its watchdog";
        if (failure) std::rethrow_exception(failure);
    }
};

class SsUdpRequestTest : public SsUdpRequestFixture,
                         public testing::WithParamInterface<const char*> {
    void SetUp() override { ConfigureCipher(GetParam()); }
};

using NoiseParam = std::tuple<const char*, Noise>;

class SsUdpNoiseTest : public SsUdpRequestFixture,
                       public testing::WithParamInterface<NoiseParam> {
    void SetUp() override { ConfigureCipher(std::get<0>(GetParam())); }
};


std::vector<uint8_t> Pattern(size_t size, uint8_t seed = 17) {
    std::vector<uint8_t> bytes(size);
    for (size_t i = 0; i < size; ++i)
        bytes[i] = static_cast<uint8_t>(seed + i * 29);
    return bytes;
}

common::MultiBuffer MakePayload(
    const common::TargetAddress& target, const std::vector<uint8_t>& bytes) {
    common::MultiBuffer payload;
    EXPECT_TRUE(common::AppendSpanToMultiBuffer(bytes, payload));
    for (auto* buffer : payload) buffer->SetUDP(target);
    return payload;
}

std::vector<uint8_t> Flatten(const common::MultiBuffer& payload) {
    std::vector<uint8_t> bytes;
    bytes.reserve(payload.byte_size());
    for (const auto* buffer : payload) {
        const auto part = buffer->Bytes();
        bytes.insert(bytes.end(), part.begin(), part.end());
    }
    return bytes;
}

std::vector<uint8_t> EncodeClassic(
    const common::TargetAddress& target,
    const std::vector<uint8_t>& payload,
    const ClassicCipher& cipher) {
    const size_t size = proxy::EncodeUdpPacketTo(
        target, payload.data(), payload.size(), cipher.key.span(),
        cipher.info.type, cipher.info.key_size, cipher.info.salt_size, nullptr, 0);
    EXPECT_NE(size, 0u);
    std::vector<uint8_t> packet(size);
    EXPECT_EQ(proxy::EncodeUdpPacketTo(
                  target, payload.data(), payload.size(), cipher.key.span(),
                  cipher.info.type, cipher.info.key_size, cipher.info.salt_size,
                  packet.data(), packet.size()), packet.size());
    return packet;
}

net::awaitable<void> Pause(net::io_context& io, std::chrono::milliseconds delay) {
    net::steady_timer timer(io, delay);
    co_await timer.async_wait(net::use_awaitable);
}

net::awaitable<udp::endpoint> SendOneAndGetClientEndpoint(
    UdpRequest& request, udp::socket& server) {
    const auto inner_target = common::TargetAddress(net::ip::address_v4::loopback(), 5353);
    co_await request.WriteMultiBuffer(MakePayload(inner_target, Pattern(48)));
    std::array<uint8_t, 65535> packet{};
    udp::endpoint client_endpoint;
    (void)co_await server.async_receive_from(
        net::buffer(packet), client_endpoint, net::use_awaitable);
    co_return client_endpoint;
}

struct ReadNoiseState {
    bool read_done = false;
    bool noise_done = false;
    bool stop_noise = false;
    bool watchdog_fired = false;
    std::exception_ptr read_error;
    std::exception_ptr noise_error;
    common::MultiBuffer received;
    size_t noise_packets = 0;
};

net::awaitable<void> SendNoise(
    net::io_context& io,
    udp::socket& sender,
    udp::endpoint destination,
    std::vector<uint8_t> packet,
    ReadNoiseState& state) {
    while (!state.stop_noise) {
        IoErrorCode error;
        (void)co_await sender.async_send_to(net::buffer(packet), destination,
            net::redirect_error(net::use_awaitable, error));
        if (error) {
            if (!state.stop_noise) throw IoSystemError(error);
            break;
        }
        ++state.noise_packets;
        co_await Pause(io, 12ms);
    }
}

TEST_P(SsUdpRequestTest, AuthenticatedRoundTripPreservesPayloadAndInnerTarget) {
    Run([&]() -> net::awaitable<void> {
        udp::socket server(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
        auto& request = Request(server.local_endpoint());
        const auto& key = *cipher;
        const common::TargetAddress inner_target(net::ip::address_v4::loopback(), 5300);
        const auto request_bytes = Pattern(73, 4);
        co_await request.WriteMultiBuffer(MakePayload(inner_target, request_bytes));

        std::array<uint8_t, 65535> wire{};
        udp::endpoint client;
        const auto wire_size = co_await server.async_receive_from(
            net::buffer(wire), client, net::use_awaitable);
        const auto decoded = proxy::DecodeUdpPacketWithKey(
            wire.data(), wire_size, key.key.span(), key.info.type,
            key.info.key_size, key.info.salt_size);
        EXPECT_TRUE(decoded.has_value());
        if (decoded) {
            EXPECT_TRUE(decoded->target.SameEndpoint(inner_target));
            EXPECT_EQ(Flatten(decoded->payload), request_bytes);
        }

        const common::TargetAddress response_target(net::ip::address_v4::loopback(), 6400);
        const auto response_bytes = Pattern(91, 33);
        const auto response = EncodeClassic(response_target, response_bytes, key);
        co_await server.async_send_to(net::buffer(response), client, net::use_awaitable);
        auto reply = co_await request.ReadMultiBuffer();
        const auto datagram = common::InspectUdpDatagram(reply);
        EXPECT_TRUE(datagram.Valid());
        EXPECT_NE(datagram.target, nullptr);
        if (datagram.target) EXPECT_TRUE(datagram.target->SameEndpoint(response_target));
        EXPECT_EQ(Flatten(reply), response_bytes);
    });
}

TEST_P(SsUdpNoiseTest, RejectedPacketsCannotSatisfyReadOrRefreshItsTimeout) {
    Run([&]() -> net::awaitable<void> {
        udp::socket server(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
        udp::socket wrong_source(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
        auto& request = Request(server.local_endpoint());
        const auto mode = std::get<1>(GetParam());
        const bool read_timeout = mode == Noise::ReadGarbage;
        const bool wrong_peer = mode == Noise::IdleWrongPeer;
        if (read_timeout) request.RelayControl().SetReadTimeout(1s);
        else request.RelayControl().SetIdleTimeout(1s);
        const auto client = co_await SendOneAndGetClientEndpoint(request, server);
        const auto packet = wrong_peer
            ? EncodeClassic(common::TargetAddress(net::ip::address_v4::loopback(), 8123),
                            Pattern(36, 92), *cipher)
            : std::vector<uint8_t>(64, 0xa7);
        // Validate the stimulus: a wrong-peer packet authenticates, while
        // same-peer garbage must fail authentication.
        const auto decoded = proxy::DecodeUdpPacketWithKey(
            packet.data(), packet.size(), cipher->key.span(), cipher->info.type,
            cipher->info.key_size, cipher->info.salt_size);
        EXPECT_EQ(decoded.has_value(), wrong_peer);

        // Once children are running, cancellation must not skip their joins.
        // The local watchdog cancels the request and stops noise independently.
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        ReadNoiseState state;
        auto& sender = wrong_peer ? wrong_source : server;
        const auto started = std::chrono::steady_clock::now();
        net::steady_timer watchdog(io, 4s);
        watchdog.async_wait([&](const IoErrorCode& error) {
            if (!error) {
                state.watchdog_fired = true;
                state.stop_noise = true;
                request.RelayControl().Cancel();
                IoErrorCode ignored;
                sender.cancel(ignored);
            }
        });
        net::co_spawn(io, request.ReadMultiBuffer(),
            [&](std::exception_ptr error, common::MultiBuffer payload) {
                state.read_error = error;
                state.received = std::move(payload);
                state.read_done = true;
            });
        net::co_spawn(io, SendNoise(io, sender, client, packet, state),
            [&](std::exception_ptr error) {
                state.noise_error = error;
                state.noise_done = true;
            });
        while (!state.read_done) co_await Pause(io, 4ms);
        state.stop_noise = true;
        while (!state.noise_done) co_await Pause(io, 4ms);
        watchdog.cancel();

        EXPECT_FALSE(state.watchdog_fired);
        EXPECT_TRUE(state.received.empty());
        EXPECT_GE(state.noise_packets, 10u);
        if (state.noise_error) std::rethrow_exception(state.noise_error);
        EXPECT_NE(state.read_error, nullptr);
        if (state.read_error) {
            try { std::rethrow_exception(state.read_error); }
            catch (const transport::LinkError& error) {
                EXPECT_EQ(error.code(), common::ErrorCode::CANCELLED);
            }
        }
        const auto elapsed = std::chrono::steady_clock::now() - started;
        EXPECT_GE(elapsed, 800ms);
        EXPECT_LT(elapsed, 3s);
        if (read_timeout) EXPECT_TRUE(request.RelayControl().ConsumeReadTimeout());
        else EXPECT_TRUE(request.RelayControl().ConsumeIdleTimeout());
    });
}

TEST_P(SsUdpRequestTest, OversizedWirePayloadIsRejectedWithoutSendingAndValidWriteRecovers) {
    Run([&]() -> net::awaitable<void> {
        udp::socket server(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
        auto& request = Request(server.local_endpoint());
        const auto& key = *cipher;
        const common::TargetAddress inner_target(net::ip::address_v4::loopback(), 5353);
        bool rejected = false;
        try {
            co_await request.WriteMultiBuffer(
                MakePayload(inner_target, Pattern(65507, 8)));
        } catch (const transport::LinkError& error) {
            rejected = true;
            EXPECT_EQ(error.code(), common::ErrorCode::INVALID_ARGUMENT);
        }
        EXPECT_TRUE(rejected);
        IoErrorCode error;
        EXPECT_EQ(server.available(error), 0u);
        EXPECT_FALSE(error);

        const auto valid_bytes = Pattern(29, 114);
        co_await request.WriteMultiBuffer(MakePayload(inner_target, valid_bytes));
        std::array<uint8_t, 65535> wire{};
        udp::endpoint source;
        const auto wire_size = co_await server.async_receive_from(
            net::buffer(wire), source, net::use_awaitable);
        const auto decoded = proxy::DecodeUdpPacketWithKey(
            wire.data(), wire_size, key.key.span(), key.info.type,
            key.info.key_size, key.info.salt_size);
        EXPECT_TRUE(decoded.has_value());
        if (decoded) {
            EXPECT_TRUE(decoded->target.SameEndpoint(inner_target));
            EXPECT_EQ(Flatten(decoded->payload), valid_bytes);
        }
    });
}

std::string CipherName(const char* method) {
    std::string name(method);
    for (auto& character : name) if (character == '-') character = '_';
    return name;
}

INSTANTIATE_TEST_SUITE_P(ClassicCiphers, SsUdpRequestTest,
    testing::Values("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"),
    [](const testing::TestParamInfo<const char*>& info) {
        return CipherName(info.param);
    });

INSTANTIATE_TEST_SUITE_P(CipherAndNoiseModes, SsUdpNoiseTest,
    testing::Combine(
        testing::Values("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"),
        testing::Values(Noise::ReadGarbage, Noise::IdleWrongPeer, Noise::IdleGarbage)),
    [](const testing::TestParamInfo<NoiseParam>& info) {
        const char* mode = "";
        switch (std::get<1>(info.param)) {
        case Noise::ReadGarbage: mode = "ReadBudgetWithUnauthenticatedPeer"; break;
        case Noise::IdleWrongPeer: mode = "IdleWithAuthenticatedWrongPeer"; break;
        case Noise::IdleGarbage: mode = "IdleWithUnauthenticatedPeer"; break;
        }
        return CipherName(std::get<0>(info.param)) + "_" + mode;
    });
}  // namespace
