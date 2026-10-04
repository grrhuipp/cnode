#include "proxy/shadowsocks/outbound/udp_request.hpp"
#include "proxy/shadowsocks/ss_udp.hpp"
#include "acppnode/app/dns/dns_worker.hpp"

#include <asio/co_spawn.hpp>
#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using namespace acpp;
using namespace std::chrono_literals;
using UdpRequest = proxy::shadowsocks::outbound::UdpRequest;

void Check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

struct Fixture {
    net::io_context io;
    app::dns::DNSWorker dns_worker{
        io, app::dns::Config{.servers = {{net::ip::address_v4::loopback(), 53}}}, 8};
    app::dns::DNS dns{dns_worker};

    void Run(net::awaitable<void> task) {
        std::exception_ptr failure;
        bool done = false;
        bool expired = false;
        net::steady_timer watchdog(io, 12s);
        watchdog.async_wait([&](const IoErrorCode& ec) {
            if (!ec) {
                expired = true;
                io.stop();
            }
        });
        net::co_spawn(io, std::move(task), [&](std::exception_ptr error) {
            failure = error;
            done = true;
            watchdog.cancel();
        });
        io.run();
        Check(done && !expired, "test task watchdog expired");
        if (failure) std::rethrow_exception(failure);
    }
};

struct ClassicCipher {
    ss::SsCipherInfo info;
    ss::KeyBytes key;
};

ClassicCipher MakeCipher() {
    const auto info = ss::ParseCipherMethod("aes-128-gcm");
    Check(info.has_value(), "aes-128-gcm is unavailable");
    return {*info, ss::DeriveKey("ss-udp-request-regression", info->key_size)};
}

TargetAddress Target(const udp::endpoint& endpoint) {
    return TargetAddress(endpoint.address(), endpoint.port());
}

std::vector<uint8_t> Pattern(size_t size, uint8_t seed = 17) {
    std::vector<uint8_t> bytes(size);
    for (size_t i = 0; i < size; ++i)
        bytes[i] = static_cast<uint8_t>(seed + i * 29);
    return bytes;
}

buf::MultiBuffer MakePayload(
    const TargetAddress& target, const std::vector<uint8_t>& bytes) {
    buf::MultiBuffer payload;
    Check(buf::AppendSpanToMultiBuffer(bytes, payload), "UDP test payload allocation failed");
    for (auto* buffer : payload) buffer->SetUDP(target);
    return payload;
}

std::vector<uint8_t> Flatten(const buf::MultiBuffer& payload) {
    std::vector<uint8_t> bytes;
    bytes.reserve(buf::TotalLen(payload));
    for (const auto* buffer : payload) {
        const auto part = buffer->Bytes();
        bytes.insert(bytes.end(), part.begin(), part.end());
    }
    return bytes;
}

std::vector<uint8_t> EncodeClassic(
    const TargetAddress& target,
    const std::vector<uint8_t>& payload,
    const ClassicCipher& cipher) {
    const size_t size = ss::EncodeUdpPacketTo(
        target, payload.data(), payload.size(), cipher.key.span(),
        cipher.info.type, cipher.info.key_size, cipher.info.salt_size, nullptr, 0);
    Check(size != 0, "Shadowsocks UDP packet size calculation failed");
    std::vector<uint8_t> packet(size);
    Check(ss::EncodeUdpPacketTo(
              target, payload.data(), payload.size(), cipher.key.span(),
              cipher.info.type, cipher.info.key_size, cipher.info.salt_size,
              packet.data(), packet.size()) == packet.size(),
          "Shadowsocks UDP packet encoding failed");
    return packet;
}

net::awaitable<void> Pause(net::io_context& io, std::chrono::milliseconds delay) {
    net::steady_timer timer(io, delay);
    co_await timer.async_wait(net::use_awaitable);
}

net::awaitable<udp::endpoint> SendOneAndGetClientEndpoint(
    UdpRequest& request, udp::socket& server) {
    const auto inner_target = TargetAddress(net::ip::address_v4::loopback(), 5353);
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
    buf::MultiBuffer received;
    size_t noise_packets = 0;
};

net::awaitable<void> SendNoise(
    net::io_context& io,
    udp::socket& sender,
    udp::endpoint destination,
    std::vector<uint8_t> packet,
    ReadNoiseState& state) {
    try {
        while (!state.stop_noise) {
            IoErrorCode ec;
            (void)co_await sender.async_send_to(
                net::buffer(packet), destination,
                net::redirect_error(net::use_awaitable, ec));
            if (ec) {
                if (!state.stop_noise) throw IoSystemError(ec);
                break;
            }
            ++state.noise_packets;
            co_await Pause(io, 12ms);
        }
    } catch (...) {
        state.noise_error = std::current_exception();
    }
}

net::awaitable<void> ReadAgainstNoise(
    Fixture& fixture,
    UdpRequest& request,
    udp::socket& sender,
    udp::endpoint destination,
    std::vector<uint8_t> noise,
    bool read_timeout) {
    ReadNoiseState state;
    const auto started = std::chrono::steady_clock::now();
    net::steady_timer watchdog(fixture.io);
    watchdog.expires_after(4s);
    watchdog.async_wait([&](const IoErrorCode& ec) {
        if (!ec) {
            state.watchdog_fired = true;
            state.stop_noise = true;
            request.Cancel();
            IoErrorCode ignored;
            sender.cancel(ignored);
        }
    });

    net::co_spawn(fixture.io, request.ReadMultiBuffer(),
        [&](std::exception_ptr error, buf::MultiBuffer payload) {
            state.read_error = error;
            state.received = std::move(payload);
            state.read_done = true;
        });
    net::co_spawn(fixture.io,
        SendNoise(fixture.io, sender, destination, std::move(noise), state),
        [&](std::exception_ptr error) {
            if (error) state.noise_error = error;
            state.noise_done = true;
        });

    while (!state.read_done)
        co_await Pause(fixture.io, 4ms);
    state.stop_noise = true;
    while (!state.noise_done)
        co_await Pause(fixture.io, 4ms);
    watchdog.cancel();

    Check(state.read_done && state.noise_done,
          "read or noise task did not join before request teardown");
    Check(!state.watchdog_fired, "noise regression test watchdog expired");
    if (state.noise_error) std::rethrow_exception(state.noise_error);
    Check(state.noise_packets >= 10, "noise sender did not exercise repeated datagrams");
    Check(state.read_error != nullptr, "noise unexpectedly satisfied the response read");
    try {
        std::rethrow_exception(state.read_error);
    } catch (const transport::LinkError& error) {
        Check(error.code() == ErrorCode::CANCELLED,
              "timed UDP request returned the wrong transport error");
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;
    Check(elapsed >= 800ms && elapsed < 3s,
          "noise extended or prematurely ended the one-second deadline");
    Check(read_timeout ? request.ConsumeReadTimeout() : request.ConsumeIdleTimeout(),
          "the expected read or idle timeout was not recorded");
}

net::awaitable<void> TestAuthenticatedRoundTrip(Fixture& fixture) {
    udp::socket server(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    const auto cipher = MakeCipher();
    const TargetAddress proxy_next_hop = Target(server.local_endpoint());
    UdpRequest request(fixture.io, fixture.dns,
        net::ip::address_v4::loopback(), proxy_next_hop,
        cipher.info, cipher.key, {});

    const TargetAddress inner_target(net::ip::address_v4::loopback(), 5300);
    const auto request_bytes = Pattern(73, 4);
    co_await request.WriteMultiBuffer(MakePayload(inner_target, request_bytes));

    std::array<uint8_t, 65535> wire{};
    udp::endpoint client_endpoint;
    const auto wire_size = co_await server.async_receive_from(
        net::buffer(wire), client_endpoint, net::use_awaitable);
    const auto decoded_request = ss::DecodeUdpPacketWithKey(
        wire.data(), wire_size, cipher.key.span(), cipher.info.type,
        cipher.info.key_size, cipher.info.salt_size);
    Check(decoded_request.has_value(), "outbound request was not valid classic SS AEAD");
    Check(decoded_request->target.SameEndpoint(inner_target),
          "outbound request lost its inner target");
    Check(Flatten(decoded_request->payload) == request_bytes,
          "outbound request changed its plaintext");

    const TargetAddress response_target(net::ip::address_v4::loopback(), 6400);
    Check(!response_target.SameEndpoint(proxy_next_hop),
          "test response target must differ from the proxy next hop");
    const auto response_bytes = Pattern(91, 33);
    const auto response = EncodeClassic(response_target, response_bytes, cipher);
    co_await server.async_send_to(
        net::buffer(response), client_endpoint, net::use_awaitable);

    auto reply = co_await request.ReadMultiBuffer();
    const auto datagram = buf::InspectUdpDatagram(reply);
    Check(datagram.Valid() && datagram.target &&
          datagram.target->SameEndpoint(response_target),
          "authenticated response returned the proxy next hop instead of the inner target");
    Check(Flatten(reply) == response_bytes, "authenticated response payload changed");
}

net::awaitable<void> TestReadBudgetAgainstSameServerGarbage(Fixture& fixture) {
    udp::socket server(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    const auto cipher = MakeCipher();
    UdpRequest request(fixture.io, fixture.dns,
        net::ip::address_v4::loopback(), Target(server.local_endpoint()),
        cipher.info, cipher.key, {});
    request.SetReadTimeout(1s);
    const auto client = co_await SendOneAndGetClientEndpoint(request, server);
    std::vector<uint8_t> garbage(64, 0xa7);
    Check(!ss::DecodeUdpPacketWithKey(
              garbage.data(), garbage.size(), cipher.key.span(), cipher.info.type,
              cipher.info.key_size, cipher.info.salt_size),
          "same-server noise must fail classic SS authentication");
    co_await ReadAgainstNoise(
        fixture, request, server, client, std::move(garbage), true);
}

net::awaitable<void> TestWrongSourceCannotExtendIdle(Fixture& fixture) {
    udp::socket server(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    udp::socket wrong_source(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    const auto cipher = MakeCipher();
    UdpRequest request(fixture.io, fixture.dns,
        net::ip::address_v4::loopback(), Target(server.local_endpoint()),
        cipher.info, cipher.key, {});
    request.SetIdleTimeout(1s);
    const auto client = co_await SendOneAndGetClientEndpoint(request, server);
    const TargetAddress inner_target(net::ip::address_v4::loopback(), 8123);
    const auto plaintext = Pattern(36, 92);
    const auto authenticated_packet = EncodeClassic(inner_target, plaintext, cipher);
    const auto decoded = ss::DecodeUdpPacketWithKey(
        authenticated_packet.data(), authenticated_packet.size(), cipher.key.span(),
        cipher.info.type, cipher.info.key_size, cipher.info.salt_size);
    Check(decoded && decoded->target.SameEndpoint(inner_target) &&
          Flatten(decoded->payload) == plaintext,
          "wrong-source noise packet must be valid classic SS AEAD");
    co_await ReadAgainstNoise(
        fixture, request, wrong_source, client, authenticated_packet, false);
}

net::awaitable<void> TestSameSourceGarbageCannotExtendIdle(Fixture& fixture) {
    udp::socket server(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    const auto cipher = MakeCipher();
    UdpRequest request(fixture.io, fixture.dns,
        net::ip::address_v4::loopback(), Target(server.local_endpoint()),
        cipher.info, cipher.key, {});
    request.SetIdleTimeout(1s);
    const auto client = co_await SendOneAndGetClientEndpoint(request, server);
    std::vector<uint8_t> garbage(64, 0x5c);
    Check(!ss::DecodeUdpPacketWithKey(
              garbage.data(), garbage.size(), cipher.key.span(), cipher.info.type,
              cipher.info.key_size, cipher.info.salt_size),
          "same-server noise must fail classic SS authentication");
    co_await ReadAgainstNoise(
        fixture, request, server, client, std::move(garbage), false);
}

net::awaitable<void> TestMaximumWirePayload(Fixture& fixture) {
    udp::socket server(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    const auto cipher = MakeCipher();
    UdpRequest request(fixture.io, fixture.dns,
        net::ip::address_v4::loopback(), Target(server.local_endpoint()),
        cipher.info, cipher.key, {});
    const TargetAddress inner_target(net::ip::address_v4::loopback(), 5353);
    const auto oversized_plaintext = Pattern(65507, 8);
    const size_t encoded_size = ss::EncodeUdpPacketTo(
        inner_target, oversized_plaintext.data(), oversized_plaintext.size(),
        cipher.key.span(), cipher.info.type, cipher.info.key_size,
        cipher.info.salt_size, nullptr, 0);
    Check(encoded_size > 65507,
          "test plaintext must exceed the IPv4 wire limit after SS encoding overhead");

    bool rejected = false;
    try {
        co_await request.WriteMultiBuffer(
            MakePayload(inner_target, oversized_plaintext));
    } catch (const transport::LinkError& error) {
        rejected = error.code() == ErrorCode::INVALID_ARGUMENT;
    }
    Check(rejected, "oversized encoded UDP packet was not rejected as invalid argument");

    IoErrorCode nonblocking_error;
    server.non_blocking(true, nonblocking_error);
    Check(!nonblocking_error, "could not make loopback receiver nonblocking");
    std::array<uint8_t, 64> probe{};
    udp::endpoint source;
    (void)server.receive_from(net::buffer(probe), source, 0, nonblocking_error);
    Check(nonblocking_error == net::error::would_block ||
          nonblocking_error == net::error::try_again,
          "oversized packet was emitted before rejection");
    server.non_blocking(false, nonblocking_error);
    Check(!nonblocking_error, "could not restore blocking loopback receiver");

    const auto valid_bytes = Pattern(29, 114);
    co_await request.WriteMultiBuffer(MakePayload(inner_target, valid_bytes));
    std::array<uint8_t, 65535> wire{};
    const auto wire_size = co_await server.async_receive_from(
        net::buffer(wire), source, net::use_awaitable);
    const auto decoded = ss::DecodeUdpPacketWithKey(
        wire.data(), wire_size, cipher.key.span(), cipher.info.type,
        cipher.info.key_size, cipher.info.salt_size);
    Check(decoded && decoded->target.SameEndpoint(inner_target) &&
          Flatten(decoded->payload) == valid_bytes,
          "valid write did not recover after oversized-packet rejection");
}

template <typename Test>
bool RunCase(std::string_view name, Test&& test) {
    try {
        Fixture fixture;
        fixture.Run(test(fixture));
        std::cout << "PASS " << name << '\n';
        return true;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << name << ": " << error.what() << '\n';
        return false;
    } catch (...) {
        std::cerr << "FAIL " << name << ": unknown exception\n";
        return false;
    }
}
}  // namespace

int main() {
    size_t failures = 0;
    failures += !RunCase("authenticated response round trip", TestAuthenticatedRoundTrip);
    failures += !RunCase("single read budget with same-server garbage", TestReadBudgetAgainstSameServerGarbage);
    failures += !RunCase("wrong-source authenticated packets do not extend idle", TestWrongSourceCannotExtendIdle);
    failures += !RunCase("same-source garbage does not extend idle", TestSameSourceGarbageCannotExtendIdle);
    failures += !RunCase("IPv4 wire-size rejection and recovery", TestMaximumWirePayload);
    std::cout << "SS UDP request cases: " << (5 - failures) << "/5 passed\n";
    return failures == 0 ? 0 : 1;
}
