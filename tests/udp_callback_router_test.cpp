#include "udp_callback_router.hpp"
#include "acppnode/common/target_address.hpp"

#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <source_location>

namespace {

[[noreturn]] void Fail(
    std::source_location location = std::source_location::current()) {
    std::cerr << "udp callback router test failed at line "
              << location.line() << '\n';
    std::exit(1);
}

}  // namespace

int main() {
    using namespace std::chrono_literals;

    acpp::detail::UdpCallbackRouter router;
    const acpp::UdpEndpointKey target{
        acpp::net::ip::address_v4::loopback(), 5353};
    acpp::TargetAddress packet_source;
    packet_source.type = acpp::AddressType::IPv4;
    packet_source.resolved_addr = acpp::net::ip::address_v4::loopback();
    packet_source.port = 5353;
    const std::array<uint8_t, 1> payload{0x42};
    const acpp::UDPPacketView packet{packet_source, payload};
    const auto now = acpp::steady_clock::now();

    uint64_t first_id = 0;
    uint64_t second_id = 0;
    size_t first_calls = 0;
    size_t second_calls = 0;
    first_id = router.Register(acpp::PacketCallback{
        [&](acpp::UDPPacketView) {
            ++first_calls;
            if (!router.Unregister(first_id) ||
                !router.Unregister(second_id)) {
                Fail();
            }
            return true;
        }});
    second_id = router.Register(acpp::PacketCallback{
        [&](acpp::UDPPacketView) {
            ++second_calls;
            return true;
        }});
    if (first_id == 0 || second_id == 0) Fail();

    auto [first_error, first_mapping] =
        router.BeginTargetSend(target, first_id, now);
    auto [second_error, second_mapping] =
        router.BeginTargetSend(target, second_id, now);
    if (first_error != acpp::ErrorCode::OK ||
        second_error != acpp::ErrorCode::OK ||
        !first_mapping || !second_mapping) {
        Fail();
    }
    if (!router.Dispatch(target, packet, now + 1ms) ||
        first_calls != 1 || second_calls != 0 ||
        router.RegisteredCount() != 0 ||
        router.TargetMappingCount() != 0) {
        Fail();
    }

    size_t clear_first_calls = 0;
    size_t clear_second_calls = 0;
    const uint64_t clear_first = router.Register(acpp::PacketCallback{
        [&](acpp::UDPPacketView) {
            ++clear_first_calls;
            router.Clear();
            return true;
        }});
    const uint64_t clear_second = router.Register(acpp::PacketCallback{
        [&](acpp::UDPPacketView) {
            ++clear_second_calls;
            return true;
        }});
    if (clear_first == 0 || clear_second == 0) Fail();
    auto [clear_first_error, clear_first_mapping] =
        router.BeginTargetSend(target, clear_first, now);
    auto [clear_second_error, clear_second_mapping] =
        router.BeginTargetSend(target, clear_second, now);
    if (clear_first_error != acpp::ErrorCode::OK ||
        clear_second_error != acpp::ErrorCode::OK) {
        Fail();
    }
    if (!router.Dispatch(target, packet, now + 2ms) ||
        clear_first_calls != 1 || clear_second_calls != 0 ||
        router.RegisteredCount() != 0 ||
        router.TargetMappingCount() != 0) {
        Fail();
    }

    size_t generation_calls = 0;
    const uint64_t generation_id = router.Register(acpp::PacketCallback{
        [&](acpp::UDPPacketView) {
            ++generation_calls;
            return true;
        }});
    if (generation_id == 0) Fail();
    auto [initial_error, initial_mapping] =
        router.BeginTargetSend(target, generation_id, now);
    auto [refresh_error, refreshed_mapping] =
        router.BeginTargetSend(target, generation_id, now + 1ms);
    if (initial_error != acpp::ErrorCode::OK ||
        refresh_error != acpp::ErrorCode::OK ||
        !initial_mapping.Inserted() || refreshed_mapping.Inserted()) {
        Fail();
    }
    initial_mapping = {};
    refreshed_mapping.Commit();
    if (!router.Dispatch(target, packet, now + 2ms) ||
        generation_calls != 1 || router.TargetMappingCount() != 1) {
        Fail();
    }

    router.Clear();
    const uint64_t rollback_id = router.Register(acpp::PacketCallback{
        [](acpp::UDPPacketView) { return true; }});
    {
        auto [rollback_error, rollback_mapping] =
            router.BeginTargetSend(target, rollback_id, now);
        if (rollback_error != acpp::ErrorCode::OK ||
            !rollback_mapping.Inserted()) {
            Fail();
        }
    }
    const uint64_t fallback_blocker = router.Register(acpp::PacketCallback{
        [](acpp::UDPPacketView) { return true; }});
    if (fallback_blocker == 0) Fail();
    if (router.TargetMappingCount() != 0 ||
        router.Dispatch(target, packet, now + 1ms)) {
        Fail();
    }

    router.Clear();
    const uint64_t concurrent_failure_id = router.Register(acpp::PacketCallback{
        [](acpp::UDPPacketView) { return true; }});
    {
        auto [failure_a_error, failure_a] =
            router.BeginTargetSend(target, concurrent_failure_id, now);
        auto [failure_b_error, failure_b] =
            router.BeginTargetSend(target, concurrent_failure_id, now + 1ms);
        if (failure_a_error != acpp::ErrorCode::OK ||
            failure_b_error != acpp::ErrorCode::OK) {
            Fail();
        }
        failure_a = std::move(failure_b);
    }
    if (router.TargetMappingCount() != 0) {
        Fail();
    }

    return 0;
}
