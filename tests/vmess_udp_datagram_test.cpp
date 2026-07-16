#include "udp_datagram.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

using namespace acpp;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

buf::Buffer* MakeBuffer(size_t size,
                        const TargetAddress* target,
                        uint8_t value = 0x6d) {
    buf::Buffer* buffer = buf::Buffer::New();
    Check(buffer != nullptr && size <= buffer->Available(),
          "failed to allocate VMess UDP test buffer");
    std::fill_n(buffer->Tail().data(), size, value);
    buffer->Produce(static_cast<uint32_t>(size));
    if (target) {
        buffer->SetUDP(*target);
    }
    return buffer;
}

template <typename Factory>
void CheckRejected(Factory&& factory, std::string_view message) {
    bool rejected = false;
    try {
        factory();
    } catch (const IoSystemError&) {
        rejected = true;
    }
    Check(rejected, message);
}

}  // namespace

int main() {
    const TargetAddress target("1.1.1.1", 53);
    const TargetAddress other("8.8.8.8", 53);

    buf::MultiBuffer valid;
    valid.push_back(MakeBuffer(buf::Buffer::kSize, &target, 0x11));
    valid.push_back(MakeBuffer(257, &target, 0x22));
    vmess::ValidateFixedUdpDatagram(valid, target);
    const vmess::ContiguousUdpDatagram contiguous(valid);
    Check(contiguous.Bytes().size() == buf::Buffer::kSize + 257 &&
          std::all_of(
              contiguous.Bytes().begin(),
              contiguous.Bytes().begin() + buf::Buffer::kSize,
              [](uint8_t value) { return value == 0x11; }) &&
          std::all_of(
              contiguous.Bytes().begin() + buf::Buffer::kSize,
              contiguous.Bytes().end(),
              [](uint8_t value) { return value == 0x22; }),
          "VMess multi-buffer UDP datagram was not coalesced exactly once");

    const std::array<uint8_t, 32> first{};
    const std::array<uint8_t, 48> second{};
    const std::array<net::const_buffer, 2> scatter{
        net::buffer(first),
        net::buffer(second),
    };
    const vmess::ContiguousUdpDatagram scatter_packet(scatter);
    Check(scatter_packet.Bytes().size() == first.size() + second.size(),
          "VMess scatter UDP datagram was split into multiple payloads");

    buf::MultiBuffer mixed;
    mixed.push_back(MakeBuffer(4096, &target));
    mixed.push_back(MakeBuffer(1024, &other));
    CheckRejected(
        [&] { vmess::ValidateFixedUdpDatagram(mixed, target); },
        "mixed VMess UDP endpoint was partially accepted");

    buf::MultiBuffer missing;
    missing.push_back(MakeBuffer(4096, &target));
    missing.push_back(MakeBuffer(1024, nullptr));
    CheckRejected(
        [&] { vmess::ValidateFixedUdpDatagram(missing, target); },
        "missing VMess UDP endpoint was partially accepted");

    buf::MultiBuffer wrong{MakeBuffer(4096, &other)};
    CheckRejected(
        [&] { vmess::ValidateFixedUdpDatagram(wrong, target); },
        "wrong fixed VMess UDP endpoint was accepted");

    return 0;
}
