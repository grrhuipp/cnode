#include "udp_datagram.hpp"

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

buf::Buffer* MakeBuffer(size_t size, const TargetAddress* target) {
    buf::Buffer* buffer = buf::Buffer::New();
    Check(buffer != nullptr && size <= buffer->Available(),
          "failed to allocate VMess UDP test buffer");
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
    valid.push_back(MakeBuffer(4096, &target));
    valid.push_back(MakeBuffer(1024, &target));
    vmess::ValidateFixedUdpDatagram(valid, target);

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
