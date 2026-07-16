#include "acppnode/common/mux/mux_codec.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>
#include <vector>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

}  // namespace

int main() {
    using namespace acpp;

    constexpr size_t kMaxPayload = std::numeric_limits<uint16_t>::max();
    std::vector<uint8_t> maximum(kMaxPayload, 0x5a);
    std::vector<uint8_t> oversized(kMaxPayload + 1, 0x6b);
    memory::ByteVector encoded;

    Check(mux::EncodeKeepDataTo(
              encoded, 7, maximum.data(), maximum.size()),
          "maximum Mux payload was rejected");
    const auto decoded = mux::DecodeFrame(encoded.data(), encoded.size());
    Check(decoded.has_value() && decoded->frame_size == encoded.size() &&
              decoded->data_len == kMaxPayload,
          "maximum Mux payload did not round-trip");

    Check(mux::EncodeKeepDataTo(encoded, 7, nullptr, 0),
          "zero-length Mux DATA frame was rejected");
    const auto empty_decoded = mux::DecodeFrame(encoded.data(), encoded.size());
    Check(empty_decoded.has_value() &&
              empty_decoded->frame_size == encoded.size() &&
              empty_decoded->has_data && empty_decoded->data_len == 0,
          "zero-length Mux DATA frame omitted its wire length");

    Check(!mux::EncodeKeepDataTo(
              encoded, 7, oversized.data(), oversized.size()) &&
              encoded.empty(),
          "oversized Mux TCP payload was truncated instead of rejected");
    Check(!mux::EncodeKeepDataHeaderTo(encoded, 7, oversized.size()) &&
              encoded.empty(),
          "oversized Mux TCP header was truncated instead of rejected");

    const TargetAddress target("example.com", 53);
    Check(!mux::EncodeNewTo(
              encoded,
              7,
              mux::NetworkType::UDP,
              target,
              oversized.data(),
              oversized.size()) &&
              encoded.empty(),
          "oversized Mux NEW payload was truncated instead of rejected");
    Check(!mux::EncodeKeepUDPTo(
              encoded,
              7,
              target,
              oversized.data(),
              oversized.size()) &&
              encoded.empty(),
          "oversized Mux UDP payload was truncated instead of rejected");
    Check(!mux::EncodeKeepUDPHeaderTo(
              encoded, 7, target, oversized.size()) &&
              encoded.empty(),
          "oversized Mux UDP header was truncated instead of rejected");

    std::cout << "mux_codec_test: ok\n";
    return 0;
}
