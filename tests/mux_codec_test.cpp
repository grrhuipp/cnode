#include "acppnode/common/mux/mux_codec.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/buffer_util.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <span>
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

void CheckInvalidAcrossLayouts(
    std::span<const uint8_t> frame,
    std::string_view message) {
    const auto contiguous = acpp::mux::DecodeFrame(frame.data(), frame.size());
    const auto prefix = acpp::mux::DecodeFramePrefix(
        frame.data(), frame.size(), frame.size());

    acpp::buf::MultiBuffer buffers;
    Check(acpp::buf::AppendSpanToMultiBuffer(frame, buffers),
          "failed to allocate fragmented Mux test input");
    const auto fragmented = acpp::mux::DecodeFrame(buffers, 0, frame.size());

    Check(contiguous.has_value() && contiguous->frame_size == 0 &&
              prefix.has_value() && prefix->frame_size == 0 &&
              fragmented.has_value() && fragmented->frame_size == 0,
          message);
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

    Check(mux::EncodeKeepDataTo(encoded, 7, nullptr, 0),
          "failed to encode option validation fixture");
    encoded[5] |= 0x80;
    CheckInvalidAcrossLayouts(
        encoded, "unknown Mux option bits were layout-dependent or accepted");

    const std::vector<uint8_t> missing_new_target{
        0x00, 0x04, 0x00, 0x07,
        static_cast<uint8_t>(mux::SessionStatus::NEW), 0x00};
    CheckInvalidAcrossLayouts(
        missing_new_target, "Mux NEW without a target was accepted");

    const std::vector<uint8_t> trailing_keepalive_metadata{
        0x00, 0x05, 0x00, 0x00,
        static_cast<uint8_t>(mux::SessionStatus::KEEPALIVE), 0x00, 0xaa};
    CheckInvalidAcrossLayouts(
        trailing_keepalive_metadata,
        "Mux KEEPALIVE trailing metadata was accepted");

    Check(mux::EncodeNewTo(
              encoded,
              7,
              mux::NetworkType::UDP,
              target,
              nullptr,
              0),
          "failed to encode GlobalID fixture");
    const uint16_t base_meta_len = static_cast<uint16_t>(
        (static_cast<uint16_t>(encoded[0]) << 8) | encoded[1]);
    encoded.insert(encoded.end(), 8, 0x42);
    const uint16_t global_meta_len = static_cast<uint16_t>(base_meta_len + 8);
    encoded[0] = static_cast<uint8_t>(global_meta_len >> 8);
    encoded[1] = static_cast<uint8_t>(global_meta_len);
    const auto global_id_frame = mux::DecodeFrame(encoded.data(), encoded.size());
    Check(global_id_frame.has_value() && global_id_frame->frame_size != 0 &&
              global_id_frame->has_global_id,
          "exact eight-byte Mux GlobalID was rejected");

    encoded.push_back(0x43);
    const uint16_t oversized_global_meta_len = static_cast<uint16_t>(base_meta_len + 9);
    encoded[0] = static_cast<uint8_t>(oversized_global_meta_len >> 8);
    encoded[1] = static_cast<uint8_t>(oversized_global_meta_len);
    CheckInvalidAcrossLayouts(
        encoded, "oversized Mux GlobalID metadata was accepted");

    std::cout << "mux_codec_test: ok\n";
    return 0;
}
