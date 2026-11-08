#include <stdexcept>
#include <gtest/gtest.h>

#include "common/mux/mux_codec.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buffer_util.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

std::optional<::mux::FrameHeader> DecodeSplit(
    std::span<const uint8_t> frame,
    size_t split) {
    ::buf::MultiBuffer buffers;
    ::buf::MultiBuffer suffix;
    split = std::min(split, frame.size());
    Check(::buf::AppendSpanToMultiBuffer(frame.first(split), buffers) &&
              ::buf::AppendSpanToMultiBuffer(frame.subspan(split), suffix),
          "failed to allocate Mux test input");
    // A separate suffix keeps the split as a real Buffer boundary.
    suffix.MoveTo(buffers);
    return ::mux::DecodeFrame(buffers);
}

std::optional<::mux::FrameHeader> Decode(std::span<const uint8_t> frame) {
    return DecodeSplit(frame, frame.size());
}

bool EncodeKeepDataHeader(
    ::memory::ByteVector& out,
    uint16_t session_id,
    size_t payload_len) {
    std::array<uint8_t, ::mux::kMaxFrameHeaderBytes> header{};
    const size_t n = ::mux::EncodeKeepDataHeaderTo(header, session_id, payload_len);
    out.assign(header.data(), header.data() + n);
    return n != 0;
}

bool EncodeNewHeaderTo(
    ::memory::ByteVector& out,
    uint16_t session_id,
    ::mux::NetworkType network,
    const ::TargetAddress& target,
    size_t payload_len,
    bool has_data) {
    std::array<uint8_t, ::mux::kMaxFrameHeaderBytes> header{};
    const size_t n = ::mux::EncodeNewHeaderTo(
        header, session_id, network, target, payload_len, has_data);
    out.assign(header.data(), header.data() + n);
    return n != 0;
}

bool EncodeKeepUDPHeaderTo(
    ::memory::ByteVector& out,
    uint16_t session_id,
    const ::TargetAddress& src,
    size_t payload_len) {
    std::array<uint8_t, ::mux::kMaxFrameHeaderBytes> header{};
    const size_t n = ::mux::EncodeKeepUDPHeaderTo(
        header, session_id, src, payload_len);
    out.assign(header.data(), header.data() + n);
    return n != 0;
}

void CheckInvalidAcrossLayouts(
    std::span<const uint8_t> frame,
    std::string_view message) {
    const auto contiguous = Decode(frame);
    const auto fragmented = DecodeSplit(frame, 3);

    Check(contiguous.has_value() && contiguous->frame_size == 0 &&
              fragmented.has_value() && fragmented->frame_size == 0,
          message);
}

}  // namespace

TEST(MuxCodec, Contract) {

    constexpr size_t kMaxPayload = std::numeric_limits<uint16_t>::max();
    std::vector<uint8_t> maximum(kMaxPayload, 0x5a);
    std::vector<uint8_t> oversized(kMaxPayload + 1, 0x6b);
    memory::ByteVector encoded;

    std::vector<uint8_t> large_xudp_packet(buf::Buffer::kSize + 257, 0x39);
    std::vector<uint8_t> xudp_wire(large_xudp_packet.size() + 2);
    xudp_wire[0] = static_cast<uint8_t>(large_xudp_packet.size() >> 8);
    xudp_wire[1] = static_cast<uint8_t>(large_xudp_packet.size());
    std::copy(
        large_xudp_packet.begin(), large_xudp_packet.end(), xudp_wire.begin() + 2);
    buf::MultiBuffer xudp_input;
    Check(buf::AppendSpanToMultiBuffer(xudp_wire, xudp_input),
          "failed to allocate large XUDP fixture");
    buf::LengthPrefixedPacketBuffer xudp_decoder;
    xudp_decoder.Append(std::move(xudp_input));
    buf::MultiBuffer decoded_xudp_packet;
    const auto xudp_result = xudp_decoder.Pop(decoded_xudp_packet);
    std::vector<uint8_t> recovered_xudp_packet(large_xudp_packet.size());
    const size_t recovered_xudp_bytes =
        decoded_xudp_packet.CopyPrefixTo(recovered_xudp_packet);
    Check(xudp_result == buf::LengthPrefixedPacketBuffer::PopResult::Packet &&
              recovered_xudp_bytes == large_xudp_packet.size() &&
              recovered_xudp_packet == large_xudp_packet &&
              xudp_decoder.PendingBytes() == 0,
          "XUDP packet larger than one Buffer was rejected or truncated");
    xudp_decoder.Finish();
    const std::array<uint8_t, 5> empty_then_packet{0, 0, 0, 1, 0x4f};
    buf::MultiBuffer empty_input;
    Check(buf::AppendSpanToMultiBuffer(empty_then_packet, empty_input),
          "failed to allocate empty XUDP fixture");
    xudp_decoder.Append(std::move(empty_input));
    Check(xudp_decoder.Pop(decoded_xudp_packet) ==
              buf::LengthPrefixedPacketBuffer::PopResult::Packet &&
          decoded_xudp_packet.empty() && xudp_decoder.PendingBytes() == 3,
          "zero-length XUDP frame failed to consume exactly its header");
    Check(xudp_decoder.Pop(decoded_xudp_packet) ==
              buf::LengthPrefixedPacketBuffer::PopResult::Packet &&
          decoded_xudp_packet.byte_size() == 1,
          "zero-length XUDP frame corrupted its successor");
    xudp_decoder.Finish();
    for (const auto& truncated : {std::vector<uint8_t>{0},
                                  std::vector<uint8_t>{0, 2, 0x41}}) {
        buf::MultiBuffer input;
        Check(buf::AppendSpanToMultiBuffer(truncated, input),
              "failed to allocate truncated XUDP fixture");
        xudp_decoder.Append(std::move(input));
        Check(xudp_decoder.Pop(decoded_xudp_packet) ==
                  buf::LengthPrefixedPacketBuffer::PopResult::NeedMore,
              "truncated XUDP frame was emitted");
        bool rejected = false;
        try {
            xudp_decoder.Finish();
        } catch (const IoSystemError&) {
            rejected = true;
        }
        Check(rejected, "XUDP EOF accepted a partial length or payload");
        xudp_decoder.Clear();
    }

    Check(EncodeNewHeaderTo(
              encoded,
              9,
              mux::NetworkType::UDP,
              TargetAddress("example.com", 53),
              large_xudp_packet.size(), true),
          "large Mux NEW header was rejected");
    encoded.insert(
        encoded.end(), large_xudp_packet.begin(), large_xudp_packet.end());
    const auto large_new_frame = Decode(encoded);
    Check(large_new_frame.has_value() && large_new_frame->frame_size == encoded.size() &&
              large_new_frame->data_len == large_xudp_packet.size(),
          "Mux NEW header did not preserve a multi-buffer datagram length");

    Check(EncodeKeepDataHeader(
              encoded, 7, maximum.size()),
          "maximum Mux payload was rejected");
    encoded.insert(encoded.end(), maximum.begin(), maximum.end());
    const auto decoded = Decode(encoded);
    Check(decoded.has_value() && decoded->frame_size == encoded.size() &&
              decoded->data_len == kMaxPayload,
          "maximum Mux payload did not round-trip");

    Check(EncodeKeepDataHeader(encoded, 7, 0),
          "zero-length Mux DATA frame was rejected");
    const auto empty_decoded = Decode(encoded);
    Check(empty_decoded.has_value() &&
              empty_decoded->frame_size == encoded.size() &&
              empty_decoded->has_data && empty_decoded->data_len == 0,
          "zero-length Mux DATA frame omitted its wire length");
    Check(EncodeNewHeaderTo(encoded, 7, mux::NetworkType::UDP,
                            TargetAddress("example.com", 53), 0, false),
          "pure Mux UDP NEW control frame was rejected");
    const auto control_new = Decode(encoded);
    const size_t control_size = encoded.size();
    Check(control_new && !control_new->has_data && control_new->data_len == 0 &&
          control_new->frame_size == control_size,
          "Mux UDP NEW control frame manufactured Data");
    Check(EncodeNewHeaderTo(encoded, 7, mux::NetworkType::UDP,
                            TargetAddress("example.com", 53), 0, true),
          "Mux UDP NEW with empty Data was rejected");
    for (size_t split = 0; split <= encoded.size(); ++split) {
        const auto data_new = DecodeSplit(encoded, split);
        Check(data_new && data_new->has_data && data_new->data_len == 0 &&
              data_new->frame_size == encoded.size() && encoded.size() == control_size + 2,
              "Mux UDP NEW lost empty Data or its length across Buffer layouts");
    }
    Check(!EncodeNewHeaderTo(encoded, 7, mux::NetworkType::UDP,
                             TargetAddress("example.com", 53), 1, false),
          "Mux NEW without Data silently encoded a nonzero payload length");
    Check(!EncodeKeepDataHeader(encoded, 7, oversized.size()) &&
              encoded.empty(),
          "oversized Mux TCP header was truncated instead of rejected");

    const TargetAddress target("example.com", 53);
    const TargetAddress zero_port_target("example.com", 0);
    TargetAddress oversized_domain_target;
    oversized_domain_target.type = AddressType::Domain;
    oversized_domain_target.host.assign(256, 'a');
    oversized_domain_target.port = 53;
    Check(!EncodeNewHeaderTo(
              encoded,
              7,
              mux::NetworkType::TCP,
              zero_port_target,
              0, false) &&
              encoded.empty(),
          "Mux NEW encoded a zero-port target");
    Check(!EncodeKeepUDPHeaderTo(
              encoded, 7, zero_port_target, 0) && encoded.empty(),
          "Mux UDP encoded a zero-port target");
    Check(!EncodeNewHeaderTo(
              encoded,
              7,
              mux::NetworkType::TCP,
              oversized_domain_target,
              0, false) &&
              encoded.empty(),
          "Mux NEW truncated an oversized domain target");
    Check(!EncodeNewHeaderTo(
              encoded,
              7,
              static_cast<mux::NetworkType>(0xff),
              target,
              0, false) &&
              encoded.empty(),
          "Mux NEW encoded an unknown network type");

    Check(!EncodeNewHeaderTo(
              encoded,
              7,
              mux::NetworkType::UDP,
              target,
              oversized.size(), true) &&
              encoded.empty(),
          "oversized Mux NEW payload was truncated instead of rejected");
    Check(!EncodeKeepUDPHeaderTo(
              encoded, 7, target, oversized.size()) &&
              encoded.empty(),
          "oversized Mux UDP header was truncated instead of rejected");

    Check(EncodeKeepDataHeader(encoded, 7, 0),
          "failed to encode option validation fixture");
    encoded[5] |= 0x80;
    CheckInvalidAcrossLayouts(
        encoded, "unknown Mux option bits were layout-dependent or accepted");

    const std::vector<uint8_t> missing_new_target{
        0x00, 0x04, 0x00, 0x07,
        static_cast<uint8_t>(mux::SessionStatus::NEW), 0x00};
    CheckInvalidAcrossLayouts(
        missing_new_target, "Mux NEW without a target was accepted");

    const std::vector<uint8_t> zero_port_new_target{
        0x00, 0x13, 0x00, 0x07,
        static_cast<uint8_t>(mux::SessionStatus::NEW), 0x00,
        static_cast<uint8_t>(mux::NetworkType::TCP),
        0x00, 0x00, 0x02, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    CheckInvalidAcrossLayouts(
        zero_port_new_target, "Mux NEW accepted a zero-port target");

    const std::vector<uint8_t> invalid_domain_new_target{
        0x00, 0x0b, 0x00, 0x07,
        static_cast<uint8_t>(mux::SessionStatus::NEW), 0x00,
        static_cast<uint8_t>(mux::NetworkType::TCP),
        0x00, 0x50, 0x02, 0x03, 'a', ' ', 'b'};
    CheckInvalidAcrossLayouts(
        invalid_domain_new_target, "Mux NEW accepted an invalid domain target");

    const std::vector<uint8_t> trailing_keepalive_metadata{
        0x00, 0x05, 0x00, 0x00,
        static_cast<uint8_t>(mux::SessionStatus::KEEPALIVE), 0x00, 0xaa};
    CheckInvalidAcrossLayouts(
        trailing_keepalive_metadata,
        "Mux KEEPALIVE trailing metadata was accepted");

    const std::vector<uint8_t> oversized_metadata_prefix{0x02, 0x00, 0x00};
    CheckInvalidAcrossLayouts(
        oversized_metadata_prefix,
        "Mux MetaLen beyond the largest valid metadata waited for more data");

    Check(EncodeNewHeaderTo(
              encoded,
              7,
              mux::NetworkType::UDP,
              target,
              0, false),
          "failed to encode GlobalID fixture");
    const uint16_t base_meta_len = static_cast<uint16_t>(
        (static_cast<uint16_t>(encoded[0]) << 8) | encoded[1]);
    encoded.insert(encoded.end(), 8, 0x42);
    const uint16_t global_meta_len = static_cast<uint16_t>(base_meta_len + 8);
    encoded[0] = static_cast<uint8_t>(global_meta_len >> 8);
    encoded[1] = static_cast<uint8_t>(global_meta_len);
    const auto global_id_frame = Decode(encoded);
    const auto fragmented_global_id_frame = DecodeSplit(encoded, 5);
    Check(global_id_frame.has_value() && global_id_frame->frame_size != 0 &&
              global_id_frame->has_global_id &&
              fragmented_global_id_frame.has_value() &&
              fragmented_global_id_frame->frame_size == global_id_frame->frame_size &&
              fragmented_global_id_frame->has_global_id,
          "exact eight-byte Mux GlobalID was rejected");

    encoded.push_back(0x43);
    const uint16_t oversized_global_meta_len = static_cast<uint16_t>(base_meta_len + 9);
    encoded[0] = static_cast<uint8_t>(oversized_global_meta_len >> 8);
    encoded[1] = static_cast<uint8_t>(oversized_global_meta_len);
    CheckInvalidAcrossLayouts(
        encoded, "oversized Mux GlobalID metadata was accepted");

    std::cout << "mux_codec_test: ok\n";
}
