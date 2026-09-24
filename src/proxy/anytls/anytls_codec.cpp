#include "anytls_codec.hpp"
#include "padding.hpp"
#include "../uot/uot.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <utility>

namespace acpp::anytls {


namespace {

void WriteU16BE(uint8_t* out, uint16_t value) noexcept {
    out[0] = static_cast<uint8_t>(value >> 8);
    out[1] = static_cast<uint8_t>(value);
}

void WriteU32BE(uint8_t* out, uint32_t value) noexcept {
    out[0] = static_cast<uint8_t>(value >> 24);
    out[1] = static_cast<uint8_t>(value >> 16);
    out[2] = static_cast<uint8_t>(value >> 8);
    out[3] = static_cast<uint8_t>(value);
}

uint16_t ReadU16BE(const uint8_t* in) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) |
                                 static_cast<uint16_t>(in[1]));
}

uint32_t ReadU32BE(const uint8_t* in) noexcept {
    return (static_cast<uint32_t>(in[0]) << 24) |
           (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8) |
           static_cast<uint32_t>(in[3]);
}

std::array<uint8_t, kFrameHeaderSize> BuildFrameHeaderBytes(
    uint8_t cmd,
    uint32_t sid,
    size_t payload_size) noexcept {
    std::array<uint8_t, kFrameHeaderSize> header{};
    header[0] = cmd;
    WriteU32BE(header.data() + 1, sid);
    WriteU16BE(header.data() + 5, static_cast<uint16_t>(payload_size));
    return header;
}

void AppendWaste(memory::ByteVector& out, uint16_t payload_size) {
    const auto header = BuildFrameHeaderBytes(kCmdWaste, 0, payload_size);
    const size_t offset = out.size();
    out.resize(offset + header.size() + payload_size, uint8_t{0});
    std::memcpy(out.data() + offset, header.data(), header.size());
}

net::awaitable<std::expected<void, ErrorCode>>
WriteMultiBufferAsFrameBatchImpl(AsyncStream& stream,
                                 uint8_t cmd,
                                 uint32_t sid,
                                 buf::MultiBuffer mb) {
    static constexpr size_t kStackFrames = buf::MultiBuffer::kInlineCapacity;
    std::array<std::array<uint8_t, kFrameHeaderSize>, kStackFrames> stack_headers{};
    std::array<net::const_buffer, kStackFrames * 2> stack_buffers{};
    memory::ThreadLocalVector<std::array<uint8_t, kFrameHeaderSize>> spill_headers;
    memory::ThreadLocalVector<net::const_buffer> spill_buffers;

    const bool use_spill = mb.size() > kStackFrames;
    if (use_spill) {
        spill_headers.reserve(mb.size());
        spill_buffers.reserve(mb.size() * 2);
    }

    size_t stack_frame_count = 0;
    size_t stack_buffer_count = 0;

    for (auto* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        if (bytes.size() > kMaxFramePayload) {
            mb.clear();
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
        if (use_spill) {
            auto& header =
                spill_headers.emplace_back(BuildFrameHeaderBytes(cmd, sid, bytes.size()));
            spill_buffers.emplace_back(header.data(), header.size());
            spill_buffers.emplace_back(bytes.data(), bytes.size());
            continue;
        }

        auto& header = stack_headers[stack_frame_count++];
        header = BuildFrameHeaderBytes(cmd, sid, bytes.size());
        stack_buffers[stack_buffer_count++] =
            net::const_buffer(header.data(), header.size());
        stack_buffers[stack_buffer_count++] =
            net::const_buffer(bytes.data(), bytes.size());
    }

    const auto buffers = use_spill
        ? std::span<const net::const_buffer>(spill_buffers.data(), spill_buffers.size())
        : std::span<const net::const_buffer>(stack_buffers.data(), stack_buffer_count);

    if (!buffers.empty()) {
        try {
            co_await stream.WriteBuffers(buffers);
        } catch (const IoSystemError& e) {
            mb.clear();
            co_return std::unexpected(MapAsioError(e.code()));
        }
    }

    mb.clear();
    co_return std::expected<void, ErrorCode>{};
}

net::awaitable<std::expected<void, ErrorCode>>
WriteBuffersAsFrameBatchImpl(AsyncStream& stream,
                             uint8_t cmd,
                             uint32_t sid,
                             std::span<const net::const_buffer> input) {
    static constexpr size_t kStackFrames = buf::MultiBuffer::kInlineCapacity;
    std::array<std::array<uint8_t, kFrameHeaderSize>, kStackFrames> stack_headers{};
    std::array<net::const_buffer, kStackFrames * 2> stack_buffers{};
    memory::ThreadLocalVector<std::array<uint8_t, kFrameHeaderSize>> spill_headers;
    memory::ThreadLocalVector<net::const_buffer> spill_buffers;

    size_t non_empty_count = 0;
    for (const net::const_buffer& buffer : input) {
        if (buffer.data() && buffer.size() > 0) {
            ++non_empty_count;
        }
    }

    const bool use_spill = non_empty_count > kStackFrames;
    if (use_spill) {
        spill_headers.reserve(non_empty_count);
        spill_buffers.reserve(non_empty_count * 2);
    }

    size_t stack_frame_count = 0;
    size_t stack_buffer_count = 0;
    for (const net::const_buffer& buffer : input) {
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        if (!data || buffer.size() == 0) {
            continue;
        }
        if (buffer.size() > kMaxFramePayload) {
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
        if (use_spill) {
            auto& header =
                spill_headers.emplace_back(BuildFrameHeaderBytes(cmd, sid, buffer.size()));
            spill_buffers.emplace_back(header.data(), header.size());
            spill_buffers.emplace_back(data, buffer.size());
            continue;
        }

        auto& header = stack_headers[stack_frame_count++];
        header = BuildFrameHeaderBytes(cmd, sid, buffer.size());
        stack_buffers[stack_buffer_count++] =
            net::const_buffer(header.data(), header.size());
        stack_buffers[stack_buffer_count++] =
            net::const_buffer(data, buffer.size());
    }

    const auto buffers = use_spill
        ? std::span<const net::const_buffer>(spill_buffers.data(), spill_buffers.size())
        : std::span<const net::const_buffer>(stack_buffers.data(), stack_buffer_count);

    if (!buffers.empty()) {
        try {
            co_await stream.WriteBuffers(buffers);
        } catch (const IoSystemError& e) {
            co_return std::unexpected(MapAsioError(e.code()));
        }
    }

    co_return std::expected<void, ErrorCode>{};
}

}  // namespace

net::awaitable<std::expected<void, ErrorCode>>
WriteMultiBufferAsFrameBatch(AsyncStream& stream,
                             uint8_t cmd,
                             uint32_t sid,
                             buf::MultiBuffer mb) {
    return WriteMultiBufferAsFrameBatchImpl(stream, cmd, sid, std::move(mb));
}

std::expected<PeerSettings, ErrorCode> ParsePeerSettings(std::string_view text) {
    PeerSettings result;
    bool has_version = false;
    bool has_padding_md5 = false;
    while (!text.empty()) {
        const auto end = text.find('\n');
        auto line = text.substr(0, end);
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        if (line.ends_with('\r')) line.remove_suffix(1);
        if (line.empty()) continue;
        const auto separator = line.find('=');
        if (separator == std::string_view::npos || separator == 0)
            return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        const auto key = line.substr(0, separator);
        const auto value = line.substr(separator + 1);
        if (key == "v") {
            if (std::exchange(has_version, true) || value.empty())
                return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            uint32_t peer_version = 0;
            const auto [ptr, error] = std::from_chars(value.data(), value.data() + value.size(), peer_version);
            if (error != std::errc{} || ptr != value.data() + value.size() || peer_version == 0)
                return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            result.version = std::min(peer_version, kProtocolVersion) >= 2
                ? SessionVersion::V2 : SessionVersion::V1;
        } else if (key == "padding-md5") {
            if (std::exchange(has_padding_md5, true))
                return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            result.padding_md5.assign(value);
        }
        // Unknown well-formed keys belong to extensions, never feature gates.
    }
    return result;
}

std::string ClientSettings(const PaddingScheme& scheme) {
    return "v=" + std::to_string(kProtocolVersion) + "\nclient=cnode\npadding-md5=" + std::string(scheme.Digest());
}

std::expected<std::string, ErrorCode> EncodeSocksAddress(const TargetAddress& target) {
    if (!target.IsValid() && !proxy::uot::VersionFromMagicAddress(target)) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    std::string out;
    if (target.IsDomain()) {
        if (target.host.empty() || target.host.size() > 255) {
            return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        out.reserve(1 + 1 + target.host.size() + 2);
        out.push_back(static_cast<char>(0x03));
        out.push_back(static_cast<char>(target.host.size()));
        out.append(target.host);
    } else if (target.resolved_addr && target.resolved_addr->is_v4()) {
        out.reserve(1 + 4 + 2);
        out.push_back(static_cast<char>(0x01));
        const auto bytes = target.resolved_addr->to_v4().to_bytes();
        out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    } else if (target.resolved_addr && target.resolved_addr->is_v6()) {
        out.reserve(1 + 16 + 2);
        out.push_back(static_cast<char>(0x04));
        const auto bytes = target.resolved_addr->to_v6().to_bytes();
        out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    } else {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    uint8_t port[2];
    WriteU16BE(port, target.port);
    out.append(reinterpret_cast<const char*>(port), sizeof(port));
    return out;
}

std::expected<void, ErrorCode> AppendFrameBytesTo(
    memory::ByteVector& out,
    uint8_t cmd,
    uint32_t sid,
    std::span<const uint8_t> payload) {
    if (payload.size() > kMaxFramePayload) {
        return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    const size_t offset = out.size();
    out.resize(offset + kFrameHeaderSize + payload.size());
    auto* header = out.data() + offset;
    header[0] = cmd;
    WriteU32BE(header + 1, sid);
    WriteU16BE(header + 5, static_cast<uint16_t>(payload.size()));
    if (!payload.empty()) {
        std::memcpy(out.data() + offset + kFrameHeaderSize, payload.data(), payload.size());
    }
    return std::expected<void, ErrorCode>{};
}

net::awaitable<std::expected<void, ErrorCode>>
WriteAll(AsyncStream& stream, std::span<const uint8_t> data) {
    while (!data.empty()) {
        try {
            const auto n = co_await stream.AsyncWrite(net::buffer(data.data(), data.size()));
            if (n == 0) {
                co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
            data = data.subspan(n);
        } catch (const IoSystemError& e) {
            co_return std::unexpected(MapAsioError(e.code()));
        }
    }
    co_return std::expected<void, ErrorCode>{};
}

net::awaitable<std::expected<void, ErrorCode>>
WriteFrame(AsyncStream& stream, uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
    if (payload.size() > kMaxFramePayload) {
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    auto header = BuildFrameHeaderBytes(cmd, sid, payload.size());
    std::array<net::const_buffer, 2> buffers{
        net::const_buffer(header.data(), header.size()),
        net::const_buffer(payload.data(), payload.size())};
    try {
        co_await stream.WriteBuffers(buffers);
    } catch (const IoSystemError& e) {
        co_return std::unexpected(MapAsioError(e.code()));
    }
    co_return std::expected<void, ErrorCode>{};
}

net::awaitable<std::expected<void, ErrorCode>>
WriteFrameBody(AsyncStream& stream, uint8_t cmd, uint32_t sid, buf::Buffer& body) {
    const auto body_bytes = body.Bytes();
    co_return co_await WriteFrame(stream, cmd, sid, body_bytes);
}

net::awaitable<std::expected<void, ErrorCode>>
WritePacketWithPadding(AsyncStream& stream,
                       const PaddingScheme& scheme,
                       uint32_t packet_index,
                       memory::ByteVector packet) {
    if (packet.empty()) {
        co_return std::expected<void, ErrorCode>{};
    }

    const auto record_rules = scheme.RecordFor(packet_index);
    if (record_rules.empty()) {
        co_return co_await WriteAll(
            stream,
            std::span<const uint8_t>(packet.data(), packet.size()));
    }

    size_t offset = 0;
    memory::ByteVector record;
    for (const PaddingRecord& rule : record_rules) {
        const int sampled_size = rule.SampleSize();
        if (sampled_size == -1) {
            if (offset >= packet.size()) {
                break;
            }
            continue;
        }
        // Compiled records are positive and every possible Waste fits uint16.
        const size_t size = static_cast<size_t>(sampled_size);
        record.clear();
        const size_t remaining = packet.size() - offset;
        std::span<const uint8_t> output;
        if (remaining >= size) {
            output = std::span<const uint8_t>(packet).subspan(offset, size);
            offset += size;
        } else if (remaining > 0) {
            output = std::span<const uint8_t>(packet).subspan(offset);
            offset = packet.size();
            if (size - remaining > kFrameHeaderSize) {
                record.assign(output.begin(), output.end());
                AppendWaste(record, static_cast<uint16_t>(size - remaining - kFrameHeaderSize));
                output = record;
            }
        } else {
            AppendWaste(record, static_cast<uint16_t>(size));
            output = record;
        }

        auto ok = co_await WriteAll(stream, output);
        if (!ok) {
            co_return std::unexpected(ok.error());
        }
    }

    if (offset < packet.size()) {
        co_return co_await WriteAll(
            stream,
            std::span<const uint8_t>(packet.data() + offset, packet.size() - offset));
    }
    co_return std::expected<void, ErrorCode>{};
}

net::awaitable<std::expected<void, ErrorCode>>
WriteMultiBufferAsFramesWithPadding(AsyncStream& stream,
                                    const PaddingScheme& scheme,
                                    uint32_t packet_index,
                                    uint8_t cmd,
                                    uint32_t sid,
                                    buf::MultiBuffer mb) {
    if (scheme.RecordFor(packet_index).empty()) {
        co_return co_await WriteMultiBufferAsFrameBatch(stream, cmd, sid, std::move(mb));
    }

    memory::ByteVector packet;
    packet.reserve(buf::TotalLen(mb) + (mb.size() * kFrameHeaderSize));
    for (auto* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        auto ok = AppendFrameBytesTo(packet, cmd, sid, buffer->Bytes());
        if (!ok) {
            co_return std::unexpected(ok.error());
        }
    }
    mb.clear();
    co_return co_await WritePacketWithPadding(stream, scheme, packet_index, std::move(packet));
}

net::awaitable<std::expected<void, ErrorCode>>
WriteBuffersAsFramesWithPadding(AsyncStream& stream,
                                const PaddingScheme& scheme,
                                uint32_t packet_index,
                                uint8_t cmd,
                                uint32_t sid,
                                std::span<const net::const_buffer> buffers) {
    if (scheme.RecordFor(packet_index).empty()) {
        co_return co_await WriteBuffersAsFrameBatchImpl(stream, cmd, sid, buffers);
    }

    size_t payload_bytes = 0;
    size_t non_empty_count = 0;
    for (const net::const_buffer& buffer : buffers) {
        if (buffer.data() && buffer.size() > 0) {
            if (buffer.size() > kMaxFramePayload) {
                co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
            }
            payload_bytes += buffer.size();
            ++non_empty_count;
        }
    }

    memory::ByteVector packet;
    packet.reserve(payload_bytes + (non_empty_count * kFrameHeaderSize));
    for (const net::const_buffer& buffer : buffers) {
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        if (!data || buffer.size() == 0) {
            continue;
        }
        auto ok = AppendFrameBytesTo(
            packet,
            cmd,
            sid,
            std::span<const uint8_t>(data, buffer.size()));
        if (!ok) {
            co_return std::unexpected(ok.error());
        }
    }
    co_return co_await WritePacketWithPadding(stream, scheme, packet_index, std::move(packet));
}

net::awaitable<std::expected<FrameHeader, ErrorCode>>
ReadFrameHeader(AsyncStream& stream) {
    std::array<uint8_t, kFrameHeaderSize> header{};
    size_t offset = 0;
    while (offset < header.size()) {
        try {
            const auto n = co_await stream.AsyncRead(
                net::buffer(header.data() + offset, header.size() - offset));
            if (n == 0) {
                co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
            }
            offset += n;
        } catch (const IoSystemError& e) {
            co_return std::unexpected(MapAsioError(e.code()));
        }
    }

    FrameHeader out;
    out.cmd = header[0];
    out.sid = ReadU32BE(header.data() + 1);
    out.length = ReadU16BE(header.data() + 5);
    co_return out;
}

net::awaitable<std::expected<std::string, ErrorCode>>
ReadFrameText(AsyncStream& stream, uint16_t length) {
    std::string text(length, '\0');
    auto bytes = std::span<uint8_t>(
        reinterpret_cast<uint8_t*>(text.data()),
        text.size());
    size_t offset = 0;
    while (offset < bytes.size()) {
        try {
            const auto n = co_await stream.AsyncRead(
                net::buffer(bytes.data() + offset, bytes.size() - offset));
            if (n == 0) {
                co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
            }
            offset += n;
        } catch (const IoSystemError& e) {
            co_return std::unexpected(MapAsioError(e.code()));
        }
    }
    co_return text;
}

net::awaitable<std::expected<void, ErrorCode>>
DiscardFramePayload(AsyncStream& stream, uint16_t length) {
    std::array<uint8_t, 512> scratch{};
    size_t remaining = length;
    while (remaining > 0) {
        const size_t want = std::min(remaining, scratch.size());
        try {
            const auto n = co_await stream.AsyncRead(net::buffer(scratch.data(), want));
            if (n == 0) {
                co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
            }
            remaining -= n;
        } catch (const IoSystemError& e) {
            co_return std::unexpected(MapAsioError(e.code()));
        }
    }
    co_return std::expected<void, ErrorCode>{};
}

net::awaitable<std::expected<buf::MultiBuffer, ErrorCode>>
ReadFramePayload(AsyncStream& stream, uint16_t length) {
    buf::MultiBuffer mb;
    size_t remaining = length;
    while (remaining > 0) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }
        const size_t want = std::min<size_t>(remaining, buffer->Available());
        size_t offset = 0;
        while (offset < want) {
            try {
                const auto n = co_await stream.AsyncRead(
                    net::buffer(buffer->Tail().data() + offset, want - offset));
                if (n == 0) {
                    co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
                }
                offset += n;
            } catch (const IoSystemError& e) {
                co_return std::unexpected(MapAsioError(e.code()));
            }
        }
        buffer->Produce(static_cast<uint32_t>(want));
        remaining -= want;
        mb.push_back(std::move(buffer));
    }
    co_return mb;
}

}  // namespace acpp::anytls
