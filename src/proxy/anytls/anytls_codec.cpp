#include "anytls_codec.hpp"
#include "common/byte_reader.hpp"
#include "padding.hpp"
#include "common/allocator.hpp"
#include "transport/async_stream.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <format>
#include <utility>

namespace anytls {


namespace {

std::array<uint8_t, kFrameHeaderSize> BuildFrameHeaderBytes(
    uint8_t cmd,
    uint32_t sid,
    size_t payload_size) noexcept {
    std::array<uint8_t, kFrameHeaderSize> header{};
    header[0] = cmd;
    StoreU32BE(header.data() + 1, sid);
    StoreU16BE(header.data() + 5, static_cast<uint16_t>(payload_size));
    return header;
}

void AppendWaste(memory::ByteVector& out, uint16_t payload_size) {
    const auto header = BuildFrameHeaderBytes(kCmdWaste, 0, payload_size);
    const size_t offset = out.size();
    out.resize(offset + header.size() + payload_size, uint8_t{0});
    std::memcpy(out.data() + offset, header.data(), header.size());
}

}  // namespace

void FrameBatch::Begin(size_t frames) {
    count_ = 0;
    spill_headers_.clear();
    spill_buffers_.clear();
    spilled_ = frames > kInlineFrames;
    if (spilled_) {
        spill_headers_.reserve(frames);
        spill_buffers_.reserve(frames * 2);
    }
}

bool FrameBatch::Append(uint8_t cmd, uint32_t sid, std::span<const uint8_t> bytes) {
    if (bytes.size() > kMaxFramePayload) {
        count_ = 0;
        spill_buffers_.clear();
        return false;
    }
    if (spilled_) {
        auto& header = spill_headers_.emplace_back(
            BuildFrameHeaderBytes(cmd, sid, bytes.size()));
        spill_buffers_.emplace_back(header.data(), header.size());
        spill_buffers_.emplace_back(bytes.data(), bytes.size());
    } else {
        auto& header = headers_[count_ / 2];
        header = BuildFrameHeaderBytes(cmd, sid, bytes.size());
        buffers_[count_++] = net::const_buffer(header.data(), header.size());
        buffers_[count_++] = net::const_buffer(bytes.data(), bytes.size());
    }
    return true;
}

tl::expected<void, ErrorCode> FrameBatch::Encode(
    uint8_t cmd, uint32_t sid, const buf::MultiBuffer& payload) {
    Begin(payload.size());
    for (const auto* buffer : payload) {
        if (!buffer || buffer->IsEmpty()) continue;
        if (!Append(cmd, sid, buffer->Bytes())) {
            return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
    }
    return {};
}

tl::expected<void, ErrorCode> FrameBatch::Encode(
    uint8_t cmd, uint32_t sid, std::span<const net::const_buffer> input) {
    size_t frame_count = 0;
    for (const net::const_buffer& buffer : input) {
        if (buffer.data() && buffer.size() > 0) {
            frame_count += 1 + (buffer.size() - 1) / kMaxFramePayload;
        }
    }
    Begin(frame_count);
    for (const net::const_buffer& buffer : input) {
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        if (!data || buffer.size() == 0) continue;
        std::span<const uint8_t> remaining(data, buffer.size());
        while (!remaining.empty()) {
            const size_t chunk_size = std::min(remaining.size(), kMaxFramePayload);
            if (!Append(cmd, sid, remaining.first(chunk_size))) {
                return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
            }
            remaining = remaining.subspan(chunk_size);
        }
    }
    return {};
}

net::awaitable<tl::expected<void, ErrorCode>>
WriteMultiBufferAsFrameBatch(AsyncStream& stream,
                             uint8_t cmd,
                             uint32_t sid,
                             buf::MultiBuffer mb) {
    FrameBatch batch;
    auto encoded = batch.Encode(cmd, sid, mb);
    if (!encoded) {
        mb.clear();
        co_return encoded;
    }
    const auto buffers = batch.Buffers();
    if (!buffers.empty()) {
        try {
            co_await stream.WriteBuffers(buffers);
        } catch (const IoSystemError& e) {
            mb.clear();
            co_return tl::unexpected(MapAsioError(e.code()));
        }
    }
    mb.clear();
    co_return tl::expected<void, ErrorCode>{};
}

net::awaitable<tl::expected<void, ErrorCode>>
WriteBuffersAsFrameBatch(AsyncStream& stream,
                         uint8_t cmd,
                         uint32_t sid,
                         std::span<const net::const_buffer> buffers) {
    FrameBatch batch;
    auto encoded = batch.Encode(cmd, sid, buffers);
    if (!encoded) {
        co_return encoded;
    }
    const auto framed = batch.Buffers();
    if (!framed.empty()) {
        try {
            co_await stream.WriteBuffers(framed);
        } catch (const IoSystemError& e) {
            co_return tl::unexpected(MapAsioError(e.code()));
        }
    }
    co_return tl::expected<void, ErrorCode>{};
}

tl::expected<PeerSettings, ErrorCode> ParsePeerSettings(std::string_view text) {
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
            return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        const auto key = line.substr(0, separator);
        const auto value = line.substr(separator + 1);
        if (key == "v") {
            if (std::exchange(has_version, true) || value.empty())
                return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            uint32_t peer_version = 0;
            const auto [ptr, error] = std::from_chars(value.data(), value.data() + value.size(), peer_version);
            if (error != std::errc{} || ptr != value.data() + value.size() || peer_version == 0)
                return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            result.version = std::min(peer_version, kProtocolVersion) >= 2
                ? SessionVersion::V2 : SessionVersion::V1;
        } else if (key == "padding-md5") {
            if (std::exchange(has_padding_md5, true))
                return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            result.padding_md5 = value;
        }
        // Unknown well-formed keys belong to extensions, never feature gates.
    }
    return result;
}

memory::ThreadLocalString ClientSettings(const PaddingScheme& scheme) {
    memory::ThreadLocalString settings;
    const auto& digest = scheme.Digest();
    settings.reserve(28 + digest.size());
    settings.append("v=2\nclient=cnode\npadding-md5=");
    settings.append(digest);
    return settings;
}


tl::expected<void, ErrorCode> AppendFrameBytesTo(
    memory::ByteVector& out,
    uint8_t cmd,
    uint32_t sid,
    std::span<const uint8_t> payload) {
    if (payload.size() > kMaxFramePayload) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    const size_t offset = out.size();
    out.resize(offset + kFrameHeaderSize + payload.size());
    auto* header = out.data() + offset;
    header[0] = cmd;
    StoreU32BE(header + 1, sid);
    StoreU16BE(header + 5, static_cast<uint16_t>(payload.size()));
    if (!payload.empty()) {
        std::memcpy(out.data() + offset + kFrameHeaderSize, payload.data(), payload.size());
    }
    return tl::expected<void, ErrorCode>{};
}

net::awaitable<tl::expected<void, ErrorCode>>
WriteAll(AsyncStream& stream, std::span<const uint8_t> data) {
    while (!data.empty()) {
        try {
            const auto n = co_await stream.AsyncWrite(net::buffer(data.data(), data.size()));
            if (n == 0) {
                co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
            data = data.subspan(n);
        } catch (const IoSystemError& e) {
            co_return tl::unexpected(MapAsioError(e.code()));
        }
    }
    co_return tl::expected<void, ErrorCode>{};
}

net::awaitable<tl::expected<void, ErrorCode>>
WriteFrame(AsyncStream& stream, uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
    if (payload.size() > kMaxFramePayload) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    auto header = BuildFrameHeaderBytes(cmd, sid, payload.size());
    std::array<net::const_buffer, 2> buffers{
        net::const_buffer(header.data(), header.size()),
        net::const_buffer(payload.data(), payload.size())};
    try {
        co_await stream.WriteBuffers(buffers);
    } catch (const IoSystemError& e) {
        co_return tl::unexpected(MapAsioError(e.code()));
    }
    co_return tl::expected<void, ErrorCode>{};
}

net::awaitable<tl::expected<void, ErrorCode>>
WritePacketWithPadding(AsyncStream& stream,
                       const PaddingScheme& scheme,
                       uint32_t packet_index,
                       memory::ByteVector packet) {
    if (packet.empty()) {
        co_return tl::expected<void, ErrorCode>{};
    }

    const auto record_rules = scheme.RecordFor(packet_index);
    if (record_rules.empty()) {
        co_return co_await WriteAll(
            stream,
            std::span<const uint8_t>(packet.data(), packet.size()));
    }

    size_t offset = 0;
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
        const size_t remaining = packet.size() - offset;
        memory::ByteVector record;
        std::span<const uint8_t> output;
        if (remaining >= size) {
            output = std::span<const uint8_t>(packet).subspan(offset, size);
            offset += size;
        } else if (remaining > 0) {
            output = std::span<const uint8_t>(packet).subspan(offset);
            offset = packet.size();
            if (size - remaining > kFrameHeaderSize) {
                record.reserve(size);
                record.assign(output.begin(), output.end());
                AppendWaste(record, static_cast<uint16_t>(size - remaining - kFrameHeaderSize));
                output = record;
            }
        } else {
            record.reserve(kFrameHeaderSize + size);
            AppendWaste(record, static_cast<uint16_t>(size));
            output = record;
        }

        auto ok = co_await WriteAll(stream, output);
        if (!ok) {
            co_return tl::unexpected(ok.error());
        }
    }
    if (offset < packet.size()) {
        co_return co_await WriteAll(
            stream,
            std::span<const uint8_t>(packet.data() + offset, packet.size() - offset));
    }
    co_return tl::expected<void, ErrorCode>{};
}

static net::awaitable<tl::expected<void, ErrorCode>>
WritePaddedMultiBufferFrames(AsyncStream& stream,
                            const PaddingScheme& scheme,
                            uint32_t packet_index,
                            uint8_t cmd,
                            uint32_t sid,
                            buf::MultiBuffer mb) {

    memory::ByteVector packet;
    packet.reserve(mb.byte_size() + (mb.size() * kFrameHeaderSize));
    for (auto* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        auto ok = AppendFrameBytesTo(packet, cmd, sid, buffer->Bytes());
        if (!ok) {
            co_return tl::unexpected(ok.error());
        }
    }
    mb.clear();
    co_return co_await WritePacketWithPadding(stream, scheme, packet_index, std::move(packet));
}

net::awaitable<tl::expected<void, ErrorCode>>
WriteMultiBufferAsFramesWithPadding(AsyncStream& stream,
                                    const PaddingScheme& scheme,
                                    uint32_t packet_index,
                                    uint8_t cmd,
                                    uint32_t sid,
                                    buf::MultiBuffer mb) {
    if (scheme.RecordFor(packet_index).empty()) {
        return WriteMultiBufferAsFrameBatch(stream, cmd, sid, std::move(mb));
    }
    return WritePaddedMultiBufferFrames(stream, scheme, packet_index, cmd, sid, std::move(mb));
}

static net::awaitable<tl::expected<void, ErrorCode>>
WritePaddedBufferFrames(AsyncStream& stream,
                       const PaddingScheme& scheme,
                       uint32_t packet_index,
                       uint8_t cmd,
                       uint32_t sid,
                       std::span<const net::const_buffer> buffers) {

    size_t payload_bytes = 0;
    size_t frame_count = 0;
    for (const net::const_buffer& buffer : buffers) {
        if (buffer.data() && buffer.size() > 0) {
            payload_bytes += buffer.size();
            frame_count += 1 + (buffer.size() - 1) / kMaxFramePayload;
        }
    }

    memory::ByteVector packet;
    packet.reserve(payload_bytes + (frame_count * kFrameHeaderSize));
    for (const net::const_buffer& buffer : buffers) {
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        if (!data || buffer.size() == 0) {
            continue;
        }
        std::span<const uint8_t> remaining(data, buffer.size());
        while (!remaining.empty()) {
            const size_t chunk_size = std::min(remaining.size(), kMaxFramePayload);
            auto ok = AppendFrameBytesTo(
                packet,
                cmd,
                sid,
                remaining.first(chunk_size));
            if (!ok) {
                co_return tl::unexpected(ok.error());
            }
            remaining = remaining.subspan(chunk_size);
        }
    }
    co_return co_await WritePacketWithPadding(stream, scheme, packet_index, std::move(packet));
}

net::awaitable<tl::expected<void, ErrorCode>>
WriteBuffersAsFramesWithPadding(AsyncStream& stream,
                                const PaddingScheme& scheme,
                                uint32_t packet_index,
                                uint8_t cmd,
                                uint32_t sid,
                                std::span<const net::const_buffer> buffers) {
    if (scheme.RecordFor(packet_index).empty()) {
        return WriteBuffersAsFrameBatch(stream, cmd, sid, buffers);
    }
    return WritePaddedBufferFrames(stream, scheme, packet_index, cmd, sid, buffers);
}

net::awaitable<tl::expected<FrameHeader, ErrorCode>>
ReadFrameHeader(AsyncStream& stream) {
    std::array<uint8_t, kFrameHeaderSize> header{};
    size_t offset = 0;
    while (offset < header.size()) {
        try {
            const auto n = co_await stream.AsyncRead(
                net::buffer(header.data() + offset, header.size() - offset));
            if (n == 0) {
                co_return tl::unexpected(ErrorCode::CONNECTION_CLOSED);
            }
            offset += n;
        } catch (const IoSystemError& e) {
            co_return tl::unexpected(MapAsioError(e.code()));
        }
    }

    FrameHeader out;
    out.cmd = header[0];
    out.sid = LoadU32BE(header.data() + 1);
    out.length = LoadU16BE(header.data() + 5);
    co_return out;
}

net::awaitable<tl::expected<memory::ThreadLocalString, ErrorCode>>
ReadFrameText(AsyncStream& stream, uint16_t length) {
    memory::ThreadLocalString text;
    if (length == 0) {
        co_return text;
    }
    std::array<char, 1024> scratch{};
    size_t remaining = length;
    while (remaining > 0) {
        const size_t want = std::min(remaining, scratch.size());
        try {
            const auto n = co_await stream.AsyncRead(
                net::buffer(scratch.data(), want));
            if (n == 0) {
                co_return tl::unexpected(ErrorCode::CONNECTION_CLOSED);
            }
            text.append(scratch.data(), n);
            remaining -= n;
        } catch (const IoSystemError& e) {
            co_return tl::unexpected(MapAsioError(e.code()));
        }
    }
    co_return text;
}

net::awaitable<tl::expected<void, ErrorCode>>
DiscardFramePayload(AsyncStream& stream, uint16_t length) {
    if (length == 0) {
        co_return tl::expected<void, ErrorCode>{};
    }
    std::array<uint8_t, 512> scratch{};
    size_t remaining = length;
    while (remaining > 0) {
        const size_t want = std::min(remaining, scratch.size());
        try {
            const auto n = co_await stream.AsyncRead(net::buffer(scratch.data(), want));
            if (n == 0) {
                co_return tl::unexpected(ErrorCode::CONNECTION_CLOSED);
            }
            remaining -= n;
        } catch (const IoSystemError& e) {
            co_return tl::unexpected(MapAsioError(e.code()));
        }
    }
    co_return tl::expected<void, ErrorCode>{};
}

net::awaitable<tl::expected<buf::MultiBuffer, ErrorCode>>
ReadFramePayload(AsyncStream& stream, uint16_t length) {
    buf::MultiBuffer mb;
    size_t remaining = length;
    while (remaining > 0) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }
        const size_t want = std::min<size_t>(remaining, buffer->Available());
        size_t offset = 0;
        while (offset < want) {
            try {
                const auto n = co_await stream.AsyncRead(
                    net::buffer(buffer->Tail().data() + offset, want - offset));
                if (n == 0) {
                    co_return tl::unexpected(ErrorCode::CONNECTION_CLOSED);
                }
                offset += n;
            } catch (const IoSystemError& e) {
                co_return tl::unexpected(MapAsioError(e.code()));
            }
        }
        buffer->Produce(static_cast<uint32_t>(want));
        remaining -= want;
        mb.push_back(std::move(buffer));
    }
    co_return mb;
}

}  // namespace anytls
