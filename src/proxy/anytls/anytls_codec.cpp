#include "anytls_codec.hpp"
#include "../uot/uot.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <openssl/evp.h>
#include <random>

namespace acpp::anytls {

std::array<uint8_t, 32> PasswordHash(std::string_view password) noexcept {
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 0;
    EVP_Digest(
        password.data(),
        password.size(),
        out.data(),
        &out_len,
        EVP_sha256(),
        nullptr);
    return out;
}

namespace {

const std::array<uint8_t, buf::Buffer::kSize>& ZeroPaddingBlock() {
    static const std::array<uint8_t, buf::Buffer::kSize> zeros{};
    return zeros;
}

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

ErrorCode MapWriteException(const IoSystemError& e) noexcept {
    return MapAsioError(e.code());
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
            co_return std::unexpected(MapWriteException(e));
        } catch (...) {
            mb.clear();
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
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
            co_return std::unexpected(MapWriteException(e));
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
    }

    co_return std::expected<void, ErrorCode>{};
}

std::optional<int> ParseInt(std::string_view text) {
    int value = 0;
    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

std::vector<std::string_view> Split(std::string_view text, char delimiter) {
    std::vector<std::string_view> out;
    while (true) {
        const auto pos = text.find(delimiter);
        auto item = pos == std::string_view::npos ? text : text.substr(0, pos);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) {
            item.remove_prefix(1);
        }
        while (!item.empty() &&
               (item.back() == ' ' || item.back() == '\t' || item.back() == '\r')) {
            item.remove_suffix(1);
        }
        if (!item.empty()) {
            out.push_back(item);
        }
        if (pos == std::string_view::npos) {
            break;
        }
        text.remove_prefix(pos + 1);
    }
    return out;
}

std::string HexDigest(const unsigned char* bytes, unsigned int size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (unsigned int i = 0; i < size; ++i) {
        out.push_back(kHex[bytes[i] >> 4]);
        out.push_back(kHex[bytes[i] & 0x0f]);
    }
    return out;
}

std::string Md5Hex(std::string_view text) {
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int digest_len = 0;
    EVP_Digest(text.data(), text.size(), digest, &digest_len, EVP_md5(), nullptr);
    return HexDigest(digest, digest_len);
}

std::vector<PaddingRecord> ParsePaddingRecord(std::string_view text) {
    std::vector<PaddingRecord> out;
    for (auto item : Split(text, ',')) {
        if (item == "c") {
            out.push_back(PaddingRecord{.copy_payload = true});
            continue;
        }
        const auto dash = item.find('-');
        if (dash == std::string_view::npos) {
            continue;
        }
        auto min_value = ParseInt(item.substr(0, dash));
        auto max_value = ParseInt(item.substr(dash + 1));
        if (!min_value || !max_value) {
            continue;
        }
        int lo = *min_value;
        int hi = *max_value;
        if (lo > hi) {
            std::swap(lo, hi);
        }
        if (lo <= 0 || hi <= 0) {
            continue;
        }
        out.push_back(PaddingRecord{
            .copy_payload = false,
            .min_size = lo,
            .max_size_exclusive = hi == lo ? lo : hi,
        });
    }
    return out;
}

const std::vector<PaddingRecord>* FindPaddingRecord(
    const PaddingScheme& scheme,
    uint32_t packet_index) noexcept {
    if (packet_index >= scheme.stop ||
        packet_index >= scheme.records.size() ||
        scheme.records[packet_index].empty()) {
        return nullptr;
    }
    return &scheme.records[packet_index];
}

int GenerateRecordPayloadSize(const PaddingRecord& record) {
    if (record.copy_payload) {
        return -1;
    }
    if (record.min_size <= 0 || record.max_size_exclusive <= 0) {
        return 0;
    }
    if (record.min_size == record.max_size_exclusive) {
        return record.min_size;
    }
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(
        record.min_size,
        record.max_size_exclusive - 1);
    return dist(rng);
}

}  // namespace

net::awaitable<std::expected<void, ErrorCode>>
WriteMultiBufferAsFrameBatch(AsyncStream& stream,
                             uint8_t cmd,
                             uint32_t sid,
                             buf::MultiBuffer mb) {
    co_return co_await WriteMultiBufferAsFrameBatchImpl(
        stream, cmd, sid, std::move(mb));
}

PaddingScheme DefaultPaddingScheme() {
    static constexpr std::string_view kRaw =
        "stop=8\n"
        "0=30-30\n"
        "1=100-400\n"
        "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
        "3=9-9,500-1000\n"
        "4=500-1000\n"
        "5=500-1000\n"
        "6=500-1000\n"
        "7=500-1000";
    return *ParsePaddingScheme(kRaw);
}

std::optional<PaddingScheme> ParsePaddingScheme(std::string_view raw) {
    if (raw.empty()) {
        return std::nullopt;
    }
    PaddingScheme scheme;
    scheme.raw.assign(raw);
    scheme.md5 = Md5Hex(raw);
    size_t parsed_records = 0;
    for (auto line : Split(raw, '\n')) {
        const auto eq = line.find('=');
        if (eq == std::string_view::npos) {
            continue;
        }
        const auto key = line.substr(0, eq);
        const auto value = line.substr(eq + 1);
        if (key == "stop") {
            auto stop = ParseInt(value);
            if (!stop || *stop <= 0) {
                return std::nullopt;
            }
            scheme.stop = static_cast<uint32_t>(*stop);
            continue;
        }

        auto index = ParseInt(key);
        if (!index || *index < 0) {
            continue;
        }

        auto record = ParsePaddingRecord(value);
        if (record.empty()) {
            continue;
        }
        const auto record_index = static_cast<size_t>(*index);
        if (record_index >= scheme.records.size()) {
            scheme.records.resize(record_index + 1);
        }
        if (scheme.records[record_index].empty()) {
            ++parsed_records;
        }
        scheme.records[record_index] = std::move(record);
    }
    if (scheme.stop == 0 || parsed_records == 0) {
        return std::nullopt;
    }
    return scheme;
}

uint16_t AuthPaddingSize(const PaddingScheme& scheme) noexcept {
    const auto* record = FindPaddingRecord(scheme, 0);
    if (record && !record->front().copy_payload) {
        const int size = record->front().min_size;
        if (size > 0 && size <= 0xffff) {
            return static_cast<uint16_t>(size);
        }
    }
    return kDefaultAuthPaddingSize;
}

std::string DefaultClientSettings() {
    return "v=2\nclient=xray\npadding-md5=" + DefaultPaddingScheme().md5;
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
            co_return std::unexpected(MapWriteException(e));
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
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
        co_return std::unexpected(MapWriteException(e));
    } catch (...) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
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

    const auto* record_rules = FindPaddingRecord(scheme, packet_index);
    if (!record_rules) {
        co_return co_await WriteAll(
            stream,
            std::span<const uint8_t>(packet.data(), packet.size()));
    }

    size_t offset = 0;
    memory::ByteVector record;
    for (const PaddingRecord& rule : *record_rules) {
        const int size = GenerateRecordPayloadSize(rule);
        if (size == -1) {
            if (offset >= packet.size()) {
                break;
            }
            continue;
        }
        if (size <= static_cast<int>(kFrameHeaderSize) ||
            size >= static_cast<int>(buf::Buffer::kSize)) {
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }

        record.clear();
        const size_t remaining = packet.size() - offset;
        if (remaining > static_cast<size_t>(size)) {
            const auto* data = packet.data() + offset;
            record.assign(data, data + static_cast<size_t>(size));
            offset += static_cast<size_t>(size);
        } else if (remaining > 0) {
            const auto* data = packet.data() + offset;
            record.assign(data, data + remaining);
            offset = packet.size();
            const int padding =
                size - static_cast<int>(remaining) - static_cast<int>(kFrameHeaderSize);
            if (padding > 0) {
                const auto& zeros = ZeroPaddingBlock();
                auto waste = AppendFrameBytesTo(
                    record,
                    kCmdWaste,
                    0,
                    std::span<const uint8_t>(zeros.data(), static_cast<size_t>(padding)));
                if (!waste) {
                    co_return std::unexpected(waste.error());
                }
            }
        } else {
            const auto& zeros = ZeroPaddingBlock();
            auto waste = AppendFrameBytesTo(
                record,
                kCmdWaste,
                0,
                std::span<const uint8_t>(zeros.data(), static_cast<size_t>(size)));
            if (!waste) {
                co_return std::unexpected(waste.error());
            }
        }

        if (!record.empty()) {
            auto ok = co_await WriteAll(
                stream,
                std::span<const uint8_t>(record.data(), record.size()));
            if (!ok) {
                co_return std::unexpected(ok.error());
            }
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
    if (!FindPaddingRecord(scheme, packet_index)) {
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
    if (!FindPaddingRecord(scheme, packet_index)) {
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
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
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
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
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
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
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
            } catch (...) {
                co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
            }
        }
        buffer->Produce(static_cast<uint32_t>(want));
        remaining -= want;
        mb.push_back(buffer.release());
    }
    co_return mb;
}

}  // namespace acpp::anytls
