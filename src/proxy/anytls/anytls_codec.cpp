#include "proxy/anytls/anytls_codec.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/anytls_padding.hpp"
#include "common/byte_reader.hpp"
#include "common/allocator.hpp"
#include "transport/async_stream.hpp"

#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <random>
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


template<class Integer>
std::optional<Integer> ParseInteger(std::string_view text) {
    if (text.empty()) return std::nullopt;
    Integer value = 0;
    const auto [ptr, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

std::string_view Trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r'))
        text.remove_suffix(1);
    return text;
}

std::optional<std::string_view> NextToken(std::string_view& text, char delimiter) {
    while (!text.empty()) {
        const auto end = text.find(delimiter);
        const auto item = Trim(text.substr(0, end));
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        if (!item.empty()) return item;
    }
    return std::nullopt;
}

struct SizeRange {
    int min;
    int max;

    int LargestSize() const noexcept { return min == max ? max : max - 1; }
};

std::optional<SizeRange> ParseRange(std::string_view text) {
    text = Trim(text);
    const auto dash = text.find('-');
    if (dash == std::string_view::npos) return std::nullopt;
    auto lo = ParseInteger<int>(text.substr(0, dash));
    auto hi = ParseInteger<int>(text.substr(dash + 1));
    if (!lo || !hi) return std::nullopt;
    if (*lo > *hi) std::swap(lo, hi);
    return SizeRange{*lo, *hi};
}

int SampleRange(int lo, int hi) {
    if (lo == hi) return lo;
    static thread_local std::mt19937 rng{std::random_device{}()};
    return std::uniform_int_distribution<int>(lo, hi - 1)(rng);
}

std::optional<std::vector<PaddingRecord>> ParseRanges(std::string_view text) {
    std::vector<PaddingRecord> ranges;
    while (const auto token = NextToken(text, ',')) {
        if (*token == "c") {
            ranges.push_back(PaddingRecord{.copy_payload = true});
            continue;
        }
        const auto range = ParseRange(*token);
        if (!range || range->min <= 0) continue;
        // Any record may become a pure Waste with one uint16 payload length.
        if (range->LargestSize() > UINT16_MAX) return std::nullopt;
        ranges.push_back(PaddingRecord{false, range->min, range->max});
    }
    return ranges;
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

memory::String ClientSettings(const PaddingScheme& scheme) {
    memory::String settings;
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
    const auto header = BuildFrameHeaderBytes(cmd, sid, payload.size());
    const size_t offset = out.size();
    out.resize(offset + header.size() + payload.size());
    std::memcpy(out.data() + offset, header.data(), header.size());
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
                       std::span<const PaddingRecord> record_rules,
                       memory::ByteVector packet) {
    if (packet.empty()) {
        co_return tl::expected<void, ErrorCode>{};
    }

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
        std::span<const uint8_t> output;
        if (remaining >= size) {
            output = std::span<const uint8_t>(packet).subspan(offset, size);
            offset += size;
        } else if (remaining > 0) {
            const size_t chunk_offset = offset;
            if (size - remaining > kFrameHeaderSize) {
                AppendWaste(packet, static_cast<uint16_t>(size - remaining - kFrameHeaderSize));
            }
            offset = packet.size();
            output = std::span<const uint8_t>(packet).subspan(chunk_offset);
        } else {
            packet.clear();
            AppendWaste(packet, static_cast<uint16_t>(size));
            offset = packet.size();
            output = packet;
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

net::awaitable<tl::expected<void, ErrorCode>>
WritePacketWithPadding(AsyncStream& stream,
                       const PaddingScheme& scheme,
                       uint32_t packet_index,
                       memory::ByteVector packet) {
    return WritePacketWithPadding(stream, scheme.RecordFor(packet_index), std::move(packet));
}

static net::awaitable<tl::expected<void, ErrorCode>>
WritePaddedMultiBufferFrames(AsyncStream& stream,
                             std::span<const PaddingRecord> records,
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
    co_return co_await WritePacketWithPadding(stream, records, std::move(packet));
}

net::awaitable<tl::expected<void, ErrorCode>>
WriteMultiBufferAsFramesWithPadding(AsyncStream& stream,
                                    const PaddingScheme& scheme,
                                    uint32_t packet_index,
                                    uint8_t cmd,
                                    uint32_t sid,
                                    buf::MultiBuffer mb) {
    const auto records = scheme.RecordFor(packet_index);
    if (records.empty()) {
        return WriteMultiBufferAsFrameBatch(stream, cmd, sid, std::move(mb));
    }
    return WritePaddedMultiBufferFrames(stream, records, cmd, sid, std::move(mb));
}

static net::awaitable<tl::expected<void, ErrorCode>>
WritePaddedBufferFrames(AsyncStream& stream,
                        std::span<const PaddingRecord> records,
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
    co_return co_await WritePacketWithPadding(stream, records, std::move(packet));
}

net::awaitable<tl::expected<void, ErrorCode>>
WriteBuffersAsFramesWithPadding(AsyncStream& stream,
                                const PaddingScheme& scheme,
                                uint32_t packet_index,
                                uint8_t cmd,
                                uint32_t sid,
                                std::span<const net::const_buffer> buffers) {
    const auto records = scheme.RecordFor(packet_index);
    if (records.empty()) {
        return WriteBuffersAsFrameBatch(stream, cmd, sid, buffers);
    }
    return WritePaddedBufferFrames(stream, records, cmd, sid, buffers);
}

net::awaitable<tl::expected<FrameHeader, ErrorCode>>
ReadFrameHeader(AsyncStream& stream) {
    std::array<uint8_t, kFrameHeaderSize> header{};
    if (auto ok = co_await proxy::ReadHandshakeExact(stream, header, proxy::HandshakeProgress::NotStarted); !ok) {
        co_return tl::unexpected(ok.error());
    }

    FrameHeader out;
    out.cmd = header[0];
    out.sid = LoadU32BE(header.data() + 1);
    out.length = LoadU16BE(header.data() + 5);
    co_return out;
}

net::awaitable<tl::expected<memory::String, ErrorCode>>
ReadFrameText(AsyncStream& stream, uint16_t length) {
    memory::String text(length, '\0');
    if (auto ok = co_await proxy::ReadHandshakeExact(
            stream,
            std::span<uint8_t>(reinterpret_cast<uint8_t*>(text.data()), length),
            proxy::HandshakeProgress::Started);
        !ok) {
        co_return tl::unexpected(ok.error());
    }
    co_return text;
}

net::awaitable<tl::expected<void, ErrorCode>>
DiscardFramePayload(AsyncStream& stream, uint16_t length) {
    std::array<uint8_t, 256> scratch{};
    size_t remaining = length;
    while (remaining > 0) {
        const size_t want = std::min(remaining, scratch.size());
        if (auto ok = co_await proxy::ReadHandshakeExact(
                stream, std::span<uint8_t>(scratch.data(), want), proxy::HandshakeProgress::Started);
            !ok) {
            co_return tl::unexpected(ok.error());
        }
        remaining -= want;
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
        if (auto ok = co_await proxy::ReadHandshakeExact(
                stream, std::span<uint8_t>(buffer->Tail().data(), want), proxy::HandshakeProgress::Started);
            !ok) {
            co_return tl::unexpected(ok.error());
        }
        buffer->Produce(static_cast<uint32_t>(want));
        remaining -= want;
        mb.push_back(std::move(buffer));
    }
    co_return mb;
}


int PaddingRecord::SampleSize() const {
    if (copy_payload) return -1;
    if (min_size <= 0 || max_size_exclusive <= 0) return 0;
    return SampleRange(min_size, max_size_exclusive);
}

std::span<const PaddingRecord> PaddingScheme::RecordFor(uint32_t index) const noexcept {
    if (index >= stop_) return {};
    const auto found = std::lower_bound(records_.begin(), records_.end(), index,
        [](const PacketPadding& record, uint32_t value) { return record.index < value; });
    return found != records_.end() && found->index == index
        ? std::span<const PaddingRecord>(found->ranges) : std::span<const PaddingRecord>{};
}

uint16_t PaddingScheme::SampleAuthPaddingSize() const {
    return static_cast<uint16_t>(SampleRange(auth_padding_.min_size,
        static_cast<int>(auth_padding_.max_size_exclusive)));
}

std::optional<PaddingScheme> ParsePaddingScheme(std::string_view raw) {
    if (raw.empty()) return std::nullopt;
    PaddingScheme scheme;
    auto text = raw;
    while (const auto line = NextToken(text, '\n')) {
        const auto separator = line->find('=');
        if (separator == std::string_view::npos) continue;
        const auto key = line->substr(0, separator);
        const auto value = line->substr(separator + 1);
        if (key == "stop") {
            const auto stop = ParseInteger<uint32_t>(value);
            if (!stop || *stop == 0) return std::nullopt;
            scheme.stop_ = *stop;
        } else if (const auto index = ParseInteger<uint32_t>(key)) {
            if (*index == 0) {
                // Authentication carries one uint16 length, never frame splitting or 'c'.
                const auto range = ParseRange(value);
                if (!range || range->min < 0 || (range->min == 0 && range->max != 0))
                    return std::nullopt;
                if (range->LargestSize() > UINT16_MAX) return std::nullopt;
                scheme.auth_padding_ = {static_cast<uint16_t>(range->min),
                    static_cast<uint32_t>(range->max)};
                continue;
            }
            auto ranges = ParseRanges(value);
            if (!ranges) return std::nullopt;
            // Preserve the last valid entry, including when a later duplicate is invalid.
            if (!ranges->empty()) {
                auto existing = std::find_if(
                    scheme.records_.begin(),
                    scheme.records_.end(),
                    [idx = *index](const PaddingScheme::PacketPadding& entry) {
                        return entry.index == idx;
                    });
                if (existing != scheme.records_.end()) {
                    existing->ranges = std::move(*ranges);
                } else {
                    scheme.records_.push_back({*index, std::move(*ranges)});
                }
            }
        }
    }
    if (scheme.stop_ == 0) return std::nullopt;
    scheme.raw_.assign(raw);
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size = 0;
    if (EVP_Digest(raw.data(), raw.size(), digest.data(), &size, EVP_md5(), nullptr) != 1)
        return std::nullopt;
    static constexpr char kHex[] = "0123456789abcdef";
    scheme.md5_.reserve(size * 2);
    for (unsigned int index = 0; index < size; ++index) {
        scheme.md5_.push_back(kHex[digest[index] >> 4]);
        scheme.md5_.push_back(kHex[digest[index] & 0xf]);
    }
    std::sort(scheme.records_.begin(), scheme.records_.end(),
        [](const PaddingScheme::PacketPadding& lhs, const PaddingScheme::PacketPadding& rhs) {
            return lhs.index < rhs.index;
        });
    return scheme;
}

const std::shared_ptr<const PaddingScheme>& DefaultPaddingScheme() {
    static const auto scheme = std::make_shared<const PaddingScheme>(ParsePaddingScheme(
        "stop=8\n"
        "0=30-30\n"
        "1=100-400\n"
        "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
        "3=9-9,500-1000\n"
        "4=500-1000\n"
        "5=500-1000\n"
        "6=500-1000\n"
        "7=500-1000").value());
    return scheme;
}
}  // namespace anytls
