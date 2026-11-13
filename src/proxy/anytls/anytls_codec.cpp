#include "proxy/anytls/anytls_codec.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/anytls_padding.hpp"
#include "common/byte_reader.hpp"
#include "common/binary_text_codec.hpp"
#include "common/const_buffer_span.hpp"
#include "transport/async_stream.hpp"

#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <random>
#include <utility>
#include <string>
#include <vector>

namespace proxy {


namespace {

std::array<uint8_t, kFrameHeaderSize> BuildFrameHeaderBytes(
    uint8_t cmd,
    uint32_t sid,
    size_t payload_size) noexcept {
    std::array<uint8_t, kFrameHeaderSize> header{};
    header[0] = cmd;
    common::StoreU32BE(header.data() + 1, sid);
    common::StoreU16BE(header.data() + 5, static_cast<uint16_t>(payload_size));
    return header;
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

tl::expected<void, common::ErrorCode> FrameBatch::Encode(
    uint8_t cmd, uint32_t sid, const common::MultiBuffer& payload) {
    const auto bytes = payload.FrontSpan();
    const net::const_buffer single(bytes.data(), bytes.size());
    return Encode(cmd, sid, {&single, bytes.empty() ? size_t{0} : size_t{1}});
}

tl::expected<void, common::ErrorCode> FrameBatch::Encode(
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
                return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
            }
            remaining = remaining.subspan(chunk_size);
        }
    }
    return {};
}

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteMultiBufferAsFrameBatch(transport::AsyncStream& stream,
                             uint8_t cmd,
                             uint32_t sid,
                             common::MultiBuffer mb) {
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
            co_return tl::unexpected(common::MapAsioError(e.code()));
        }
    }
    mb.clear();
    co_return tl::expected<void, common::ErrorCode>{};
}

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteBuffersAsFrameBatch(transport::AsyncStream& stream,
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
            co_return tl::unexpected(common::MapAsioError(e.code()));
        }
    }
    co_return tl::expected<void, common::ErrorCode>{};
}

tl::expected<PeerSettings, common::ErrorCode> ParsePeerSettings(std::string_view text) {
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
            return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        const auto key = line.substr(0, separator);
        const auto value = line.substr(separator + 1);
        if (key == "v") {
            if (std::exchange(has_version, true) || value.empty())
                return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            uint32_t peer_version = 0;
            const auto [ptr, error] = std::from_chars(value.data(), value.data() + value.size(), peer_version);
            if (error != std::errc{} || ptr != value.data() + value.size() || peer_version == 0)
                return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            result.version = std::min(peer_version, kProtocolVersion) >= 2
                ? SessionVersion::V2 : SessionVersion::V1;
        } else if (key == "padding-md5") {
            if (std::exchange(has_padding_md5, true))
                return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            result.padding_md5 = value;
        }
        // Unknown well-formed keys belong to extensions, never feature gates.
    }
    return result;
}

std::string ClientSettings(const AnyTlsPaddingScheme& scheme) {
    std::string settings;
    const auto& digest = scheme.Digest();
    settings.reserve(28 + digest.size());
    settings.append("v=2\nclient=cnode\npadding-md5=");
    settings.append(digest);
    return settings;
}


tl::expected<void, common::ErrorCode> AppendFrameBytesTo(
    std::vector<uint8_t>& out,
    uint8_t cmd,
    uint32_t sid,
    std::span<const uint8_t> payload) {
    if (payload.size() > kMaxFramePayload) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    const auto header = BuildFrameHeaderBytes(cmd, sid, payload.size());
    const size_t offset = out.size();
    out.resize(offset + header.size() + payload.size());
    std::memcpy(out.data() + offset, header.data(), header.size());
    if (!payload.empty()) {
        std::memcpy(out.data() + offset + kFrameHeaderSize, payload.data(), payload.size());
    }
    return tl::expected<void, common::ErrorCode>{};
}

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteAll(transport::AsyncStream& stream, std::span<const uint8_t> data) {
    while (!data.empty()) {
        try {
            const auto n = co_await stream.AsyncWrite(net::buffer(data.data(), data.size()));
            if (n == 0) {
                co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
            }
            data = data.subspan(n);
        } catch (const IoSystemError& e) {
            co_return tl::unexpected(common::MapAsioError(e.code()));
        }
    }
    co_return tl::expected<void, common::ErrorCode>{};
}

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteFrame(transport::AsyncStream& stream, uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
    if (payload.size() > kMaxFramePayload) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    auto header = BuildFrameHeaderBytes(cmd, sid, payload.size());
    std::array<net::const_buffer, 2> buffers{
        net::const_buffer(header.data(), header.size()),
        net::const_buffer(payload.data(), payload.size())};
    try {
        co_await stream.WriteBuffers(buffers);
    } catch (const IoSystemError& e) {
        co_return tl::unexpected(common::MapAsioError(e.code()));
    }
    co_return tl::expected<void, common::ErrorCode>{};
}

static net::awaitable<tl::expected<void, common::ErrorCode>>
WriteSlicesWithPadding(transport::AsyncStream& stream,
                       std::span<const PaddingRecord> record_rules,
                       std::span<const net::const_buffer> buffers) {
    size_t remaining = 0;
    for (const net::const_buffer& buf : buffers) {
        remaining += buf.size();
    }
    if (remaining == 0) {
        co_return tl::expected<void, common::ErrorCode>{};
    }
    auto write_span = [&stream](std::span<const net::const_buffer> out)
        -> net::awaitable<tl::expected<void, common::ErrorCode>> {
        if (out.empty()) {
            co_return tl::expected<void, common::ErrorCode>{};
        }
        try {
            co_await stream.WriteBuffers(out);
        } catch (const IoSystemError& e) {
            co_return tl::unexpected(common::MapAsioError(e.code()));
        }
        co_return tl::expected<void, common::ErrorCode>{};
    };
    if (record_rules.empty()) {
        co_return co_await write_span(buffers);
    }

    static constexpr std::array<uint8_t, 16384> kZeroWaste{};
    size_t buf_idx = 0;
    size_t buf_off = 0;
    auto append_data = [&](auto& out, size_t count) {
        remaining -= count;
        while (count > 0) {
            while (buf_idx < buffers.size() && buffers[buf_idx].size() <= buf_off) {
                ++buf_idx;
                buf_off = 0;
            }
            const auto* ptr = static_cast<const uint8_t*>(buffers[buf_idx].data()) + buf_off;
            const size_t avail = buffers[buf_idx].size() - buf_off;
            const size_t take = std::min(count, avail);
            out.Append(net::const_buffer(ptr, take));
            buf_off += take;
            count -= take;
        }
    };
    auto append_waste = [](auto& out,
                           std::array<uint8_t, kFrameHeaderSize>& header_buf,
                           uint16_t payload_size) {
        header_buf = BuildFrameHeaderBytes(kCmdWaste, 0, payload_size);
        out.Append(net::const_buffer(header_buf.data(), header_buf.size()));
        size_t zeros = payload_size;
        while (zeros > 0) {
            const size_t chunk = std::min(zeros, kZeroWaste.size());
            out.Append(net::const_buffer(kZeroWaste.data(), chunk));
            zeros -= chunk;
        }
    };

    for (const PaddingRecord& rule : record_rules) {
        const int sampled_size = rule.SampleSize();
        if (sampled_size == -1) {
            if (remaining == 0) {
                break;
            }
            continue;
        }
        // Compiled records are positive and every possible Waste fits uint16.
        const size_t size = static_cast<size_t>(sampled_size);
        common::ConstBufferSpanBuilder<8> out;
        std::array<uint8_t, kFrameHeaderSize> waste_header{};
        if (remaining >= size) {
            append_data(out, size);
        } else if (remaining > 0) {
            const size_t tail = remaining;
            append_data(out, tail);
            if (size - tail > kFrameHeaderSize) {
                append_waste(out, waste_header,
                             static_cast<uint16_t>(size - tail - kFrameHeaderSize));
            }
        } else {
            append_waste(out, waste_header, static_cast<uint16_t>(size));
        }
        auto ok = co_await write_span(out.Span());
        if (!ok) {
            co_return tl::unexpected(ok.error());
        }
    }
    if (remaining > 0) {
        common::ConstBufferSpanBuilder<8> tail_out;
        append_data(tail_out, remaining);
        co_return co_await write_span(tail_out.Span());
    }
    co_return tl::expected<void, common::ErrorCode>{};
}

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteAnyTlsPacketWithPadding(transport::AsyncStream& stream,
                             std::span<const PaddingRecord> record_rules,
                             std::vector<uint8_t> packet) {
    const net::const_buffer single(packet.data(), packet.size());
    co_return co_await WriteSlicesWithPadding(
        stream, record_rules, {&single, packet.empty() ? size_t{0} : size_t{1}});
}

static net::awaitable<tl::expected<void, common::ErrorCode>>
WritePaddedMultiBufferFrames(transport::AsyncStream& stream,
                             std::span<const PaddingRecord> records,
                             uint8_t cmd,
                             uint32_t sid,
                             common::MultiBuffer mb) {
    FrameBatch batch;
    auto encoded = batch.Encode(cmd, sid, mb);
    if (!encoded) {
        mb.clear();
        co_return encoded;
    }
    auto res = co_await WriteSlicesWithPadding(stream, records, batch.Buffers());
    mb.clear();
    co_return res;
}

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteAnyTlsMultiBufferAsFramesWithPadding(transport::AsyncStream& stream,
                                    const AnyTlsPaddingScheme& scheme,
                                    uint32_t packet_index,
                                    uint8_t cmd,
                                    uint32_t sid,
                                    common::MultiBuffer mb) {
    const auto records = scheme.RecordFor(packet_index);
    if (records.empty()) {
        return WriteMultiBufferAsFrameBatch(stream, cmd, sid, std::move(mb));
    }
    return WritePaddedMultiBufferFrames(stream, records, cmd, sid, std::move(mb));
}

static net::awaitable<tl::expected<void, common::ErrorCode>>
WritePaddedBufferFrames(transport::AsyncStream& stream,
                        std::span<const PaddingRecord> records,
                        uint8_t cmd,
                        uint32_t sid,
                        std::span<const net::const_buffer> buffers) {
    FrameBatch batch;
    auto encoded = batch.Encode(cmd, sid, buffers);
    if (!encoded) {
        co_return encoded;
    }
    co_return co_await WriteSlicesWithPadding(stream, records, batch.Buffers());
}

net::awaitable<tl::expected<void, common::ErrorCode>>
WriteAnyTlsBuffersAsFramesWithPadding(transport::AsyncStream& stream,
                                const AnyTlsPaddingScheme& scheme,
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

net::awaitable<tl::expected<AnyTlsFrameHeader, common::ErrorCode>>
ReadAnyTlsFrameHeader(transport::AsyncStream& stream) {
    std::array<uint8_t, kFrameHeaderSize> header{};
    if (auto ok = co_await proxy::ReadHandshakeExact(stream, header, proxy::HandshakeProgress::NotStarted); !ok) {
        co_return tl::unexpected(ok.error());
    }

    AnyTlsFrameHeader out;
    out.cmd = header[0];
    out.sid = common::LoadU32BE(header.data() + 1);
    out.length = common::LoadU16BE(header.data() + 5);
    co_return out;
}

net::awaitable<tl::expected<std::string, common::ErrorCode>>
ReadFrameText(transport::AsyncStream& stream, uint16_t length) {
    std::string text(length, '\0');
    if (auto ok = co_await proxy::ReadHandshakeExact(
            stream,
            std::span<uint8_t>(reinterpret_cast<uint8_t*>(text.data()), length),
            proxy::HandshakeProgress::Started);
        !ok) {
        co_return tl::unexpected(ok.error());
    }
    co_return text;
}

net::awaitable<tl::expected<void, common::ErrorCode>>
DiscardFramePayload(transport::AsyncStream& stream, uint16_t length) {
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
    co_return tl::expected<void, common::ErrorCode>{};
}

net::awaitable<tl::expected<common::MultiBuffer, common::ErrorCode>>
ReadFramePayload(transport::AsyncStream& stream, uint16_t length) {
    common::MultiBuffer mb;
    size_t remaining = length;
    while (remaining > 0) {
        common::BufferGuard buffer{common::Buffer::New()};
        if (!buffer) {
            co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
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

std::span<const PaddingRecord> AnyTlsPaddingScheme::RecordFor(uint32_t index) const noexcept {
    if (index >= stop_) return {};
    const auto found = std::lower_bound(records_.begin(), records_.end(), index,
        [](const PacketPadding& record, uint32_t value) { return record.index < value; });
    return found != records_.end() && found->index == index
        ? std::span<const PaddingRecord>(found->ranges) : std::span<const PaddingRecord>{};
}

uint16_t AnyTlsPaddingScheme::SampleAuthPaddingSize() const {
    return static_cast<uint16_t>(SampleRange(auth_padding_.min_size,
        static_cast<int>(auth_padding_.max_size_exclusive)));
}

std::optional<AnyTlsPaddingScheme> ParseAnyTlsPaddingScheme(std::string_view raw) {
    if (raw.empty()) return std::nullopt;
    AnyTlsPaddingScheme scheme;
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
                    [idx = *index](const AnyTlsPaddingScheme::PacketPadding& entry) {
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
    scheme.md5_ = common::EncodeHexLower(
        std::span<const uint8_t>(digest.data(), size));
    std::sort(scheme.records_.begin(), scheme.records_.end(),
        [](const AnyTlsPaddingScheme::PacketPadding& lhs, const AnyTlsPaddingScheme::PacketPadding& rhs) {
            return lhs.index < rhs.index;
        });
    return scheme;
}

const std::shared_ptr<const AnyTlsPaddingScheme>& DefaultAnyTlsPaddingScheme() {
    static const auto scheme = std::make_shared<const AnyTlsPaddingScheme>(ParseAnyTlsPaddingScheme(
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
}  // namespace proxy
