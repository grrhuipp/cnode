#include "anytls_codec.hpp"

#include "acppnode/transport/async_stream.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <openssl/evp.h>
#include <random>

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

ErrorCode MapWriteException(const IoSystemError& e) noexcept {
    return MapAsioError(e.code());
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

std::vector<int> GenerateRecordPayloadSizes(const PaddingScheme& scheme, uint32_t packet_index) {
    auto it = scheme.records.find(std::to_string(packet_index));
    if (it == scheme.records.end()) {
        return {};
    }

    static thread_local std::mt19937 rng{std::random_device{}()};
    std::vector<int> out;
    for (auto item : Split(it->second, ',')) {
        if (item == "c") {
            out.push_back(-1);
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
        if (lo == hi) {
            out.push_back(lo);
        } else {
            std::uniform_int_distribution<int> dist(lo, hi - 1);
            out.push_back(dist(rng));
        }
    }
    return out;
}

}  // namespace

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
    for (auto line : Split(raw, '\n')) {
        const auto eq = line.find('=');
        if (eq == std::string_view::npos) {
            continue;
        }
        std::string key(line.substr(0, eq));
        std::string value(line.substr(eq + 1));
        if (key == "stop") {
            auto stop = ParseInt(value);
            if (!stop || *stop <= 0) {
                return std::nullopt;
            }
            scheme.stop = static_cast<uint32_t>(*stop);
        }
        scheme.records.emplace(std::move(key), std::move(value));
    }
    if (scheme.stop == 0 || scheme.records.empty()) {
        return std::nullopt;
    }
    return scheme;
}

uint16_t AuthPaddingSize(const PaddingScheme& scheme) noexcept {
    auto sizes = GenerateRecordPayloadSizes(scheme, 0);
    if (!sizes.empty() && sizes.front() > 0 && sizes.front() <= 0xffff) {
        return static_cast<uint16_t>(sizes.front());
    }
    return kDefaultAuthPaddingSize;
}

std::string DefaultClientSettings() {
    return "v=2\nclient=xray\npadding-md5=" + DefaultPaddingScheme().md5;
}

std::expected<std::string, ErrorCode> EncodeSocksAddress(const TargetAddress& target) {
    if (!target.IsValid() && !IsUotMagicAddress(target)) {
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

bool IsUotMagicAddress(const TargetAddress& target) noexcept {
    return target.IsDomain() && target.host.find(kUotMagicAddress) != std::string::npos;
}

std::expected<std::string, ErrorCode> EncodeUotRequest(
    const TargetAddress& target,
    bool is_connect) {
    auto encoded_target = EncodeSocksAddress(target);
    if (!encoded_target) {
        return std::unexpected(encoded_target.error());
    }
    std::string out;
    out.reserve(1 + encoded_target->size());
    out.push_back(is_connect ? '\x01' : '\x00');
    out.append(*encoded_target);
    return out;
}

std::expected<UotRequest, ErrorCode> DecodeUotRequest(std::span<const uint8_t> data) {
    if (data.size() < 1 + 1 + 2) {
        return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    UotRequest request;
    request.is_connect = data[0] != 0;
    size_t offset = 1;
    const uint8_t atype = data[offset++];
    if (atype == 0x01) {
        if (data.size() < offset + 4 + 2) {
            return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        net::ip::address_v4::bytes_type bytes{};
        std::copy_n(data.data() + offset, bytes.size(), bytes.begin());
        offset += bytes.size();
        const uint16_t port = ReadU16BE(data.data() + offset);
        offset += 2;
        request.destination = TargetAddress(net::ip::make_address_v4(bytes), port);
    } else if (atype == 0x04) {
        if (data.size() < offset + 16 + 2) {
            return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        net::ip::address_v6::bytes_type bytes{};
        std::copy_n(data.data() + offset, bytes.size(), bytes.begin());
        offset += bytes.size();
        const uint16_t port = ReadU16BE(data.data() + offset);
        offset += 2;
        request.destination = TargetAddress(net::ip::make_address_v6(bytes), port);
    } else if (atype == 0x03) {
        if (data.size() < offset + 1) {
            return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        const uint8_t host_len = data[offset++];
        if (host_len == 0 || data.size() < offset + host_len + 2) {
            return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        std::string_view host(
            reinterpret_cast<const char*>(data.data() + offset),
            host_len);
        offset += host_len;
        const uint16_t port = ReadU16BE(data.data() + offset);
        offset += 2;
        request.destination = TargetAddress(host, port);
    } else {
        return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }

    request.consumed = offset;
    return request;
}

std::expected<std::string, ErrorCode> BuildFrameBytes(
    uint8_t cmd,
    uint32_t sid,
    std::span<const uint8_t> payload) {
    if (payload.size() > kMaxFramePayload) {
        return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    std::string out(kFrameHeaderSize + payload.size(), '\0');
    auto* header = reinterpret_cast<uint8_t*>(out.data());
    header[0] = cmd;
    WriteU32BE(header + 1, sid);
    WriteU16BE(header + 5, static_cast<uint16_t>(payload.size()));
    if (!payload.empty()) {
        std::memcpy(out.data() + kFrameHeaderSize, payload.data(), payload.size());
    }
    return out;
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
                       std::string packet) {
    if (packet.empty()) {
        co_return std::expected<void, ErrorCode>{};
    }

    auto sizes = GenerateRecordPayloadSizes(scheme, packet_index);
    if (packet_index >= scheme.stop || sizes.empty()) {
        co_return co_await WriteAll(
            stream,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(packet.data()),
                packet.size()));
    }

    size_t offset = 0;
    for (int size : sizes) {
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

        std::string record;
        const size_t remaining = packet.size() - offset;
        if (remaining > static_cast<size_t>(size)) {
            record.assign(packet.data() + offset, static_cast<size_t>(size));
            offset += static_cast<size_t>(size);
        } else if (remaining > 0) {
            record.assign(packet.data() + offset, remaining);
            offset = packet.size();
            const int padding =
                size - static_cast<int>(remaining) - static_cast<int>(kFrameHeaderSize);
            if (padding > 0) {
                std::string zeros(static_cast<size_t>(padding), '\0');
                auto waste = BuildFrameBytes(
                    kCmdWaste,
                    0,
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(zeros.data()),
                        zeros.size()));
                if (!waste) {
                    co_return std::unexpected(waste.error());
                }
                record.append(*waste);
            }
        } else {
            std::string zeros(static_cast<size_t>(size), '\0');
            auto waste = BuildFrameBytes(
                kCmdWaste,
                0,
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(zeros.data()),
                    zeros.size()));
            if (!waste) {
                co_return std::unexpected(waste.error());
            }
            record = std::move(*waste);
        }

        if (!record.empty()) {
            auto ok = co_await WriteAll(
                stream,
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(record.data()),
                    record.size()));
            if (!ok) {
                co_return std::unexpected(ok.error());
            }
        }
    }

    if (offset < packet.size()) {
        co_return co_await WriteAll(
            stream,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(packet.data() + offset),
                packet.size() - offset));
    }
    co_return std::expected<void, ErrorCode>{};
}

net::awaitable<std::expected<void, ErrorCode>>
WriteMultiBufferAsFrames(AsyncStream& stream, uint8_t cmd, uint32_t sid, buf::MultiBuffer mb) {
    for (auto* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        if (bytes.size() > kMaxFramePayload) {
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
        if (auto ok = co_await WriteFrame(stream, cmd, sid, bytes); !ok) {
            co_return std::unexpected(ok.error());
        }
    }
    mb.clear();
    co_return std::expected<void, ErrorCode>{};
}

net::awaitable<std::expected<void, ErrorCode>>
WriteMultiBufferAsFramesWithPadding(AsyncStream& stream,
                                    const PaddingScheme& scheme,
                                    uint32_t packet_index,
                                    uint8_t cmd,
                                    uint32_t sid,
                                    buf::MultiBuffer mb) {
    std::string packet;
    packet.reserve(buf::TotalLen(mb) + (mb.size() * kFrameHeaderSize));
    for (auto* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        auto frame = BuildFrameBytes(cmd, sid, buffer->Bytes());
        if (!frame) {
            co_return std::unexpected(frame.error());
        }
        packet.append(*frame);
    }
    mb.clear();
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
