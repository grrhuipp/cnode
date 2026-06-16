#include "vless_vision.hpp"

#include "acppnode/common/error.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <algorithm>
#include <cstring>
#include <openssl/rand.h>

namespace acpp::vless {

namespace {

constexpr size_t kVisionBaseHeaderLen = 1 + 2 + 2;
constexpr size_t kVisionUuidHeaderLen = 16 + kVisionBaseHeaderLen;
constexpr size_t kVisionFrameContentLimit = 8192 - kVisionUuidHeaderLen;

constexpr uint8_t kCommandPaddingContinue = 0x00;
constexpr uint8_t kCommandPaddingEnd = 0x01;
constexpr uint8_t kCommandPaddingDirect = 0x02;

constexpr std::array<uint8_t, 2> kTlsClientHandshakeStart{0x16, 0x03};
constexpr std::array<uint8_t, 3> kTlsServerHandshakeStart{0x16, 0x03, 0x03};
constexpr std::array<uint8_t, 3> kTlsApplicationDataStart{0x17, 0x03, 0x03};
constexpr std::array<uint8_t, 6> kTls13SupportedVersions{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};

[[nodiscard]] uint16_t ReadU16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(p[0]) << 8) |
        static_cast<uint16_t>(p[1]));
}

void WriteU16(uint8_t* p, uint16_t value) noexcept {
    p[0] = static_cast<uint8_t>((value >> 8) & 0xff);
    p[1] = static_cast<uint8_t>(value & 0xff);
}

[[nodiscard]] bool StartsWith(std::span<const uint8_t> data,
                              std::span<const uint8_t> prefix) noexcept {
    return data.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), data.begin());
}

[[nodiscard]] size_t FindBytes(std::span<const uint8_t> data,
                               std::span<const uint8_t> needle) noexcept {
    if (needle.empty() || data.size() < needle.size()) {
        return std::string_view::npos;
    }
    auto it = std::search(data.begin(), data.end(), needle.begin(), needle.end());
    return it == data.end()
        ? std::string_view::npos
        : static_cast<size_t>(it - data.begin());
}

[[nodiscard]] bool ContainsBytes(std::span<const uint8_t> data,
                                 std::span<const uint8_t> needle) noexcept {
    return FindBytes(data, needle) != std::string_view::npos;
}

[[nodiscard]] uint16_t RandomU16(uint16_t limit) noexcept {
    if (limit == 0) {
        return 0;
    }
    uint16_t value = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
        return 0;
    }
    return static_cast<uint16_t>(value % limit);
}

[[nodiscard]] uint16_t PaddingLen(size_t content_len, bool padding_tls) noexcept {
    if (content_len >= 900) {
        return 0;
    }
    if (padding_tls) {
        return static_cast<uint16_t>(RandomU16(500) + 900 - content_len);
    }
    return RandomU16(256);
}

void AppendBytesToMultiBuffer(buf::MultiBuffer& out, std::span<const uint8_t> data) {
    while (!data.empty()) {
        buf::BufferGuard b{buf::Buffer::New()};
        if (!b) {
            return;
        }
        const size_t n = std::min<size_t>(data.size(), b->Available());
        std::memcpy(b->Tail().data(), data.data(), n);
        b->Produce(static_cast<uint32_t>(n));
        out.push_back(b.release());
        data = data.subspan(n);
    }
}

void AppendZerosToMultiBuffer(buf::MultiBuffer& out, size_t len) {
    while (len > 0) {
        buf::BufferGuard b{buf::Buffer::New()};
        if (!b) {
            return;
        }
        const size_t n = std::min<size_t>(len, b->Available());
        std::memset(b->Tail().data(), 0, n);
        b->Produce(static_cast<uint32_t>(n));
        out.push_back(b.release());
        len -= n;
    }
}

}  // namespace

bool IsVisionFlow(std::string_view flow) noexcept {
    return flow == kVisionFlow;
}

VisionReader::VisionReader(AsyncStream& src,
                           std::array<uint8_t, 16> user_uuid,
                           std::span<const uint8_t> initial)
    : src_(src)
    , user_uuid_(user_uuid) {
    pending_.insert(pending_.end(), initial.begin(), initial.end());
}

void VisionReader::Feed(buf::MultiBuffer mb) {
    for (buf::Buffer* b : mb) {
        if (b && !b->IsEmpty()) {
            const auto bytes = b->Bytes();
            pending_.insert(pending_.end(), bytes.begin(), bytes.end());
        }
    }
    mb.clear();
}

bool VisionReader::TryDecode(buf::MultiBuffer& out) {
    if (!read_process_) {
        if (!pending_.empty()) {
            AppendBytesToMultiBuffer(out, pending_);
            pending_.clear();
        }
        return !out.empty();
    }

    while (true) {
        const size_t header_len = expect_uuid_
            ? kVisionUuidHeaderLen
            : kVisionBaseHeaderLen;
        if (pending_.size() < header_len) {
            return !out.empty();
        }

        size_t pos = 0;
        if (expect_uuid_) {
            if (!std::equal(user_uuid_.begin(), user_uuid_.end(), pending_.begin())) {
                throw IoSystemError(io_error::connection_reset, "VLESS Vision UUID mismatch");
            }
            pos += user_uuid_.size();
            expect_uuid_ = false;
        }

        const uint8_t command = pending_[pos++];
        const uint16_t content_len = ReadU16(pending_.data() + pos);
        pos += 2;
        const uint16_t padding_len = ReadU16(pending_.data() + pos);
        pos += 2;

        const size_t frame_len = header_len + content_len + padding_len;
        if (pending_.size() < frame_len) {
            return !out.empty();
        }
        if (command != kCommandPaddingContinue &&
            command != kCommandPaddingEnd &&
            command != kCommandPaddingDirect) {
            throw IoSystemError(io_error::connection_reset, "VLESS Vision command invalid");
        }

        if (content_len > 0) {
            AppendBytesToMultiBuffer(
                out,
                std::span<const uint8_t>(
                    pending_.data() + header_len,
                    content_len));
        }

        pending_.erase(
            pending_.begin(),
            pending_.begin() + static_cast<std::ptrdiff_t>(frame_len));

        if (command == kCommandPaddingEnd ||
            command == kCommandPaddingDirect) {
            read_process_ = false;
            if (!pending_.empty()) {
                AppendBytesToMultiBuffer(out, pending_);
                pending_.clear();
            }
            return !out.empty();
        }
        if (!out.empty()) {
            return true;
        }
    }
}

net::awaitable<buf::MultiBuffer> VisionReader::ReadMultiBuffer() {
    while (true) {
        buf::MultiBuffer out;
        if (TryDecode(out)) {
            co_return out;
        }

        if (!read_process_) {
            co_return co_await src_.ReadMultiBuffer();
        }

        buf::MultiBuffer raw = co_await src_.ReadMultiBuffer();
        if (raw.empty()) {
            co_return buf::MultiBuffer{};
        }
        Feed(std::move(raw));
    }
}

VisionWriter::VisionWriter(AsyncStream& dst, std::array<uint8_t, 16> user_uuid)
    : dst_(dst)
    , user_uuid_(user_uuid) {}

void VisionWriter::FilterTLS(std::span<const uint8_t> data) noexcept {
    if (packets_to_filter_ <= 0 || data.empty()) {
        return;
    }
    --packets_to_filter_;

    const size_t server_index = FindBytes(data, kTlsServerHandshakeStart);
    if (server_index != std::string_view::npos) {
        if (data.size() > server_index + 5 &&
            data[server_index] == 0x16 &&
            data[server_index + 1] == 0x03 &&
            data[server_index + 2] == 0x03) {
            is_tls_ = true;
            if (data[server_index + 5] == 0x02) {
                remaining_server_hello_ =
                    static_cast<uint16_t>(ReadU16(data.data() + server_index + 3) + 5);
                is_tls12_or_above_ = true;
                if (data.size() - server_index >= 79 && remaining_server_hello_ >= 79) {
                    const size_t session_id_len = data[server_index + 43];
                    const size_t cipher_offset = server_index + 43 + session_id_len + 1;
                    if (cipher_offset + 2 <= data.size()) {
                        cipher_ = ReadU16(data.data() + cipher_offset);
                    }
                }
            }
        }
    } else {
        const size_t client_index = FindBytes(data, kTlsClientHandshakeStart);
        if (client_index != std::string_view::npos &&
            data.size() > client_index + 5 &&
            data[client_index + 5] == 0x01) {
            is_tls_ = true;
        }
    }

    if (remaining_server_hello_ > 0) {
        size_t start = server_index == std::string_view::npos ? 0 : server_index;
        size_t end = std::min(data.size(), start + remaining_server_hello_);
        if (ContainsBytes(data.subspan(start, end - start), kTls13SupportedVersions)) {
            (void)cipher_;
            packets_to_filter_ = 0;
            remaining_server_hello_ = 0;
        } else {
            const size_t consumed = end - start;
            remaining_server_hello_ = consumed >= remaining_server_hello_
                ? 0
                : static_cast<uint16_t>(remaining_server_hello_ - consumed);
            if (remaining_server_hello_ == 0) {
                packets_to_filter_ = 0;
            }
        }
    }
}

bool VisionWriter::ShouldEndVision(std::span<const uint8_t> data) const noexcept {
    if (is_tls_ && StartsWith(data, kTlsApplicationDataStart)) {
        return true;
    }
    return !is_tls12_or_above_ && packets_to_filter_ <= 1;
}

bool VisionWriter::AppendVisionFrame(buf::MultiBuffer& out,
                                     std::span<const uint8_t> content,
                                     uint8_t command) {
    const uint16_t padding_len = PaddingLen(content.size(), is_tls_);
    const size_t header_len = send_uuid_
        ? kVisionUuidHeaderLen
        : kVisionBaseHeaderLen;

    buf::BufferGuard header{buf::Buffer::New()};
    if (!header || header->Available() < header_len) {
        return false;
    }

    uint8_t* tail = header->Tail().data();
    size_t pos = 0;
    if (send_uuid_) {
        std::memcpy(tail, user_uuid_.data(), user_uuid_.size());
        pos += user_uuid_.size();
        send_uuid_ = false;
    }
    tail[pos++] = command;
    WriteU16(tail + pos, static_cast<uint16_t>(content.size()));
    pos += 2;
    WriteU16(tail + pos, padding_len);
    pos += 2;
    header->Produce(static_cast<uint32_t>(pos));
    out.push_back(header.release());

    AppendBytesToMultiBuffer(out, content);
    if (padding_len > 0) {
        AppendZerosToMultiBuffer(out, padding_len);
    }
    return true;
}

net::awaitable<void> VisionWriter::WriteMultiBuffer(buf::MultiBuffer mb) {
    buf::MultiBuffer out;
    for (buf::Buffer* b : mb) {
        if (!b || b->IsEmpty()) {
            continue;
        }
        std::span<const uint8_t> bytes = b->Bytes();
        while (!bytes.empty()) {
            if (!write_process_) {
                AppendBytesToMultiBuffer(out, bytes);
                break;
            }

            const size_t n = std::min<size_t>(bytes.size(), kVisionFrameContentLimit);
            const auto chunk = bytes.first(n);
            FilterTLS(chunk);
            const bool end_vision = ShouldEndVision(chunk);
            const uint8_t command = end_vision
                ? kCommandPaddingEnd
                : kCommandPaddingContinue;
            if (!AppendVisionFrame(out, chunk, command)) {
                mb.clear();
                throw IoSystemError(io_error::fault,
                                    "VLESS Vision frame allocation failed");
            }
            if (end_vision) {
                write_process_ = false;
            }
            bytes = bytes.subspan(n);
        }
    }
    mb.clear();
    if (!out.empty()) {
        co_await dst_.WriteMultiBuffer(std::move(out));
    }
}

net::awaitable<void> VisionWriter::AsyncShutdownWrite() {
    co_await dst_.AsyncShutdownWrite();
}

}  // namespace acpp::vless
