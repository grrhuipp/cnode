#include "vless_vision.hpp"
#include "acppnode/common/byte_reader.hpp"

#include "acppnode/common/error.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <openssl/mem.h>
#include <openssl/rand.h>

namespace acpp::vless {

namespace {

constexpr size_t kVisionBaseHeaderLen = 1 + 2 + 2;
constexpr size_t kVisionUuidHeaderLen = 16 + kVisionBaseHeaderLen;
using detail::kVisionFrameContentLimit;

constexpr uint8_t kCommandPaddingContinue = 0x00;
constexpr uint8_t kCommandPaddingEnd = 0x01;
constexpr uint8_t kCommandPaddingDirect = 0x02;

constexpr std::array<uint8_t, 2> kTlsClientHandshakeStart{0x16, 0x03};
constexpr std::array<uint8_t, 3> kTlsServerHandshakeStart{0x16, 0x03, 0x03};
constexpr std::array<uint8_t, 3> kTlsApplicationDataStart{0x17, 0x03, 0x03};
constexpr std::array<uint8_t, 6> kTls13SupportedVersions{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
constexpr std::array<uint8_t, 2048> kZeroPadding{};

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
    uint16_t value;
    const uint32_t bound = 65536u - (65536u % limit);
    do {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
            std::abort();
        }
    } while (value >= bound);
    return static_cast<uint16_t>(value % limit);
}

[[nodiscard]] uint16_t PaddingLen(size_t content_len, bool padding_tls) noexcept {
    return detail::VisionPaddingSize(content_len, padding_tls,
        RandomU16(content_len < 900 && padding_tls ? 500 : 256));
}

[[noreturn]] void ThrowVisionAllocationFailure() {
    throw IoSystemError(io_error::fault, "VLESS Vision buffer allocation failed");
}

// Xray IsCompleteRecord, without flattening the scatter/gather payload.
struct CompleteRecords {
    std::array<uint8_t, 5> header{};
    size_t header_bytes = 0;
    size_t remaining = 0;
    bool valid = true;
    bool seen = false;

    void Add(std::span<const uint8_t> bytes) noexcept {
        while (valid && !bytes.empty()) {
            seen = true;
            if (remaining != 0) {
                const auto n = std::min(remaining, bytes.size());
                remaining -= n;
                bytes = bytes.subspan(n);
                continue;
            }
            header[header_bytes++] = bytes.front();
            bytes = bytes.subspan(1);
            if (header_bytes == header.size()) {
                valid = StartsWith(header, kTlsApplicationDataStart);
                remaining = LoadU16BE(header.data() + 3);
                valid = valid && remaining != 0;
                header_bytes = 0;
            }
        }
    }

    [[nodiscard]] bool Complete() const noexcept {
        return valid && seen && remaining == 0 && header_bytes == 0;
    }
};

}  // namespace

bool IsVisionFlow(std::string_view flow) noexcept {
    return flow == kVisionFlow;
}

VisionReader::VisionReader(transport::MultiBufferReader& src,
                           std::array<uint8_t, 16> user_uuid,
                           VisionTrafficState& traffic,
                           std::span<const uint8_t> initial)
    : src_(src)
    , user_uuid_(user_uuid)
    , traffic_(traffic) {
    if (!buf::AppendSpanToMultiBuffer(initial, pending_)) {
        ThrowVisionAllocationFailure();
    }
}

void VisionReader::Decode(buf::MultiBuffer& out) {
    while (read_process_) {
        if (frame_active_) {
            if (content_remaining_ > 0) {
                const size_t n = std::min(content_remaining_, pending_.byte_size());
                if (n == 0) {
                    return;
                }
                if (!pending_.MovePrefixTo(out, n)) {
                    ThrowVisionAllocationFailure();
                }
                content_remaining_ -= n;
                continue;
            }
            if (padding_remaining_ > 0) {
                padding_remaining_ -= pending_.DropPrefixBytes(
                    std::min(padding_remaining_, pending_.byte_size()));
                if (padding_remaining_ > 0) {
                    return;
                }
            }
            frame_active_ = false;
            if (command_ != kCommandPaddingContinue) {
                if (command_ == kCommandPaddingDirect && !src_.EnableRawRead()) {
                    throw IoSystemError(io_error::connection_reset,
                                        "VLESS Vision direct read transition failed");
                }
                read_process_ = false;
            }
            continue;
        }

        const size_t header_len = expect_uuid_
            ? kVisionUuidHeaderLen
            : kVisionBaseHeaderLen;
        header_read_ += pending_.ConsumePrefixTo(
            std::span<uint8_t>(header_).subspan(header_read_, header_len - header_read_));
        if (header_read_ < header_len) {
            return;
        }
        header_read_ = 0;

        const uint8_t* fields = header_.data();
        if (expect_uuid_) {
            if (CRYPTO_memcmp(fields, user_uuid_.data(), user_uuid_.size()) != 0) {
                throw IoSystemError(io_error::connection_reset, "VLESS Vision UUID mismatch");
            }
            fields += user_uuid_.size();
            expect_uuid_ = false;
        }
        command_ = fields[0];
        if (command_ != kCommandPaddingContinue &&
            command_ != kCommandPaddingEnd &&
            command_ != kCommandPaddingDirect) {
            throw IoSystemError(io_error::connection_reset, "VLESS Vision command invalid");
        }
        content_remaining_ = LoadU16BE(fields + 1);
        padding_remaining_ = LoadU16BE(fields + 3);
        frame_active_ = true;
    }
    // After the final padded frame the rest of the stream is raw.
    pending_.MoveTo(out);
}

net::awaitable<buf::MultiBuffer> VisionReader::ReadMultiBuffer() {
    while (true) {
        buf::MultiBuffer out;
        Decode(out);
        if (out.byte_size() != 0) {
            if (traffic_.packets_to_filter > 0) {
                for (const auto* buffer : out) {
                    traffic_.FilterTLS(buffer->Bytes());
                }
            }
            co_return out;
        }

        if (!read_process_) {
            co_return co_await src_.ReadMultiBuffer();
        }

        buf::MultiBuffer raw = co_await src_.ReadMultiBuffer();
        if (raw.byte_size() == 0) {
            co_return buf::MultiBuffer{};
        }
        raw.MoveTo(pending_);
    }
}

VisionWriter::VisionWriter(transport::MultiBufferWriter& dst,
                           std::array<uint8_t, 16> user_uuid,
                           VisionTrafficState& traffic)
    : dst_(dst)
    , user_uuid_(user_uuid)
    , traffic_(traffic) {}

void VisionTrafficState::FilterTLS(std::span<const uint8_t> data) noexcept {
    if (data.empty() || tls_classified) {
        return;
    }
    --packets_to_filter;
    if (data.size() >= 6) {
        if (StartsWith(data, kTlsServerHandshakeStart) && data[5] == 0x02) {
            remaining_server_hello = LoadU16BE(data.data() + 3) + 5;
            is_tls12_or_above = true;
            is_tls = true;
        } else if (StartsWith(data, kTlsClientHandshakeStart) && data[5] == 0x01) {
            is_tls = true;
        }
    }
    if (remaining_server_hello > 0) {
        const auto end = std::min<size_t>(data.size(), remaining_server_hello);
        remaining_server_hello -= static_cast<int32_t>(data.size());
        if (ContainsBytes(data.first(end), kTls13SupportedVersions) ||
            remaining_server_hello <= 0) {
            packets_to_filter = 0;
            tls_classified = true;
        }
    }
}

void VisionWriter::AppendVisionFrameBuffers(
    buf::MultiBuffer& header_owner,
    memory::ThreadLocalVector<net::const_buffer>& out,
    std::span<const uint8_t> content,
    uint8_t command,
    bool long_padding) {
    const uint16_t padding_len = PaddingLen(content.size(), long_padding);
    const size_t header_len = send_uuid_
        ? kVisionUuidHeaderLen
        : kVisionBaseHeaderLen;

    buf::Buffer* header_buf = header_owner.back();
    if (!header_buf || header_buf->Available() < header_len) {
        buf::BufferGuard header{buf::Buffer::New()};
        if (!header || header->Available() < header_len) {
            ThrowVisionAllocationFailure();
        }
        header_buf = header.get();
        header_owner.push_back(std::move(header));
    }

    uint8_t* tail = header_buf->Tail().data();
    size_t pos = 0;
    if (send_uuid_) {
        std::memcpy(tail, user_uuid_.data(), user_uuid_.size());
        pos += user_uuid_.size();
        send_uuid_ = false;
    }
    tail[pos++] = command;
    StoreU16BE(tail + pos, static_cast<uint16_t>(content.size()));
    pos += 2;
    StoreU16BE(tail + pos, padding_len);
    pos += 2;
    header_buf->Produce(static_cast<uint32_t>(pos));
    header_owner.RecordTailProduced(pos);
    out.emplace_back(tail, pos);
    if (!content.empty()) {
        out.emplace_back(content.data(), content.size());
    }

    size_t remaining_padding = padding_len;
    while (remaining_padding > 0) {
        const size_t n = std::min(remaining_padding, kZeroPadding.size());
        out.emplace_back(kZeroPadding.data(), n);
        remaining_padding -= n;
    }
}

void VisionWriter::AppendFramed(
    buf::MultiBuffer& header_owner,
    memory::ThreadLocalVector<net::const_buffer>& out,
    std::span<const uint8_t> bytes,
    bool complete_records,
    bool last_buffer,
    bool& ending,
    bool& long_padding) {
    while (!bytes.empty()) {
        if (!write_process_) {
            out.emplace_back(bytes.data(), bytes.size());
            return;
        }

        // Match Xray ReshapeMultiBuffer: prefer the last application record
        // boundary when it leaves room for the Vision header.
        size_t n = bytes.size();
        if (n >= kVisionFrameContentLimit) {
            const auto it = std::find_end(bytes.begin(), bytes.end(),
                kTlsApplicationDataStart.begin(), kTlsApplicationDataStart.end());
            const size_t index = static_cast<size_t>(it - bytes.begin());
            n = index >= kVisionUuidHeaderLen && index <= kVisionFrameContentLimit
                ? index : std::min<size_t>(n, 4096);
        }
        const auto chunk = bytes.first(n);
        const bool application = traffic_.is_tls && chunk.size() >= 6 &&
            StartsWith(chunk, kTlsApplicationDataStart) && complete_records;
        uint8_t command = kCommandPaddingContinue;
        bool frame_long_padding = long_padding;
        if (application) {
            ending = true;
            frame_long_padding = true;
            long_padding = false;
        } else if (!traffic_.is_tls12_or_above && traffic_.packets_to_filter <= 1) {
            command = kCommandPaddingEnd;
            write_process_ = false;
        }
        if (ending && last_buffer && n == bytes.size()) {
            command = kCommandPaddingEnd;
            write_process_ = false;
        }
        AppendVisionFrameBuffers(header_owner, out, chunk, command, frame_long_padding);
        bytes = bytes.subspan(n);
    }
}

net::awaitable<void> VisionWriter::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (!write_process_) {
        co_await dst_.WriteMultiBuffer(std::move(mb));
        co_return;
    }

    CompleteRecords records;
    const bool filter = traffic_.packets_to_filter > 0;
    for (const auto* buffer : mb) {
        if (buffer && !buffer->IsEmpty()) {
            if (filter) traffic_.FilterTLS(buffer->Bytes());
            records.Add(buffer->Bytes());
        }
    }
    bool ending = false;
    bool long_padding = traffic_.is_tls;
    size_t remaining_bytes = mb.byte_size();
    buf::MultiBuffer header_owner;
    memory::ThreadLocalVector<net::const_buffer> out;
    out.reserve(mb.size() * 3);
    for (buf::Buffer* buffer : mb) {
        if (buffer && !buffer->IsEmpty()) {
            remaining_bytes -= buffer->Bytes().size();
            AppendFramed(header_owner, out, buffer->Bytes(), records.Complete(),
                         remaining_bytes == 0, ending, long_padding);
        }
    }
    if (!out.empty()) {
        co_await dst_.WriteBuffers(out);
    }
    mb.clear();
}

net::awaitable<void> VisionWriter::WriteBuffers(std::span<const net::const_buffer> buffers) {
    if (!write_process_) {
        co_await dst_.WriteBuffers(buffers);
        co_return;
    }
    CompleteRecords records;
    const bool filter = traffic_.packets_to_filter > 0;
    size_t remaining_bytes = 0;
    for (const auto& buffer : buffers) {
        const auto bytes = std::span(static_cast<const uint8_t*>(buffer.data()), buffer.size());
        if (filter) traffic_.FilterTLS(bytes);
        records.Add(bytes);
        remaining_bytes += buffer.size();
    }
    bool ending = false;
    bool long_padding = traffic_.is_tls;

    buf::MultiBuffer header_owner;
    memory::ThreadLocalVector<net::const_buffer> out;
    out.reserve(buffers.size() * 3);
    for (const net::const_buffer& buffer : buffers) {
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        if (data && buffer.size() > 0) {
            remaining_bytes -= buffer.size();
            AppendFramed(header_owner, out, std::span<const uint8_t>(data, buffer.size()),
                         records.Complete(), remaining_bytes == 0, ending, long_padding);
        }
    }
    if (!out.empty()) {
        co_await dst_.WriteBuffers(out);
    }
}

net::awaitable<void> VisionWriter::AsyncShutdownWrite() {
    co_await dst_.AsyncShutdownWrite();
}

}  // namespace acpp::vless
