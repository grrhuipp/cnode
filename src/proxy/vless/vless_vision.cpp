#include "vless_vision.hpp"
#include "common/byte_reader.hpp"
#include "common/buffer_util.hpp"

#include "common/error.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <openssl/mem.h>
#include <openssl/rand.h>

namespace vless {

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


using VisionFrameBufferBuilder =
    ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity * 3>;

class VisionHeaderArena {
public:
    uint8_t* Allocate(size_t len) {
        if (inline_used_ + len <= inline_.size()) {
            uint8_t* ptr = inline_.data() + inline_used_;
            inline_used_ += len;
            return ptr;
        }
        if (overflow_.empty() || overflow_used_ + len > kBlockSize) {
            overflow_.emplace_back();
            overflow_used_ = 0;
        }
        uint8_t* ptr = overflow_.back().data() + overflow_used_;
        overflow_used_ += len;
        return ptr;
    }

private:
    static constexpr size_t kBlockSize = 128;
    std::array<uint8_t, kBlockSize> inline_{};
    size_t inline_used_ = 0;
    std::deque<std::array<uint8_t, kBlockSize>,
               memory::ThreadLocalAllocator<std::array<uint8_t, kBlockSize>>> overflow_;
    size_t overflow_used_ = 0;
};

void AppendVisionFrameBuffers(
    VisionHeaderArena& header_owner,
    VisionFrameBufferBuilder& out,
    std::span<uint8_t, 16> user_uuid,
    bool& send_uuid,
    std::span<const uint8_t> content,
    uint8_t command,
    bool long_padding) {
    const uint16_t padding_len = PaddingLen(content.size(), long_padding);
    const size_t header_len = send_uuid
        ? kVisionUuidHeaderLen
        : kVisionBaseHeaderLen;

    uint8_t* tail = header_owner.Allocate(header_len);
    size_t pos = 0;
    if (send_uuid) {
        std::memcpy(tail, user_uuid.data(), user_uuid.size());
        OPENSSL_cleanse(user_uuid.data(), user_uuid.size());
        pos += user_uuid.size();
        send_uuid = false;
    }
    tail[pos++] = command;
    StoreU16BE(tail + pos, static_cast<uint16_t>(content.size()));
    pos += 2;
    StoreU16BE(tail + pos, padding_len);
    pos += 2;
    out.Append(net::const_buffer(tail, pos));
    if (!content.empty()) {
        out.Append(net::const_buffer(content.data(), content.size()));
    }

    size_t remaining_padding = padding_len;
    while (remaining_padding > 0) {
        const size_t n = std::min(remaining_padding, kZeroPadding.size());
        out.Append(net::const_buffer(kZeroPadding.data(), n));
        remaining_padding -= n;
    }
}

void AppendVisionFramed(
    VisionHeaderArena& header_owner,
    VisionFrameBufferBuilder& out,
    std::span<uint8_t, 16> user_uuid,
    bool& send_uuid,
    bool& write_process,
    const VisionTrafficState& traffic,
    std::span<const uint8_t> bytes,
    bool complete_records,
    bool last_buffer,
    bool& ending,
    bool& long_padding) {
    while (!bytes.empty()) {
        if (!write_process) {
            out.Append(net::const_buffer(bytes.data(), bytes.size()));
            return;
        }

        // Match Xray ReshapeMultiBuffer: prefer the last application record
        // boundary when it leaves room for the Vision header.
        size_t n = bytes.size();
        if (n >= kVisionFrameContentLimit) {
            const auto window = bytes.first(kVisionFrameContentLimit);
            const auto it = std::find_end(window.begin(), window.end(),
                kTlsApplicationDataStart.begin(), kTlsApplicationDataStart.end());
            const size_t index = static_cast<size_t>(it - window.begin());
            n = (it != window.end() && index >= kVisionUuidHeaderLen)
                ? index : std::min<size_t>(n, 4096);
        }
        const auto chunk = bytes.first(n);
        const bool application = traffic.is_tls && chunk.size() >= 6 &&
            StartsWith(chunk, kTlsApplicationDataStart) && complete_records;
        uint8_t command = kCommandPaddingContinue;
        bool frame_long_padding = long_padding;
        if (application) {
            ending = true;
            frame_long_padding = true;
            long_padding = false;
        } else if (!traffic.is_tls12_or_above && traffic.packets_to_filter <= 1) {
            command = kCommandPaddingEnd;
            write_process = false;
        }
        if (ending && last_buffer && n == bytes.size()) {
            command = kCommandPaddingEnd;
            write_process = false;
        }
        AppendVisionFrameBuffers(
            header_owner, out, user_uuid, send_uuid, chunk, command, frame_long_padding);
        bytes = bytes.subspan(n);
    }
}

[[nodiscard]] std::span<const uint8_t> VisionChunkBytes(const buf::Buffer* buffer) noexcept {
    return buffer ? buffer->Bytes() : std::span<const uint8_t>{};
}

[[nodiscard]] std::span<const uint8_t> VisionChunkBytes(const net::const_buffer& buffer) noexcept {
    const auto* data = static_cast<const uint8_t*>(buffer.data());
    return data ? std::span<const uint8_t>(data, buffer.size()) : std::span<const uint8_t>{};
}

template <typename BufferRange>
net::awaitable<void> WriteVisionFramed(
    transport::MultiBufferWriter& dst,
    std::span<uint8_t, 16> user_uuid,
    bool& send_uuid,
    bool& write_process,
    VisionTrafficState& traffic,
    const BufferRange& buffers) {
    CompleteRecords records;
    const bool filter = traffic.packets_to_filter > 0;
    size_t remaining_bytes = 0;
    for (const auto& buffer : buffers) {
        const auto bytes = VisionChunkBytes(buffer);
        if (!bytes.empty()) {
            if (filter) {
                traffic.FilterTLS(bytes);
            }
            records.Add(bytes);
            remaining_bytes += bytes.size();
        }
    }
    bool ending = false;
    bool long_padding = traffic.is_tls;
    VisionHeaderArena header_owner;
    VisionFrameBufferBuilder out;
    for (const auto& buffer : buffers) {
        const auto bytes = VisionChunkBytes(buffer);
        if (!bytes.empty()) {
            remaining_bytes -= bytes.size();
            AppendVisionFramed(
                header_owner, out, user_uuid, send_uuid, write_process, traffic,
                bytes, records.Complete(), remaining_bytes == 0, ending, long_padding);
        }
    }
    if (!out.empty()) {
        co_await dst.WriteBuffers(out.Span());
    }
}
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
                    if (pending_.empty()) {
                        pending_.ReleaseIfIdle();
                    }
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
                    if (pending_.empty()) {
                        pending_.ReleaseIfIdle();
                    }
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
            if (pending_.empty()) {
                pending_.ReleaseIfIdle();
            }
            return;
        }
        header_read_ = 0;

        const uint8_t* fields = header_.data();
        if (expect_uuid_) {
            if (CRYPTO_memcmp(fields, user_uuid_.data(), user_uuid_.size()) != 0) {
                OPENSSL_cleanse(user_uuid_.data(), user_uuid_.size());
                OPENSSL_cleanse(header_.data(), user_uuid_.size());
                throw IoSystemError(io_error::connection_reset, "VLESS Vision UUID mismatch");
            }
            fields += user_uuid_.size();
            OPENSSL_cleanse(user_uuid_.data(), user_uuid_.size());
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
    pending_.ReleaseIfIdle();
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
            co_return co_await ReadMultiBufferOrThrowOnCancel(src_);
        }

        buf::MultiBuffer raw = co_await ReadMultiBufferOrThrowOnCancel(src_);
        if (raw.byte_size() == 0) {
            if (read_process_ && (header_read_ != 0 || frame_active_ || expect_uuid_)) {
                throw IoSystemError(io_error::connection_reset, "VLESS Vision frame truncated");
            }
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
    if (data.empty() || tls_classified || packets_to_filter <= 0) {
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


net::awaitable<void> VisionWriter::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (!write_process_) {
        co_await dst_.WriteMultiBuffer(std::move(mb));
        co_return;
    }
    co_await WriteVisionFramed(
        dst_, user_uuid_, send_uuid_, write_process_, traffic_, mb);
    mb.clear();
}

net::awaitable<void> VisionWriter::WriteBuffers(std::span<const net::const_buffer> buffers) {
    if (!write_process_) {
        co_await dst_.WriteBuffers(buffers);
        co_return;
    }
    co_await WriteVisionFramed(
        dst_, user_uuid_, send_uuid_, write_process_, traffic_, buffers);
}

net::awaitable<void> VisionWriter::AsyncShutdownWrite() {
    co_await dst_.AsyncShutdownWrite();
}

}  // namespace vless
