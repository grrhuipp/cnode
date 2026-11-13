#include "proxy/vless/vless_encryption.hpp"
#include "common/asio_types.hpp"

#include <asio/this_coro.hpp>
#include <algorithm>
#include <array>
#include <cstring>
#include <type_traits>
#include <utility>
#include <vector>
namespace proxy {
VlessEncryptedIo::VlessEncryptedIo(proxy::BufferedStreamReader& raw_reader,
                                   transport::MultiBufferWriter& raw_writer,
                                   VlessEncryptionRuntime runtime)
    : reader(raw_reader,
             std::move(runtime.read_keys),
             runtime.united_key,
             std::move(runtime.read_xor))
    , writer(raw_writer,
             std::move(runtime.write_aead),
             runtime.united_key,
             std::move(runtime.write_xor))
    , plain_reader(reader) {}
namespace {

[[noreturn]] void ThrowVlessEncryptionIoError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

// Replaces the AEAD after the record sealed or opened at the maximum nonce;
// `context` is that complete wire record.
[[nodiscard]] bool RekeyAead(VlessEncryptionAead& aead,
                             std::span<const uint8_t> context,
                             const VlessEncryptionUnitedKey& united_key) noexcept {
    auto next = VlessEncryptionAead::Create(
        context,
        united_key.bytes,
        aead.Cipher());
    if (!next) {
        return false;
    }
    aead = std::move(*next);
    return true;
}

[[nodiscard]] bool WillReachVlessEncryptionMaxNonce(
    const VlessEncryptionNonce& nonce) noexcept {
    auto next = nonce;
    IncreaseVlessEncryptionNonce(next);
    return IsVlessEncryptionMaxNonce(next);
}

}  // namespace

VlessEncryptionReader::VlessEncryptionReader(
    transport::MultiBufferReader& src,
    VlessEncryptionReadKeys keys,
    const VlessEncryptionUnitedKey& united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : src_(src)
    , keys_(std::move(keys))
    , united_key_(united_key)
    , header_xor_(std::move(header_xor)) {
    if (const auto* deferred = std::get_if<VlessEncryptionDeferredRead>(&keys_)) {
        unverified_ticket_ = deferred->ticket_rejection;
    }
}

void VlessEncryptionReader::RejectDeferredTicket() noexcept {
    if (unverified_ticket_) {
        unverified_ticket_->rejected = true;
        unverified_ticket_ = nullptr;
    }
}

VlessEncryptionAead& VlessEncryptionReader::KeyDeferredRead(
    const VlessEncryptionDeferredRead& deferred) {
    auto aead = VlessEncryptionAead::Create(
        server_random_, united_key_.bytes, deferred.cipher);
    if (!aead) {
        ThrowVlessEncryptionIoError("VLESS Encryption server random invalid");
    }
    if (deferred.header_xor) {
        header_xor_ = VlessEncryptionHeaderXor::Create(
            united_key_.bytes, server_random_);
        if (!header_xor_) {
            ThrowVlessEncryptionIoError("VLESS Encryption lazy xor failed");
        }
    }
    bytes_read_ = 0;
    return keys_.emplace<VlessEncryptionAead>(std::move(*aead));
}

bool VlessEncryptionReader::EnableRawRead() noexcept {
    if (header_read_ != 0 || bytes_read_ != 0 || encrypted_size_ != 0 ||
        !std::holds_alternative<VlessEncryptionAead>(keys_)) {
        return false;
    }
    // Xray unwraps CommonConn, not its underlying TLS transport a second time.
    // In random mode XorConn stays in place across the transition.
    raw_read_ = true;
    return true;
}

net::awaitable<common::MultiBuffer> VlessEncryptionReader::ReadRawBytes() {
    auto out = co_await src_.ReadMultiBuffer();
    if (out.byte_size() == 0) {
        co_await common::ThrowIfCancelledOnEof("VLESS Encryption read cancelled");
    }
    if (header_xor_) {
        if (const auto bytes = out.MutableFrontSpan();
            !bytes.empty() && !header_xor_->XorInboundInPlace(bytes)) {
            ThrowVlessEncryptionIoError("VLESS Encryption direct header xor failed");
        }
    }
    co_return out;
}

void VlessEncryptionReader::DecodeLoadedRecordHeader() {
    auto& header = read_header_;
    if (header_xor_ && !header_xor_->XorInboundInPlace(header)) {
        ThrowVlessEncryptionIoError("VLESS Encryption header xor failed");
    }
    const auto encrypted_len = DecodeVlessEncryptionRecordHeader(header);
    if (!encrypted_len) {
        ThrowVlessEncryptionIoError("VLESS Encryption record header invalid");
    }
    encrypted_size_ = *encrypted_len;
}

size_t VlessEncryptionReader::OpenRecord(
    VlessEncryptionAead& aead,
    std::span<const uint8_t> encrypted_span,
    std::span<uint8_t> plain_out) {
    const auto& header = read_header_;
    std::vector<uint8_t> rekey_context;
    if (WillReachVlessEncryptionMaxNonce(aead.Nonce())) {
        rekey_context.resize(header.size() + encrypted_span.size());
        auto next = std::copy(header.begin(), header.end(), rekey_context.begin());
        std::copy(encrypted_span.begin(), encrypted_span.end(), next);
    }

    const auto opened = OpenVlessEncryptionRecord(
        aead,
        header,
        encrypted_span,
        plain_out);
    if (!opened) {
        ThrowVlessEncryptionIoError("VLESS Encryption record decrypt failed");
    }
    unverified_ticket_ = nullptr;

    if (!rekey_context.empty() &&
        !RekeyAead(aead, rekey_context, united_key_)) {
        ThrowVlessEncryptionIoError("VLESS Encryption read rekey failed");
    }
    return *opened;
}

net::awaitable<common::MultiBuffer> VlessEncryptionReader::ReadMultiBuffer() {
    if (raw_read_) {
        return ReadRawBytes();
    }
    return ReadEncryptedMultiBuffer();
}

net::awaitable<common::MultiBuffer> VlessEncryptionReader::ReadEncryptedMultiBuffer() {
    try {
        auto* aead = std::get_if<VlessEncryptionAead>(&keys_);
        if (!aead) {
            if (!co_await src_.ReadExact(server_random_.data(),
                                         server_random_.size(), &bytes_read_)) {
                ThrowVlessEncryptionIoError("VLESS Encryption server random missing");
            }
            aead = &KeyDeferredRead(std::get<VlessEncryptionDeferredRead>(keys_));
        }

        for (;;) {
            if (encrypted_size_ == 0) {
                auto& header = read_header_;
                if (!src_.ReadBuffered(header.data(), header.size(), header_read_) &&
                    !co_await src_.ReadExact(header.data(), header.size(), &header_read_)) {
                    if (header_read_ != 0) {
                        ThrowVlessEncryptionIoError("VLESS Encryption record header truncated");
                    }
                    const auto cancellation =
                        co_await net::this_coro::cancellation_state;
                    if (cancellation.cancelled() != net::cancellation_type::none) {
                        throw IoSystemError(
                            io_error::operation_aborted,
                            "VLESS Encryption read cancelled");
                    }
                    RejectDeferredTicket();
                    read_record_.Reset();
                    co_return common::MultiBuffer{};
                }
                DecodeLoadedRecordHeader();
            }
            // `encrypted_size_` is bounded by kVlessEncryptionMaxRecordCiphertextSize.
            if (bytes_read_ == 0 && read_record_.Empty()) {
                if (auto sealed = src_.TakeFrontIfLen(encrypted_size_)) {
                    auto encrypted_span = sealed->Bytes();
                    if (header_xor_ && !header_xor_->XorInboundInPlace(encrypted_span)) {
                        ThrowVlessEncryptionIoError("VLESS Encryption body xor state failed");
                    }
                    const auto opened = OpenRecord(*aead, encrypted_span, encrypted_span);
                    header_read_ = 0;
                    bytes_read_ = 0;
                    encrypted_size_ = 0;
                    if (opened == 0) {
                        continue;
                    }
                    sealed->end = sealed->start + static_cast<uint32_t>(opened);
                    co_return common::MultiBuffer{std::move(sealed)};
                }
                if (src_.PendingBytes() > encrypted_size_) {
                    auto prefix = src_.MutablePrefixSpan(encrypted_size_);
                    if (header_xor_ && !header_xor_->XorInboundInPlace(prefix)) {
                        ThrowVlessEncryptionIoError("VLESS Encryption body xor state failed");
                    }
                    const size_t plain_cap = encrypted_size_ - kVlessEncryptionTagSize;
                    if (plain_cap == 0) {
                        uint8_t empty_plain = 0;
                        (void)OpenRecord(*aead, prefix, {&empty_plain, 0});
                        src_.DropBufferedPrefix(encrypted_size_);
                        header_read_ = 0;
                        bytes_read_ = 0;
                        encrypted_size_ = 0;
                        continue;
                    }
                    common::BufferGuard out_buf{common::Buffer::New(plain_cap)};
                    if (!out_buf) {
                        ThrowVlessEncryptionIoError("VLESS Encryption buffer allocation failed");
                    }
                    const auto opened = OpenRecord(
                        *aead, prefix, out_buf->Tail().first(plain_cap));
                    src_.DropBufferedPrefix(encrypted_size_);
                    header_read_ = 0;
                    bytes_read_ = 0;
                    encrypted_size_ = 0;
                    if (opened == 0) {
                        continue;
                    }
                    out_buf->Produce(opened);
                    co_return common::MultiBuffer{std::move(out_buf)};
                }
                (void)read_record_.Prepare(encrypted_size_);
            }
            uint8_t* record_bytes = read_record_.Data();
            if (!src_.ReadBuffered(record_bytes, encrypted_size_, bytes_read_) &&
                !co_await src_.ReadExact(record_bytes, encrypted_size_, &bytes_read_)) {
                ThrowVlessEncryptionIoError("VLESS Encryption record truncated");
            }
            auto encrypted_span = std::span<uint8_t>(record_bytes, encrypted_size_);
            if (header_xor_ && !header_xor_->XorInboundInPlace(encrypted_span)) {
                ThrowVlessEncryptionIoError("VLESS Encryption body xor state failed");
            }

            const auto opened = OpenRecord(*aead, encrypted_span, encrypted_span);

            header_read_ = 0;
            bytes_read_ = 0;
            encrypted_size_ = 0;
            if (opened == 0) {
                read_record_.Reset();
                continue;
            }
            common::MultiBuffer out;
            if (!read_record_.TryAppendTo(opened, out)) {
                throw IoSystemError(io_error::fault,
                                    "VLESS Encryption buffer allocation failed");
            }
            co_return out;
        }
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::operation_aborted) {
            RejectDeferredTicket();
            header_read_ = 0;
            bytes_read_ = 0;
            encrypted_size_ = 0;
            read_record_.Reset();
        }
        throw;
    } catch (...) {
        RejectDeferredTicket();
        header_read_ = 0;
        bytes_read_ = 0;
        encrypted_size_ = 0;
        read_record_.Reset();
        throw;
    }
}

VlessEncryptionWriter::VlessEncryptionWriter(
    transport::MultiBufferWriter& dst,
    VlessEncryptionAead aead,
    const VlessEncryptionUnitedKey& united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : dst_(dst)
    , aead_(std::move(aead))
    , united_key_(united_key)
    , header_xor_(std::move(header_xor)) {}

void VlessEncryptionWriter::CheckWritable() const {
    if (state_ == State::Failed) {
        ThrowVlessEncryptionIoError("VLESS Encryption writer failed");
    }
    if (state_ == State::Finished) {
        throw transport::WriteClosed();
    }
}

net::const_buffer VlessEncryptionWriter::SealRecordForWrite(
    std::span<const uint8_t> plain, std::span<uint8_t> frame) {
    const auto written = SealVlessEncryptionRecord(
        aead_,
        plain,
        frame);
    if (!written) {
        ThrowVlessEncryptionIoError("VLESS Encryption record encrypt failed");
    }
    auto frame_view = frame.first(*written);
    if (IsVlessEncryptionMaxNonce(aead_.Nonce()) &&
        !RekeyAead(aead_, frame_view, united_key_)) {
        ThrowVlessEncryptionIoError("VLESS Encryption write rekey failed");
    }
    if (header_xor_ &&
        !header_xor_->XorOutboundInPlace(frame_view)) {
        ThrowVlessEncryptionIoError("VLESS Encryption write xor failed");
    }
    return net::const_buffer{frame_view.data(), frame_view.size()};
}

template <typename BufferRange>
net::awaitable<void> VlessEncryptionWriter::WriteEncrypted(BufferRange source) {
    constexpr bool kOwnsBuffers = std::is_same_v<BufferRange, common::MultiBuffer>;
    CheckWritable();
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(io_error::operation_aborted,
                            "VLESS Encryption write cancelled");
    }
    net::const_buffer single_buffer;
    std::span<const net::const_buffer> buffers;
    if constexpr (kOwnsBuffers) {
        const auto bytes = source.FrontSpan();
        if (bytes.empty()) {
            co_return;
        }
        single_buffer = net::buffer(bytes.data(), bytes.size());
        buffers = {&single_buffer, 1};
    } else {
        buffers = source;
    }
    size_t total_plain = 0;
    for (const auto& buf : buffers) {
        if (buf.data() && buf.size() > 0) {
            if (buf.size() > std::numeric_limits<size_t>::max() - total_plain) {
                ThrowVlessEncryptionIoError("VLESS Encryption write overflow");
            }
            total_plain += buf.size();
        }
    }
    if (total_plain == 0) {
        if constexpr (kOwnsBuffers) {
            source.clear();
        }
        co_return;
    }
    bool record_started = false;
    try {
        size_t idx = 0;
        size_t offset = 0;
        auto skip_empty = [&]() noexcept {
            while (idx < buffers.size()) {
                const auto* data = static_cast<const uint8_t*>(buffers[idx].data());
                if (data && offset < buffers[idx].size()) {
                    return;
                }
                ++idx;
                offset = 0;
            }
        };
        skip_empty();

        constexpr size_t kRecordOverhead =
            kVlessEncryptionRecordHeaderSize + kVlessEncryptionTagSize;
        const size_t record_count =
            1 + (total_plain - 1) / kVlessEncryptionMaxPlaintextSize;
        if (record_count >
            (std::numeric_limits<size_t>::max() - total_plain) / kRecordOverhead) {
            ThrowVlessEncryptionIoError("VLESS Encryption write overflow");
        }
        const size_t total_wire = total_plain + record_count * kRecordOverhead;
        common::MultiBuffer out_mb;
        uint8_t* out_base = nullptr;
        try {
            out_base = out_mb.PrepareAppend(total_wire);
        } catch (const std::bad_alloc&) {
            ThrowVlessEncryptionIoError("VLESS Encryption buffer allocation failed");
        }
        size_t total_written = 0;
        while (idx < buffers.size()) {
            const auto* first_data =
                static_cast<const uint8_t*>(buffers[idx].data()) + offset;
            const size_t first_rem = buffers[idx].size() - offset;

            size_t planned_len = std::min(first_rem, kVlessEncryptionMaxPlaintextSize);
            if (planned_len < kVlessEncryptionMaxPlaintextSize) {
                for (size_t j = idx + 1;
                     j < buffers.size() && planned_len < kVlessEncryptionMaxPlaintextSize;
                     ++j) {
                    if (buffers[j].data() && buffers[j].size() > 0) {
                        planned_len += std::min(
                            buffers[j].size(),
                            kVlessEncryptionMaxPlaintextSize - planned_len);
                    }
                }
            }

            const size_t frame_capacity = planned_len + kRecordOverhead;
            uint8_t* frame_ptr = out_base + total_written;
            std::span<const uint8_t> plain;
            if (planned_len <= first_rem) {
                plain = {first_data, planned_len};
                offset += planned_len;
                skip_empty();
            } else {
                uint8_t* dst = frame_ptr + kVlessEncryptionRecordHeaderSize;
                size_t filled = 0;
                while (idx < buffers.size() && filled < planned_len) {
                    const auto* data =
                        static_cast<const uint8_t*>(buffers[idx].data()) + offset;
                    const size_t rem = buffers[idx].size() - offset;
                    const size_t copy_len = std::min(rem, planned_len - filled);
                    std::memcpy(dst + filled, data, copy_len);
                    filled += copy_len;
                    offset += copy_len;
                    skip_empty();
                }
                plain = {dst, filled};
            }
            // Seal advances the nonce even if record encryption subsequently fails.
            record_started = true;
            const net::const_buffer record_buf =
                SealRecordForWrite(plain, {frame_ptr, frame_capacity});
            total_written += record_buf.size();
        }
        out_mb.CommitAppend(total_written);
        if constexpr (kOwnsBuffers) {
            source.clear();
        }
        if (record_count == 1) {
            const auto span = out_mb.FrontSpan();
            const net::const_buffer single(span.data(), span.size());
            co_await dst_.WriteBuffers(
                std::span<const net::const_buffer>{&single, 1});
            out_mb.clear();
        } else {
            co_await dst_.WriteMultiBuffer(std::move(out_mb));
        }
    } catch (const transport::WriteClosed&) {
        if constexpr (kOwnsBuffers) {
            source.clear();
        }
        state_ = State::Finished;
        throw;
    } catch (...) {
        if constexpr (kOwnsBuffers) {
            source.clear();
        }
        if (record_started) {
            state_ = State::Failed;
        }
        throw;
    }
}

net::awaitable<void> VlessEncryptionWriter::WriteMultiBuffer(common::MultiBuffer mb) {
    return WriteEncrypted(std::move(mb));
}

net::awaitable<void> VlessEncryptionWriter::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    return WriteEncrypted(buffers);
}

net::awaitable<void> VlessEncryptionWriter::AsyncShutdownWrite() {
    if (state_ == State::Finished) {
        co_return;
    }
    CheckWritable();
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(io_error::operation_aborted,
                            "VLESS Encryption write shutdown cancelled");
    }
    try {
        co_await dst_.AsyncShutdownWrite();
        state_ = State::Finished;
    } catch (const transport::WriteClosed&) {
        state_ = State::Finished;
        throw;
    } catch (...) {
        state_ = State::Failed;
        throw;
    }
}

}  // namespace proxy
