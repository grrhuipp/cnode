#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace common {

// ============================================================================
// Buffer - mimalloc 连续字节缓冲（默认 8 KiB，按需几何扩容为单一连续块）
// ============================================================================
struct Buffer {
    static constexpr uint32_t kSize = 8192;

    size_t start = 0;
    size_t end   = 0;
    size_t capacity = kSize;
    std::optional<TargetAddress> udp_;
    bool mixed_udp_ = false;
    bool udp_untagged_ = false;
    alignas(std::max_align_t) uint8_t data[kSize];

    std::span<uint8_t> Bytes() noexcept {
        return {data + start, end - start};
    }
    std::span<const uint8_t> Bytes() const noexcept {
        return {data + start, end - start};
    }

    std::span<uint8_t> Tail() noexcept { return {data + end, capacity - end}; }

    size_t Len()       const noexcept { return end - start; }
    size_t Available() const noexcept { return capacity - end; }
    bool   IsEmpty()   const noexcept { return start == end; }

    void Advance(size_t n) noexcept { start += n; }
    void Produce(size_t n) noexcept { end += n; }

    void CompactToFront() noexcept {
        const size_t len = Len();
        if (start == 0) {
            return;
        }
        if (len > 0) {
            std::memmove(data, data + start, len);
        }
        start = 0;
        end = len;
    }

    void Reset() noexcept {
        start = 0;
        end = 0;
        udp_.reset();
        mixed_udp_ = false;
        udp_untagged_ = false;
    }

    void SetUDP(const TargetAddress& dest) {
        udp_ = dest;
        mixed_udp_ = false;
        udp_untagged_ = false;
    }
    void ClearUDP() noexcept {
        udp_.reset();
        mixed_udp_ = false;
        udp_untagged_ = false;
    }
    [[nodiscard]] bool HasUDP() const noexcept { return udp_.has_value(); }
    [[nodiscard]] TargetAddress& UDP() noexcept { return *udp_; }
    [[nodiscard]] const TargetAddress& UDP() const noexcept { return *udp_; }

    [[nodiscard]] static Buffer* New(size_t req_capacity = kSize) noexcept {
        const size_t cap = std::max<size_t>(req_capacity, kSize);
        const size_t header_size = offsetof(Buffer, data);
        if (cap > static_cast<size_t>(std::numeric_limits<std::ptrdiff_t>::max()) - header_size) {
            return nullptr;
        }
        void* raw = TryAllocateProcessRaw(header_size + cap, alignof(Buffer));
        if (!raw) return nullptr;
        auto* b = ::new (raw) Buffer(cap);
        OnBufferNew();
        return b;
    }

    static void Free(Buffer* b) noexcept {
        if (!b) {
            return;
        }
        OnBufferFree();
        b->~Buffer();
        mi_free(b);
    }

private:
    explicit Buffer(size_t cap) noexcept : capacity(cap) {}
};

struct BufferDeleter {
    void operator()(Buffer* b) const noexcept { Buffer::Free(b); }
};

using BufferGuard = std::unique_ptr<Buffer, BufferDeleter>;

// ============================================================================
// MultiBuffer - 单一连续 Buffer 所有权宿主（sizeof == 8，零分块链表开销）
// ============================================================================
class MultiBuffer {
public:
    MultiBuffer() noexcept = default;

    explicit MultiBuffer(BufferGuard buffer) noexcept
        : buf_(buffer.release()) {}

    MultiBuffer(const MultiBuffer&) = delete;
    MultiBuffer& operator=(const MultiBuffer&) = delete;

    MultiBuffer(MultiBuffer&& other) noexcept
        : buf_(std::exchange(other.buf_, nullptr)) {}

    MultiBuffer& operator=(MultiBuffer&& other) noexcept {
        if (this != &other) {
            Buffer::Free(buf_);
            buf_ = std::exchange(other.buf_, nullptr);
        }
        return *this;
    }

    ~MultiBuffer() noexcept {
        Buffer::Free(buf_);
    }

    [[nodiscard]] bool empty() const noexcept { return buf_ == nullptr; }
    [[nodiscard]] size_t byte_size() const noexcept { return buf_ ? buf_->Len() : 0; }
    [[nodiscard]] bool HasUDP() const noexcept {
        return buf_ && (buf_->HasUDP() || buf_->mixed_udp_);
    }
    [[nodiscard]] Buffer* FrontBuffer() noexcept { return buf_; }
    [[nodiscard]] const Buffer* FrontBuffer() const noexcept { return buf_; }
    void push_back(BufferGuard buffer) {
        if (!buffer) {
            return;
        }
        const size_t bytes = buffer->Len();
        if (bytes > std::numeric_limits<size_t>::max() - byte_size()) {
            throw std::length_error("MultiBuffer byte size overflow");
        }
        if (!buf_) {
            buf_ = buffer.release();
            return;
        }
        if (buf_->IsEmpty() && !buf_->HasUDP() && !buf_->mixed_udp_) {
            Buffer::Free(buf_);
            buf_ = buffer.release();
            return;
        }
        if (buffer->IsEmpty() && !buffer->HasUDP() && !buffer->mixed_udp_) {
            return;
        }
        AppendBufferContents(*buffer);
    }

    [[nodiscard]] BufferGuard pop_front() noexcept {
        return BufferGuard{std::exchange(buf_, nullptr)};
    }

    size_t DropPrefixBytes(size_t bytes) noexcept {
        if (!buf_) return 0;
        const size_t dropped = std::min(bytes, buf_->Len());
        buf_->Advance(dropped);
        ReleaseIfIdle();
        return dropped;
    }

    size_t ConsumePrefixTo(std::span<uint8_t> dst) noexcept {
        const size_t copied = CopyPrefixTo(dst);
        DropPrefixBytes(copied);
        return copied;
    }

    [[nodiscard]] bool MovePrefixTo(MultiBuffer& dst, size_t bytes) {
        if (std::addressof(dst) == this || bytes > byte_size() ||
            bytes > std::numeric_limits<size_t>::max() - dst.byte_size()) {
            return false;
        }
        if (bytes == 0) {
            ReleaseIfIdle();
            return true;
        }
        if (bytes == byte_size() && dst.empty()) {
            dst.buf_ = std::exchange(buf_, nullptr);
            return true;
        }
        try {
            const auto slice = buf_->Bytes().first(bytes);
            if (!dst.buf_) {
                BufferGuard next{Buffer::New(bytes)};
                if (!next) return false;
                if (buf_->HasUDP()) {
                    next->SetUDP(buf_->UDP());
                }
                next->mixed_udp_ = buf_->mixed_udp_;
                next->udp_untagged_ = buf_->udp_untagged_;
                std::memcpy(next->Tail().data(), slice.data(), bytes);
                next->Produce(bytes);
                dst.buf_ = next.release();
            } else {
                dst.AppendRawWithUdp(slice, buf_->udp_, buf_->mixed_udp_, buf_->udp_untagged_);
            }
        } catch (const std::bad_alloc&) {
            return false;
        } catch (const std::length_error&) {
            return false;
        }
        DropPrefixBytes(bytes);
        return true;
    }

    [[nodiscard]] std::span<const uint8_t> PrefixSpan(size_t len) const& noexcept {
        if (len == 0 || !buf_ || buf_->Len() < len) {
            return {};
        }
        return buf_->Bytes().first(len);
    }
    std::span<const uint8_t> PrefixSpan(size_t) const&& = delete;

    [[nodiscard]] std::span<const uint8_t> FrontSpan() const& noexcept {
        if (!buf_ || buf_->IsEmpty()) {
            return {};
        }
        return buf_->Bytes();
    }
    std::span<const uint8_t> FrontSpan() const&& = delete;

    [[nodiscard]] std::span<uint8_t> MutableFrontSpan() & noexcept {
        if (!buf_ || buf_->IsEmpty()) {
            return {};
        }
        return buf_->Bytes();
    }
    std::span<uint8_t> MutableFrontSpan() && = delete;
    size_t CopyPrefixTo(std::span<uint8_t> dst) const noexcept {
        if (!buf_ || dst.empty()) return 0;
        const auto bytes = buf_->Bytes();
        const size_t n = std::min(dst.size(), bytes.size());
        if (n > 0) {
            std::memcpy(dst.data(), bytes.data(), n);
        }
        return n;
    }

    [[nodiscard]] BufferGuard TakeFrontIfLen(size_t len) noexcept {
        ReleaseIfIdle();
        if (!buf_ || buf_->Len() != len) {
            return {};
        }
        return pop_front();
    }

    void clear() noexcept {
        Buffer::Free(std::exchange(buf_, nullptr));
    }

    void ReleaseIfIdle() noexcept {
        if (buf_ && buf_->IsEmpty() && !buf_->HasUDP() && !buf_->mixed_udp_) {
            clear();
        }
    }

    void MoveTo(MultiBuffer& dst, bool clear_udp = false) {
        if (std::addressof(dst) == this) {
            return;
        }
        ReleaseIfIdle();
        if (!buf_) {
            return;
        }
        if (clear_udp && buf_->IsEmpty()) {
            clear();
            return;
        }
        if (!dst.buf_ || (dst.buf_->IsEmpty() && !dst.buf_->HasUDP() && !dst.buf_->mixed_udp_)) {
            Buffer::Free(dst.buf_);
            dst.buf_ = std::exchange(buf_, nullptr);
            if (clear_udp) dst.buf_->ClearUDP();
            return;
        }
        if (clear_udp) {
            dst.AppendRawWithUdp(buf_->Bytes(), std::nullopt, false, !buf_->IsEmpty());
        } else {
            dst.AppendBufferContents(*buf_);
        }
        clear();
    }

    void AppendAndCoalesce(MultiBuffer&& next) {
        if (std::addressof(next) == this) {
            return;
        }
        next.MoveTo(*this, false);
    }

    [[nodiscard]] bool AppendSpan(std::span<const uint8_t> data) {
        if (data.empty()) return true;
        if (data.size() > std::numeric_limits<size_t>::max() - byte_size()) {
            throw std::length_error("MultiBuffer byte size overflow");
        }
        try {
            if (!buf_) {
                BufferGuard next{Buffer::New(data.size())};
                if (!next) return false;
                std::memcpy(next->Tail().data(), data.data(), data.size());
                next->Produce(data.size());
                buf_ = next.release();
                return true;
            }
            AppendRawWithUdp(data, std::nullopt, false, true);
            return true;
        } catch (const std::bad_alloc&) {
            return false;
        }
    }

private:
    void AppendBufferContents(const Buffer& src) {
        AppendRawWithUdp(src.Bytes(), src.udp_, src.mixed_udp_, !src.HasUDP() && !src.IsEmpty());
    }

    void AppendRawWithUdp(std::span<const uint8_t> bytes,
                          const std::optional<TargetAddress>& src_udp,
                          bool src_mixed_udp,
                          bool src_untagged_nonempty) {
        const size_t current_len = buf_->Len();
        if (bytes.size() > std::numeric_limits<size_t>::max() - current_len) {
            throw std::length_error("MultiBuffer byte size overflow");
        }
        const bool existing_has_udp = buf_->HasUDP();
        const bool existing_nonempty = !buf_->IsEmpty();
        bool next_mixed = buf_->mixed_udp_ || src_mixed_udp;
        bool next_untagged = buf_->udp_untagged_ || (existing_nonempty && !existing_has_udp);
        std::optional<TargetAddress> next_udp = buf_->udp_;

        if (src_udp) {
            if (next_untagged) {
                next_mixed = true;
            } else if (!next_udp) {
                next_udp = *src_udp;
            } else if (!next_udp->SameEndpoint(*src_udp)) {
                next_mixed = true;
            }
        } else if (src_untagged_nonempty) {
            next_untagged = true;
        }

        if (buf_->Available() >= bytes.size()) {
            if (!bytes.empty()) {
                std::memmove(buf_->Tail().data(), bytes.data(), bytes.size());
                buf_->Produce(bytes.size());
            }
            buf_->udp_ = std::move(next_udp);
            buf_->mixed_udp_ = next_mixed;
            buf_->udp_untagged_ = next_untagged;
            return;
        }
        if (buf_->Available() + buf_->start >= bytes.size()) {
            buf_->CompactToFront();
            if (!bytes.empty()) {
                std::memmove(buf_->Tail().data(), bytes.data(), bytes.size());
                buf_->Produce(bytes.size());
            }
            buf_->udp_ = std::move(next_udp);
            buf_->mixed_udp_ = next_mixed;
            buf_->udp_untagged_ = next_untagged;
            return;
        }

        const size_t needed = current_len + bytes.size();
        const size_t doubled = buf_->capacity <= std::numeric_limits<size_t>::max() / 2
            ? buf_->capacity * 2
            : std::numeric_limits<size_t>::max();
        const size_t new_cap = std::max(needed, std::min(doubled,
            static_cast<size_t>(std::numeric_limits<std::ptrdiff_t>::max()) - offsetof(Buffer, data)));
        BufferGuard grown{Buffer::New(new_cap)};
        if (!grown) {
            throw std::bad_alloc();
        }
        if (current_len > 0) {
            std::memcpy(grown->data, buf_->Bytes().data(), current_len);
            grown->Produce(current_len);
        }
        if (!bytes.empty()) {
            std::memcpy(grown->Tail().data(), bytes.data(), bytes.size());
            grown->Produce(bytes.size());
        }
        grown->udp_ = std::move(next_udp);
        grown->mixed_udp_ = next_mixed;
        grown->udp_untagged_ = next_untagged;
        Buffer::Free(buf_);
        buf_ = grown.release();
    }

    Buffer* buf_ = nullptr;
};

[[nodiscard]] inline bool SetUdpTarget(MultiBuffer& packet, const TargetAddress& target) {
    if (packet.empty()) {
        BufferGuard buffer{Buffer::New()};
        if (!buffer) return false;
        buffer->SetUDP(target);
        packet.push_back(std::move(buffer));
        return true;
    }
    packet.FrontBuffer()->SetUDP(target);
    return true;
}

enum class UdpDatagramStatus : uint8_t {
    Empty,
    Valid,
    MissingTarget,
    MixedTarget,
};

struct UdpDatagramInfo {
    UdpDatagramStatus status = UdpDatagramStatus::Empty;
    const TargetAddress* target = nullptr;
    const Buffer* single_buffer = nullptr;
    size_t payload_size = 0;

    [[nodiscard]] bool Valid() const noexcept {
        return status == UdpDatagramStatus::Valid;
    }
};

[[nodiscard]] inline UdpDatagramInfo InspectUdpDatagram(
    const MultiBuffer& mb) noexcept {
    UdpDatagramInfo info;
    const Buffer* buffer = mb.FrontBuffer();
    if (!buffer || (buffer->IsEmpty() && !buffer->HasUDP() && !buffer->mixed_udp_)) {
        return info;
    }
    if (buffer->mixed_udp_) {
        info.status = UdpDatagramStatus::MixedTarget;
        return info;
    }
    if (!buffer->HasUDP() || buffer->udp_untagged_) {
        info.status = UdpDatagramStatus::MissingTarget;
        return info;
    }
    info.status = UdpDatagramStatus::Valid;
    info.target = std::addressof(buffer->UDP());
    info.single_buffer = buffer;
    info.payload_size = buffer->Len();
    return info;
}

UdpDatagramInfo InspectUdpDatagram(const MultiBuffer&&) = delete;

class ContiguousWriteBuffer {
public:
    ContiguousWriteBuffer() noexcept = default;
    ContiguousWriteBuffer(const ContiguousWriteBuffer&) = delete;
    ContiguousWriteBuffer& operator=(const ContiguousWriteBuffer&) = delete;
    ContiguousWriteBuffer(ContiguousWriteBuffer&&) noexcept = default;
    ContiguousWriteBuffer& operator=(ContiguousWriteBuffer&&) noexcept = default;
    ~ContiguousWriteBuffer() noexcept = default;

    [[nodiscard]] uint8_t* Prepare(size_t capacity) {
        Reset();
        if (capacity > kMaxCapacity) {
            throw std::length_error("ContiguousWriteBuffer capacity");
        }
        buf_ = BufferGuard{Buffer::New(capacity)};
        if (!buf_) {
            throw std::bad_alloc();
        }
        return buf_->Tail().data();
    }

    [[nodiscard]] uint8_t* TryPrepare(size_t capacity) noexcept {
        if (capacity > kMaxCapacity) {
            Reset();
            return nullptr;
        }
        try {
            return Prepare(capacity);
        } catch (const std::bad_alloc&) {
            return nullptr;
        }
    }

    [[nodiscard]] uint8_t* Data() noexcept {
        return buf_ ? buf_->Tail().data() : nullptr;
    }

    [[nodiscard]] bool Empty() const noexcept {
        return !buf_;
    }

    void Reset() noexcept {
        buf_.reset();
    }

    [[nodiscard]] bool TryAppendTo(size_t size, MultiBuffer& out) noexcept {
        try {
            if (!buf_ || size > buf_->Available()) {
                Reset();
                return false;
            }
            buf_->Produce(size);
            out.push_back(std::move(buf_));
            Reset();
            return true;
        } catch (...) {
            Reset();
            return false;
        }
    }

    void AppendTo(size_t size, MultiBuffer& out) {
        if (!TryAppendTo(size, out)) {
            throw std::bad_alloc();
        }
    }

private:
    static constexpr size_t kMaxCapacity =
        static_cast<size_t>(std::numeric_limits<std::ptrdiff_t>::max()) - offsetof(Buffer, data);

    BufferGuard buf_;
};

class ContiguousBufferView {
public:
    ContiguousBufferView(const ContiguousBufferView&) = delete;
    ContiguousBufferView& operator=(const ContiguousBufferView&) = delete;
    ContiguousBufferView(const MultiBuffer&&) = delete;

    explicit ContiguousBufferView(const MultiBuffer& buffers) noexcept
        : bytes_(buffers.FrontSpan()) {}

    explicit ContiguousBufferView(std::span<const net::const_buffer> buffers) {
        const net::const_buffer* single = nullptr;
        size_t buffer_count = 0;
        size_t total_size = 0;
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            if (!buffer.data()) {
                throw IoSystemError(
                    io_error::invalid_argument,
                    "buffer sequence contains a null data pointer");
            }
            AddSize(buffer.size(), total_size);
            single = &buffer;
            ++buffer_count;
        }
        if (buffer_count == 0) {
            return;
        }
        if (buffer_count == 1) {
            bytes_ = std::span<const uint8_t>(
                static_cast<const uint8_t*>(single->data()), single->size());
            return;
        }
        owned_.reserve(total_size);
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            owned_.insert(owned_.end(), data, data + buffer.size());
        }
        bytes_ = owned_;
    }

    [[nodiscard]] std::span<const uint8_t> Bytes() const & noexcept {
        return bytes_;
    }
    std::span<const uint8_t> Bytes() const && = delete;

private:
    static void AddSize(size_t size, size_t& total_size) {
        if (size > std::numeric_limits<size_t>::max() - total_size) {
            throw IoSystemError(
                io_error::message_size, "buffer sequence is too large");
        }
        total_size += size;
    }

    std::vector<uint8_t> owned_;
    std::span<const uint8_t> bytes_;
};

class MultiBufferBatch {
public:
    MultiBufferBatch() noexcept = default;
    explicit MultiBufferBatch(MultiBuffer payload) { Push(std::move(payload)); }
    MultiBufferBatch(const MultiBufferBatch&) = delete;
    MultiBufferBatch& operator=(const MultiBufferBatch&) = delete;

    MultiBufferBatch(MultiBufferBatch&& other) noexcept
        : first_(std::move(other.first_)), overflow_(std::move(other.overflow_)),
          bytes_(std::exchange(other.bytes_, 0)),
          occupied_(std::exchange(other.occupied_, false)) {}

    MultiBufferBatch& operator=(MultiBufferBatch&& other) noexcept {
        if (this != &other) {
            clear();
            overflow_ = std::move(other.overflow_);
            first_ = std::move(other.first_);
            bytes_ = std::exchange(other.bytes_, 0);
            occupied_ = std::exchange(other.occupied_, false);
        }
        return *this;
    }

    void Push(MultiBuffer payload) {
        const size_t bytes = payload.byte_size();
        if (bytes == 0 && !payload.HasUDP()) {
            payload.clear();
            return;
        }
        if (bytes > std::numeric_limits<size_t>::max() - bytes_) {
            throw std::length_error("MultiBufferBatch byte size overflow");
        }
        if (!occupied_) {
            first_ = std::move(payload);
            occupied_ = true;
        } else {
            overflow_.push_back(std::move(payload));
        }
        bytes_ += bytes;
    }

    [[nodiscard]] MultiBuffer PopFront() noexcept {
        if (!occupied_) return {};
        MultiBuffer result = std::move(first_);
        bytes_ -= result.byte_size();
        if (!overflow_.empty()) {
            first_ = std::move(overflow_.front());
            overflow_.pop_front();
        } else {
            occupied_ = false;
        }
        return result;
    }

    [[nodiscard]] bool empty() const noexcept { return !occupied_; }
    [[nodiscard]] size_t byte_size() const noexcept { return bytes_; }

    void clear() noexcept {
        first_.clear();
        overflow_.clear();
        bytes_ = 0;
        occupied_ = false;
    }

private:
    MultiBuffer first_;
    RingDeque<MultiBuffer> overflow_;
    size_t bytes_ = 0;
    bool occupied_ = false;
};

[[nodiscard]] inline std::span<const uint8_t> ChunkBytes(const net::const_buffer& buffer) noexcept {
    if (!buffer.data() || buffer.size() == 0) {
        return {};
    }
    return {static_cast<const uint8_t*>(buffer.data()), buffer.size()};
}


// The upstream bytes a protocol already decoded before dispatch. They cross
// Dispatch by value exactly once and become the relay's first upload batch;
// the owned buffers are transferred, never copied or staged inline.
class InitialPayload {
public:
    InitialPayload() noexcept = default;
    explicit InitialPayload(MultiBuffer data) noexcept : data_(std::move(data)) {
        data_.ReleaseIfIdle();
    }

    InitialPayload(const InitialPayload&) = delete;
    InitialPayload& operator=(const InitialPayload&) = delete;
    InitialPayload(InitialPayload&&) noexcept = default;
    InitialPayload& operator=(InitialPayload&&) noexcept = default;

    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

    [[nodiscard]] MultiBuffer MoveToMultiBuffer() && noexcept { return std::move(data_); }

private:
    MultiBuffer data_;
};
}  // namespace common
