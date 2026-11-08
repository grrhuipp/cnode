#pragma once

// Big-endian (network byte order) integer access for protocol parsing and
// framing. The raw-pointer Load/Store functions are the single authority for
// the byte layout; callers own the bounds check. ByteReader/ByteWriter add
// bounds checking: a failed read or write latches the error state and every
// later operation fails, so callers may check Ok() once after a run of fields.

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>


[[nodiscard]] constexpr uint16_t LoadU16BE(const uint8_t* in) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) |
                                 static_cast<uint16_t>(in[1]));
}

[[nodiscard]] constexpr uint32_t LoadU32BE(const uint8_t* in) noexcept {
    return (static_cast<uint32_t>(in[0]) << 24) |
           (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8) |
           static_cast<uint32_t>(in[3]);
}

[[nodiscard]] constexpr uint64_t LoadU64BE(const uint8_t* in) noexcept {
    return (static_cast<uint64_t>(LoadU32BE(in)) << 32) | LoadU32BE(in + 4);
}

constexpr void StoreU16BE(uint8_t* out, uint16_t value) noexcept {
    out[0] = static_cast<uint8_t>(value >> 8);
    out[1] = static_cast<uint8_t>(value);
}

constexpr void StoreU32BE(uint8_t* out, uint32_t value) noexcept {
    out[0] = static_cast<uint8_t>(value >> 24);
    out[1] = static_cast<uint8_t>(value >> 16);
    out[2] = static_cast<uint8_t>(value >> 8);
    out[3] = static_cast<uint8_t>(value);
}

constexpr void StoreU64BE(uint8_t* out, uint64_t value) noexcept {
    StoreU32BE(out, static_cast<uint32_t>(value >> 32));
    StoreU32BE(out + 4, static_cast<uint32_t>(value));
}

class ByteReader {
public:
    ByteReader(const uint8_t* data, size_t size) noexcept
        : data_(data), size_(size), pos_(0), error_(false) {}

    explicit ByteReader(std::span<const uint8_t> span) noexcept
        : data_(span.data()), size_(span.size()), pos_(0), error_(false) {}

    [[nodiscard]] bool Ok() const noexcept { return !error_; }

    [[nodiscard]] size_t Remaining() const noexcept {
        return error_ ? 0 : (size_ - pos_);
    }

    [[nodiscard]] size_t Position() const noexcept { return pos_; }

    [[nodiscard]] bool Empty() const noexcept { return Remaining() == 0; }

    [[nodiscard]] uint8_t ReadU8() noexcept {
        if (!CanRead(1)) return 0;
        return data_[pos_++];
    }

    [[nodiscard]] uint16_t ReadU16BE() noexcept {
        if (!CanRead(2)) return 0;
        const uint16_t result = LoadU16BE(data_ + pos_);
        pos_ += 2;
        return result;
    }

    [[nodiscard]] uint32_t ReadU32BE() noexcept {
        if (!CanRead(4)) return 0;
        const uint32_t result = LoadU32BE(data_ + pos_);
        pos_ += 4;
        return result;
    }

    // Empty span and latched error when fewer than len bytes remain.
    [[nodiscard]] std::span<const uint8_t> ReadBytes(size_t len) noexcept {
        if (!CanRead(len) || len == 0) return {};
        std::span<const uint8_t> result(data_ + pos_, len);
        pos_ += len;
        return result;
    }

    // Borrows the reader's input; valid only while that buffer is alive.
    [[nodiscard]] std::string_view ReadStringView(size_t len) noexcept {
        auto span = ReadBytes(len);
        if (error_) return {};
        return {reinterpret_cast<const char*>(span.data()), span.size()};
    }

    bool Skip(size_t count) noexcept {
        if (!CanRead(count)) return false;
        pos_ += count;
        return true;
    }

    [[nodiscard]] std::optional<uint8_t> Peek() const noexcept {
        if (error_ || !data_ || pos_ >= size_) return std::nullopt;
        return data_[pos_];
    }

private:
    // Subtractive comparison: count may be an untrusted wire length.
    [[nodiscard]] bool CanRead(size_t count) noexcept {
        if (error_ || (count != 0 && !data_) || count > size_ - pos_) {
            error_ = true;
            return false;
        }
        return true;
    }

    const uint8_t* data_;
    size_t size_;
    size_t pos_;
    bool error_;
};

class ByteWriter {
public:
    ByteWriter(uint8_t* data, size_t capacity) noexcept
        : data_(data), capacity_(capacity), pos_(0), error_(false) {}

    [[nodiscard]] bool Ok() const noexcept { return !error_; }
    [[nodiscard]] size_t Position() const noexcept { return pos_; }

    bool WriteU8(uint8_t value) noexcept {
        if (!CanWrite(1)) return false;
        data_[pos_++] = value;
        return true;
    }

    bool WriteU16BE(uint16_t value) noexcept {
        if (!CanWrite(2)) return false;
        StoreU16BE(data_ + pos_, value);
        pos_ += 2;
        return true;
    }

    bool WriteBytes(const uint8_t* src, size_t len) noexcept {
        if (len != 0 && !src) {
            error_ = true;
            return false;
        }
        if (!CanWrite(len)) return false;
        if (len != 0) {
            std::memcpy(data_ + pos_, src, len);
            pos_ += len;
        }
        return true;
    }

    bool WriteString(std::string_view str) noexcept {
        return WriteBytes(reinterpret_cast<const uint8_t*>(str.data()), str.size());
    }

private:
    [[nodiscard]] bool CanWrite(size_t count) noexcept {
        if (error_ || (count != 0 && !data_) || count > capacity_ - pos_) {
            error_ = true;
            return false;
        }
        return true;
    }
    uint8_t* data_;
    size_t capacity_;
    size_t pos_;
    bool error_;
};

