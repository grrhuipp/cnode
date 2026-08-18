#pragma once

/**
 * ByteReader / ByteWriter - 协议解析安全模块（ISSUE-02-03）
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ 设计目的：                                                              │
 * │   1. 所有协议字段读取必须经过边界检查                                    │
 * │   2. 统一字节序转换（大端/小端）                                         │
 * │   3. 提供清晰的错误处理机制                                              │
 * │   4. 防止缓冲区溢出攻击                                                 │
 * │                                                                         │
 * │ 使用示例：                                                              │
 * │   ByteReader reader(data, len);                                        │
 * │   auto version = reader.ReadU8();                                      │
 * │   auto cmd = reader.ReadU8();                                          │
 * │   auto port = reader.ReadU16BE();                                      │
 * │   if (!reader.Ok()) return ParseError;                                  │
 * └─────────────────────────────────────────────────────────────────────────┘
 */

#include <bit>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>

namespace acpp {

// ============================================================================
// ByteReader - 安全的字节读取器
// ============================================================================
class ByteReader {
public:
    /**
     * 构造函数
     *
     * @param data 数据指针
     * @param size 数据大小
     */
    ByteReader(const uint8_t* data, size_t size) noexcept
        : data_(data), size_(size), pos_(0), error_(false) {}

    explicit ByteReader(std::span<const uint8_t> span) noexcept
        : data_(span.data()), size_(span.size()), pos_(0), error_(false) {}

    // ========================================================================
    // 状态查询
    // ========================================================================

    /**
     * 是否处于有效状态（无错误）
     */
    [[nodiscard]] bool Ok() const noexcept { return !error_; }

    /**
     * 剩余可读字节数
     */
    [[nodiscard]] size_t Remaining() const noexcept {
        return error_ ? 0 : (size_ - pos_);
    }

    /**
     * 当前位置
     */
    [[nodiscard]] size_t Position() const noexcept { return pos_; }

    /**
     * 是否读完
     */
    [[nodiscard]] bool Empty() const noexcept { return Remaining() == 0; }

    // ========================================================================
    // 读取操作 - 大端字节序（网络字节序）
    // ========================================================================

    /**
     * 读取 1 字节无符号整数
     */
    [[nodiscard]] uint8_t ReadU8() noexcept {
        if (!CanRead(1)) return 0;
        return data_[pos_++];
    }

    /**
     * 读取 2 字节无符号整数（大端）
     */
    [[nodiscard]] uint16_t ReadU16BE() noexcept {
        if (!CanRead(2)) return 0;
        uint16_t result;
        std::memcpy(&result, data_ + pos_, 2);
        pos_ += 2;
        if constexpr (std::endian::native == std::endian::little)
            result = std::byteswap(result);
        return result;
    }

    /**
     * 读取 4 字节无符号整数（大端）
     */
    [[nodiscard]] uint32_t ReadU32BE() noexcept {
        if (!CanRead(4)) return 0;
        uint32_t result;
        std::memcpy(&result, data_ + pos_, 4);
        pos_ += 4;
        if constexpr (std::endian::native == std::endian::little)
            result = std::byteswap(result);
        return result;
    }

    // ========================================================================
    // 批量读取
    // ========================================================================

    /**
     * 读取指定长度的字节数组
     *
     * @param len 要读取的长度
     * @return 字节数组的 span；如果长度不足则返回空 span 并设置错误
     */
    [[nodiscard]] std::span<const uint8_t> ReadBytes(size_t len) noexcept {
        if (!CanRead(len)) return {};
        std::span<const uint8_t> result(data_ + pos_, len);
        pos_ += len;
        return result;
    }

    /**
     * 读取固定长度字符串视图。
     *
     * 返回值只在 ByteReader 底层输入缓冲区存活期间有效；协议解析热路径用它
     * 避免先分配 std::string，再拷贝到 TargetAddress 的 worker heap 字符串。
     */
    [[nodiscard]] std::string_view ReadStringView(size_t len) noexcept {
        auto span = ReadBytes(len);
        if (error_) return {};
        return {reinterpret_cast<const char*>(span.data()), span.size()};
    }

    // ========================================================================
    // 导航操作
    // ========================================================================

    /**
     * 跳过指定字节数
     */
    bool Skip(size_t count) noexcept {
        if (!CanRead(count)) return false;
        pos_ += count;
        return true;
    }

    [[nodiscard]] std::optional<uint8_t> Peek() const noexcept {
        if (error_ || pos_ >= size_) return std::nullopt;
        return data_[pos_];
    }

private:
    /**
     * 检查是否可以读取指定字节数
     */
    [[nodiscard]] bool CanRead(size_t count) noexcept {
        if (error_ || pos_ + count > size_) {
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

// ============================================================================
// ByteWriter - 安全的字节写入器
// ============================================================================
class ByteWriter {
public:
    /**
     * 构造函数
     *
     * @param data 目标缓冲区指针
     * @param capacity 缓冲区容量
     */
    ByteWriter(uint8_t* data, size_t capacity) noexcept
        : data_(data), capacity_(capacity), pos_(0), error_(false) {}

    // ========================================================================
    // 状态查询
    // ========================================================================

    [[nodiscard]] bool Ok() const noexcept { return !error_; }
    [[nodiscard]] size_t Position() const noexcept { return pos_; }

    // ========================================================================
    // 写入操作 - 大端字节序
    // ========================================================================

    bool WriteU8(uint8_t value) noexcept {
        if (!CanWrite(1)) return false;
        data_[pos_++] = value;
        return true;
    }

    bool WriteU16BE(uint16_t value) noexcept {
        if (!CanWrite(2)) return false;
        if constexpr (std::endian::native == std::endian::little)
            value = std::byteswap(value);
        std::memcpy(data_ + pos_, &value, 2);
        pos_ += 2;
        return true;
    }

    bool WriteU32BE(uint32_t value) noexcept {
        if (!CanWrite(4)) return false;
        if constexpr (std::endian::native == std::endian::little)
            value = std::byteswap(value);
        std::memcpy(data_ + pos_, &value, 4);
        pos_ += 4;
        return true;
    }

    // ========================================================================
    // 批量写入
    // ========================================================================

    bool WriteBytes(const uint8_t* src, size_t len) noexcept {
        if (!CanWrite(len)) return false;
        std::memcpy(data_ + pos_, src, len);
        pos_ += len;
        return true;
    }

    bool WriteBytes(std::span<const uint8_t> span) noexcept {
        return WriteBytes(span.data(), span.size());
    }

    bool WriteString(std::string_view str) noexcept {
        return WriteBytes(reinterpret_cast<const uint8_t*>(str.data()), str.size());
    }

private:
    [[nodiscard]] bool CanWrite(size_t count) noexcept {
        if (error_ || pos_ + count > capacity_) {
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

}  // namespace acpp
