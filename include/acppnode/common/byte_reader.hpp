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
#include <span>
#include <string>
#include <string_view>
#include <optional>
#include <vector>

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
     * 是否发生错误
     */
    [[nodiscard]] bool HasError() const noexcept { return error_; }
    
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
     * 总大小
     */
    [[nodiscard]] size_t Size() const noexcept { return size_; }
    
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

    /**
     * 读取 8 字节无符号整数（大端）
     */
    [[nodiscard]] uint64_t ReadU64BE() noexcept {
        if (!CanRead(8)) return 0;
        uint64_t result;
        std::memcpy(&result, data_ + pos_, 8);
        pos_ += 8;
        if constexpr (std::endian::native == std::endian::little)
            result = std::byteswap(result);
        return result;
    }
    
    // ========================================================================
    // 读取操作 - 小端字节序
    // ========================================================================
    
    /**
     * 读取 2 字节无符号整数（小端）
     */
    [[nodiscard]] uint16_t ReadU16LE() noexcept {
        if (!CanRead(2)) return 0;
        uint16_t result;
        std::memcpy(&result, data_ + pos_, 2);
        pos_ += 2;
        if constexpr (std::endian::native == std::endian::big)
            result = std::byteswap(result);
        return result;
    }

    /**
     * 读取 4 字节无符号整数（小端）
     */
    [[nodiscard]] uint32_t ReadU32LE() noexcept {
        if (!CanRead(4)) return 0;
        uint32_t result;
        std::memcpy(&result, data_ + pos_, 4);
        pos_ += 4;
        if constexpr (std::endian::native == std::endian::big)
            result = std::byteswap(result);
        return result;
    }

    /**
     * 读取 8 字节无符号整数（小端）
     */
    [[nodiscard]] uint64_t ReadU64LE() noexcept {
        if (!CanRead(8)) return 0;
        uint64_t result;
        std::memcpy(&result, data_ + pos_, 8);
        pos_ += 8;
        if constexpr (std::endian::native == std::endian::big)
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
     * 读取指定长度的字节到 vector
     */
    [[nodiscard]] std::vector<uint8_t> ReadBytesVec(size_t len) {
        auto span = ReadBytes(len);
        if (error_) return {};
        return std::vector<uint8_t>(span.begin(), span.end());
    }
    
    /**
     * 读取剩余所有字节
     */
    [[nodiscard]] std::span<const uint8_t> ReadRemaining() noexcept {
        return ReadBytes(Remaining());
    }
    
    /**
     * 读取固定长度字符串
     * 
     * @param len 字符串长度
     * @return 字符串；如果长度不足则返回空字符串并设置错误
     */
    [[nodiscard]] std::string ReadString(size_t len) {
        auto span = ReadBytes(len);
        if (error_) return {};
        return std::string(reinterpret_cast<const char*>(span.data()), span.size());
    }
    
    /**
     * 读取以长度前缀的字符串（1字节长度）
     */
    [[nodiscard]] std::string ReadLenPrefixedString8() {
        uint8_t len = ReadU8();
        if (error_) return {};
        return ReadString(len);
    }
    
    /**
     * 读取以长度前缀的字符串（2字节长度，大端）
     */
    [[nodiscard]] std::string ReadLenPrefixedString16BE() {
        uint16_t len = ReadU16BE();
        if (error_) return {};
        return ReadString(len);
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
    
    /**
     * 跳转到指定位置
     */
    bool Seek(size_t pos) noexcept {
        if (pos > size_) {
            error_ = true;
            return false;
        }
        pos_ = pos;
        return true;
    }
    
    /**
     * 回退到开头
     */
    void Reset() noexcept {
        pos_ = 0;
        error_ = false;
    }
    
    // ========================================================================
    // 查看操作（不移动位置）
    // ========================================================================
    
    /**
     * 查看当前位置的字节（不消费）
     */
    [[nodiscard]] std::optional<uint8_t> Peek() const noexcept {
        if (error_ || pos_ >= size_) return std::nullopt;
        return data_[pos_];
    }
    
    /**
     * 查看指定偏移处的字节（不消费）
     */
    [[nodiscard]] std::optional<uint8_t> PeekAt(size_t offset) const noexcept {
        if (error_ || pos_ + offset >= size_) return std::nullopt;
        return data_[pos_ + offset];
    }
    
    // ========================================================================
    // TryRead 系列方法 - 返回 optional（安全加固：明确区分错误和有效值 0）
    // ========================================================================
    
    /**
     * 尝试读取 1 字节无符号整数
     * @return 成功返回值，失败返回 nullopt
     */
    [[nodiscard]] std::optional<uint8_t> TryReadU8() noexcept {
        if (!CanRead(1)) return std::nullopt;
        return data_[pos_++];
    }
    
    /**
     * 尝试读取 2 字节无符号整数（大端）
     */
    [[nodiscard]] std::optional<uint16_t> TryReadU16BE() noexcept {
        if (!CanRead(2)) return std::nullopt;
        uint16_t result;
        std::memcpy(&result, data_ + pos_, 2);
        pos_ += 2;
        if constexpr (std::endian::native == std::endian::little)
            result = std::byteswap(result);
        return result;
    }

    /**
     * 尝试读取 4 字节无符号整数（大端）
     */
    [[nodiscard]] std::optional<uint32_t> TryReadU32BE() noexcept {
        if (!CanRead(4)) return std::nullopt;
        uint32_t result;
        std::memcpy(&result, data_ + pos_, 4);
        pos_ += 4;
        if constexpr (std::endian::native == std::endian::little)
            result = std::byteswap(result);
        return result;
    }
    
    /**
     * 获取当前位置的原始指针（用于与 C API 交互）
     */
    [[nodiscard]] const uint8_t* CurrentPtr() const noexcept {
        return data_ + pos_;
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
    
    explicit ByteWriter(std::span<uint8_t> span) noexcept
        : data_(span.data()), capacity_(span.size()), pos_(0), error_(false) {}
    
    // ========================================================================
    // 状态查询
    // ========================================================================
    
    [[nodiscard]] bool Ok() const noexcept { return !error_; }
    [[nodiscard]] bool HasError() const noexcept { return error_; }
    [[nodiscard]] size_t Remaining() const noexcept { 
        return error_ ? 0 : (capacity_ - pos_); 
    }
    [[nodiscard]] size_t Position() const noexcept { return pos_; }
    [[nodiscard]] size_t Capacity() const noexcept { return capacity_; }
    [[nodiscard]] size_t Written() const noexcept { return pos_; }
    
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

    bool WriteU64BE(uint64_t value) noexcept {
        if (!CanWrite(8)) return false;
        if constexpr (std::endian::native == std::endian::little)
            value = std::byteswap(value);
        std::memcpy(data_ + pos_, &value, 8);
        pos_ += 8;
        return true;
    }
    
    // ========================================================================
    // 写入操作 - 小端字节序
    // ========================================================================
    
    bool WriteU16LE(uint16_t value) noexcept {
        if (!CanWrite(2)) return false;
        if constexpr (std::endian::native == std::endian::big)
            value = std::byteswap(value);
        std::memcpy(data_ + pos_, &value, 2);
        pos_ += 2;
        return true;
    }

    bool WriteU32LE(uint32_t value) noexcept {
        if (!CanWrite(4)) return false;
        if constexpr (std::endian::native == std::endian::big)
            value = std::byteswap(value);
        std::memcpy(data_ + pos_, &value, 4);
        pos_ += 4;
        return true;
    }

    bool WriteU64LE(uint64_t value) noexcept {
        if (!CanWrite(8)) return false;
        if constexpr (std::endian::native == std::endian::big)
            value = std::byteswap(value);
        std::memcpy(data_ + pos_, &value, 8);
        pos_ += 8;
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
    
    /**
     * 写入以长度前缀的字符串（1字节长度）
     */
    bool WriteLenPrefixedString8(std::string_view str) noexcept {
        if (str.size() > 255) {
            error_ = true;
            return false;
        }
        if (!WriteU8(static_cast<uint8_t>(str.size()))) return false;
        return WriteString(str);
    }
    
    /**
     * 写入以长度前缀的字符串（2字节长度，大端）
     */
    bool WriteLenPrefixedString16BE(std::string_view str) noexcept {
        if (str.size() > 65535) {
            error_ = true;
            return false;
        }
        if (!WriteU16BE(static_cast<uint16_t>(str.size()))) return false;
        return WriteString(str);
    }
    
    /**
     * 填充指定字节
     */
    bool Fill(uint8_t value, size_t count) noexcept {
        if (!CanWrite(count)) return false;
        std::memset(data_ + pos_, value, count);
        pos_ += count;
        return true;
    }
    
    // ========================================================================
    // 导航操作
    // ========================================================================
    
    bool Skip(size_t count) noexcept {
        if (!CanWrite(count)) return false;
        pos_ += count;
        return true;
    }
    
    bool Seek(size_t pos) noexcept {
        if (pos > capacity_) {
            error_ = true;
            return false;
        }
        pos_ = pos;
        return true;
    }
    
    void Reset() noexcept {
        pos_ = 0;
        error_ = false;
    }
    
    /**
     * 获取当前位置的原始指针
     */
    [[nodiscard]] uint8_t* CurrentPtr() noexcept {
        return data_ + pos_;
    }
    
    /**
     * 获取已写入数据的 span
     */
    [[nodiscard]] std::span<const uint8_t> WrittenData() const noexcept {
        return std::span<const uint8_t>(data_, pos_);
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

// ============================================================================
// 便捷类型别名
// ============================================================================
using Cursor = ByteReader;  // 向后兼容

}  // namespace acpp
