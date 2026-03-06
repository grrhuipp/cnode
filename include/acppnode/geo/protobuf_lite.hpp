#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛

namespace acpp {
namespace proto {

// ============================================================================
// 轻量级 Protobuf 解码器
// 只支持读取，不支持写入
// 支持：varint, bytes/string, embedded messages
// ============================================================================

// Wire types
enum WireType {
    VARINT = 0,           // int32, int64, uint32, uint64, sint32, sint64, bool, enum
    FIXED64 = 1,          // fixed64, sfixed64, double
    LENGTH_DELIMITED = 2, // string, bytes, embedded messages, packed repeated
    START_GROUP = 3,      // deprecated
    END_GROUP = 4,        // deprecated
    FIXED32 = 5,          // fixed32, sfixed32, float
};

// Protobuf 读取器
class ProtoReader {
public:
    ProtoReader(const uint8_t* data, size_t size)
        : data_(data), size_(size), pos_(0) {}
    
    ProtoReader(std::string_view data)
        // ISSUE-02-02: 使用 unsafe::ptr_cast 替代 reinterpret_cast
        : data_(unsafe::ptr_cast<const uint8_t>(data.data()))
        , size_(data.size())
        , pos_(0) {}
    
    // 是否还有数据
    bool HasMore() const { return pos_ < size_; }
    
    // 当前位置
    size_t Position() const { return pos_; }
    
    // 剩余字节数
    size_t Remaining() const { return size_ - pos_; }
    
    // 跳过指定字节
    bool Skip(size_t n) {
        if (pos_ + n > size_) return false;
        pos_ += n;
        return true;
    }
    
    // 读取 tag（field number + wire type）
    bool ReadTag(uint32_t& field_number, WireType& wire_type) {
        uint64_t tag;
        if (!ReadVarint(tag)) return false;
        field_number = static_cast<uint32_t>(tag >> 3);
        wire_type = static_cast<WireType>(tag & 0x07);
        return true;
    }
    
    // 读取 varint
    bool ReadVarint(uint64_t& value) {
        value = 0;
        int shift = 0;
        while (pos_ < size_) {
            uint8_t b = data_[pos_++];
            value |= static_cast<uint64_t>(b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return true;
            }
            shift += 7;
            if (shift >= 64) return false;  // 溢出
        }
        return false;
    }
    
    bool ReadVarint32(uint32_t& value) {
        uint64_t v;
        if (!ReadVarint(v)) return false;
        value = static_cast<uint32_t>(v);
        return true;
    }
    
    bool ReadVarint64(uint64_t& value) {
        return ReadVarint(value);
    }
    
    // 读取定长数据
    bool ReadFixed32(uint32_t& value) {
        if (pos_ + 4 > size_) return false;
        std::memcpy(&value, data_ + pos_, 4);
        pos_ += 4;
        return true;
    }
    
    bool ReadFixed64(uint64_t& value) {
        if (pos_ + 8 > size_) return false;
        std::memcpy(&value, data_ + pos_, 8);
        pos_ += 8;
        return true;
    }
    
    // 读取 bytes/string（先读长度，再读数据）
    bool ReadBytes(std::string_view& data) {
        uint64_t len;
        if (!ReadVarint(len)) return false;
        if (pos_ + len > size_) return false;
        // ISSUE-02-02: 使用 unsafe::ptr_cast 替代 reinterpret_cast
        data = std::string_view(unsafe::ptr_cast<const char>(data_ + pos_), len);
        pos_ += len;
        return true;
    }
    
    bool ReadString(std::string& str) {
        std::string_view sv;
        if (!ReadBytes(sv)) return false;
        str = std::string(sv);
        return true;
    }
    
    // 读取原始字节
    bool ReadRaw(std::vector<uint8_t>& data) {
        uint64_t len;
        if (!ReadVarint(len)) return false;
        if (pos_ + len > size_) return false;
        data.resize(len);
        std::memcpy(data.data(), data_ + pos_, len);
        pos_ += len;
        return true;
    }
    
    // 读取子消息（返回子 reader）
    std::optional<ProtoReader> ReadSubMessage() {
        uint64_t len;
        if (!ReadVarint(len)) return std::nullopt;
        if (pos_ + len > size_) return std::nullopt;
        ProtoReader sub(data_ + pos_, len);
        pos_ += len;
        return sub;
    }
    
    // 跳过当前字段
    bool SkipField(WireType wire_type) {
        switch (wire_type) {
            case VARINT: {
                uint64_t dummy;
                return ReadVarint(dummy);
            }
            case FIXED64:
                return Skip(8);
            case LENGTH_DELIMITED: {
                uint64_t len;
                if (!ReadVarint(len)) return false;
                return Skip(len);
            }
            case FIXED32:
                return Skip(4);
            default:
                return false;
        }
    }
    
    // 获取当前位置的原始数据指针
    const uint8_t* CurrentData() const { return data_ + pos_; }

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_;
};

}  // namespace proto
}  // namespace acpp
