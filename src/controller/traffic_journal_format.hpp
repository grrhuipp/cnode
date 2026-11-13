#pragma once

#include <charconv>
#include "common/binary_text_codec.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <unistd.h>

#include <cerrno>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

// 流量 journal 的磁盘格式：cnode 写入与 cnode_traffic_journal 对账共用这一份
// 文法、上限与解码，任何一侧都不另行解释记录。
namespace controller {

struct ScopedFd {
    int fd = -1;
    ScopedFd() noexcept = default;
    explicit ScopedFd(int value) noexcept : fd(value) {}
    ~ScopedFd() {
        if (fd >= 0) ::close(fd);
    }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    ScopedFd(ScopedFd&& other) noexcept : fd(std::exchange(other.fd, -1)) {}
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) {
            if (fd >= 0) ::close(fd);
            fd = std::exchange(other.fd, -1);
        }
        return *this;
    }
};

[[nodiscard]] inline bool WriteAllFd(int fd, std::string_view data) noexcept {
    size_t offset = 0;
    while (offset != data.size()) {
        const auto count = ::write(fd, data.data() + offset, data.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (count == 0) errno = EIO;
            return false;
        }
        offset += static_cast<size_t>(count);
    }
    return true;
}

[[nodiscard]] inline std::string Sha256Hex(std::string_view raw) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(raw.data()), raw.size(), digest.data());
    return common::EncodeHexLower(digest);
}

// 单条记录与目录内全部 ready/unknown 记录的字节上限，以及记录条数上限。
inline constexpr size_t kMaxBytes = 64 * 1024 * 1024;
inline constexpr size_t kMaxRecords = 1024;

// 记录名：`batch-` + 6 个 [A-Za-z0-9]（mkostemps 生成）+ 状态后缀。
// `.tmp` 从未发布或发送；`.ready` 可以发送；`.unknown` 已开始发送、结果未知，
// 只能人工对账，绝不自动重试。
inline constexpr std::string_view kRecordPrefix = "batch-";
inline constexpr size_t kRecordIdSize = 6;
inline constexpr std::string_view kTemporarySuffix = ".tmp";
inline constexpr std::string_view kReadySuffix = ".ready";
inline constexpr std::string_view kUnknownSuffix = ".unknown";

enum class RecordState : uint8_t { Ready, Unknown };

[[nodiscard]] constexpr std::string_view RecordSuffix(RecordState state) noexcept {
    return state == RecordState::Ready ? kReadySuffix : kUnknownSuffix;
}

// 只接受完整文法的已发布记录名；其他目录项（锁、审计日志、临时文件）不是记录。
[[nodiscard]] constexpr std::optional<RecordState> ParseRecordName(std::string_view name) noexcept {
    constexpr size_t stem_size = kRecordPrefix.size() + kRecordIdSize;
    if (name.size() <= stem_size || !name.starts_with(kRecordPrefix)) return std::nullopt;
    for (const char ch : name.substr(kRecordPrefix.size(), kRecordIdSize)) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))) {
            return std::nullopt;
        }
    }
    const auto suffix = name.substr(stem_size);
    if (suffix == kReadySuffix) return RecordState::Ready;
    if (suffix == kUnknownSuffix) return RecordState::Unknown;
    return std::nullopt;
}

// 同一记录在另一状态下的文件名；`name` 必须已通过 ParseRecordName。
[[nodiscard]] inline std::string RecordNameWithState(std::string_view name, RecordState state) {
    std::string result(name.substr(0, kRecordPrefix.size() + kRecordIdSize));
    result += RecordSuffix(state);
    return result;
}

// 一行记录 `[uid, upload, download]`：UniProxy 使用有符号 64 位整数，uid 为正，
// 上下行非负且不同时为零（全零行从不写入）。
struct RecordRow {
    int64_t uid = 0;
    int64_t upload = 0;
    int64_t download = 0;
};

// 单遍零分配校验并逐行交给 `visit`；任何一行或尾随字节非法都使整条记录无效（抛 runtime_error）。
template <typename Visit>
void VisitRecordRows(std::string_view text, Visit&& visit) {
    size_t pos = 0;
    const auto skip_ws = [&]() noexcept {
        while (pos < text.size()) {
            const char c = text[pos];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
            ++pos;
        }
    };
    const auto consume_char = [&](char expected) noexcept {
        skip_ws();
        if (pos < text.size() && text[pos] == expected) {
            ++pos;
            return true;
        }
        return false;
    };
    const auto read_counter = [&](const char* invalid_what) -> int64_t {
        skip_ws();
        if (pos >= text.size()) {
            throw std::runtime_error(invalid_what);
        }
        const char first = text[pos];
        if (first < '0' || first > '9') {
            throw std::runtime_error(invalid_what);
        }
        const size_t start = pos++;
        if (first == '0') {
            if (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
                throw std::runtime_error(invalid_what);
            }
        } else {
            while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
                ++pos;
            }
        }
        int64_t value = 0;
        const auto [end, ec] = std::from_chars(text.data() + start, text.data() + pos, value);
        if (ec != std::errc{} || end != text.data() + pos) {
            throw std::runtime_error(invalid_what);
        }
        return value;
    };

    if (!consume_char('[')) {
        throw std::runtime_error("invalid traffic journal record");
    }
    if (!consume_char(']')) {
        for (;;) {
            if (!consume_char('[')) {
                throw std::runtime_error("invalid traffic journal row");
            }
            const int64_t uid = read_counter("invalid traffic journal counters");
            if (!consume_char(',')) {
                throw std::runtime_error("invalid traffic journal row");
            }
            const int64_t upload = read_counter("invalid traffic journal counters");
            if (!consume_char(',')) {
                throw std::runtime_error("invalid traffic journal row");
            }
            const int64_t download = read_counter("invalid traffic journal counters");
            if (!consume_char(']')) {
                throw std::runtime_error("invalid traffic journal row");
            }
            if (uid <= 0 || (upload == 0 && download == 0)) {
                throw std::runtime_error("invalid traffic journal counters");
            }
            visit(RecordRow{.uid = uid, .upload = upload, .download = download});
            if (consume_char(',')) {
                continue;
            }
            if (!consume_char(']')) {
                throw std::runtime_error("invalid traffic journal record");
            }
            break;
        }
    }
    skip_ws();
    if (pos != text.size()) {
        throw std::runtime_error("invalid traffic journal record");
    }
}

// 在 journal 目录内按名读取一条记录：不跟随符号链接，只接受普通文件，
// 先按 fstat 大小受 kMaxBytes 约束再分配。
[[nodiscard]] inline std::string ReadRecord(int directory_fd, const char* name) {
    const auto fail = [](const char* operation) {
        throw std::system_error(errno, std::generic_category(), operation);
    };
    const int fd = ::openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("open traffic journal record");
    ScopedFd closer(fd);
    struct stat info{};
    if (::fstat(fd, &info) != 0) fail("stat traffic journal record");
    if (!S_ISREG(info.st_mode) || info.st_size < 0 ||
        static_cast<uint64_t>(info.st_size) > kMaxBytes) {
        throw std::runtime_error("invalid traffic journal record size/type");
    }
    std::string text(static_cast<size_t>(info.st_size), '\0');
    size_t offset = 0;
    while (offset != text.size()) {
        const auto count = ::read(fd, text.data() + offset, text.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) fail("read traffic journal record");
        if (count == 0) throw std::runtime_error("truncated traffic journal record");
        offset += static_cast<size_t>(count);
    }
    return text;
}

}  // namespace controller
