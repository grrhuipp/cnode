#pragma once

#include "infra/json.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

// 流量 journal 的磁盘格式：cnode 写入与 cnode_traffic_journal 对账共用这一份
// 文法、上限与解码，任何一侧都不另行解释记录。
namespace controller::traffic_journal {

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

[[nodiscard]] inline std::optional<int64_t> DecodeCounter(const json::value& value) noexcept {
    const auto number = infra::JsonUnsignedInteger(value);
    if (!number || *number > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        return std::nullopt;
    }
    return static_cast<int64_t>(*number);
}

// 单遍校验并逐行交给 `visit`；任何一行非法都使整条记录无效（抛 runtime_error）。
template <typename Visit>
void VisitRecordRows(std::string_view text, Visit&& visit) {
    const auto parsed = json::parse(text);
    if (!parsed.is_array()) throw std::runtime_error("invalid traffic journal record");
    for (const auto& item : parsed.as_array()) {
        if (!item.is_array() || item.as_array().size() != 3) {
            throw std::runtime_error("invalid traffic journal row");
        }
        const auto& fields = item.as_array();
        const auto uid = DecodeCounter(fields[0]);
        const auto upload = DecodeCounter(fields[1]);
        const auto download = DecodeCounter(fields[2]);
        if (!uid || !upload || !download || *uid == 0 || (*upload == 0 && *download == 0)) {
            throw std::runtime_error("invalid traffic journal counters");
        }
        visit(RecordRow{.uid = *uid, .upload = *upload, .download = *download});
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
    struct Closer {
        int fd;
        ~Closer() { ::close(fd); }
    } closer{fd};
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

}  // namespace controller::traffic_journal
