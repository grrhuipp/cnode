#include "infra/json.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr size_t MaxRecordBytes = 64 * 1024 * 1024;
constexpr size_t MaxAuditBytes = 1024 * 1024;

[[noreturn]] void FailSystem(const char* operation) {
    throw std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

class File {
public:
    explicit File(int fd) : fd_(fd) { if (fd < 0) FailSystem("open"); }
    ~File() { ::close(fd_); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    int Get() const noexcept { return fd_; }
private:
    int fd_;
};

void Sync(int fd) {
    if (::fsync(fd) != 0) FailSystem("fsync");
}

bool RecordName(std::string_view name) {
    if (!name.starts_with("batch-") || name.size() < 18) return false;
    for (char character : name.substr(6, 6)) {
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9'))) return false;
    }
    return name.substr(12) == ".ready" || name.substr(12) == ".unknown";
}

std::string ReadRecord(int directory, const std::string& name) {
    File file(::openat(directory, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    struct stat info {};
    if (::fstat(file.Get(), &info) != 0) FailSystem("fstat");
    if (!S_ISREG(info.st_mode) || info.st_size < 0 ||
        static_cast<uint64_t>(info.st_size) > MaxRecordBytes)
        throw std::runtime_error("invalid record type or size");
    std::string raw;
    std::array<char, 8192> buffer {};
    for (;;) {
        const auto count = ::read(file.Get(), buffer.data(), buffer.size());
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            FailSystem("read");
        }
        if (static_cast<size_t>(count) > MaxRecordBytes - raw.size())
            throw std::runtime_error("record size limit exceeded");
        raw.append(buffer.data(), static_cast<size_t>(count));
    }
    return raw;
}

uint64_t Counter(const ::json::value& value) {
    if (value.is_int64() && value.as_int64() >= 0)
        return static_cast<uint64_t>(value.as_int64());
    if (value.is_uint64() && value.as_uint64() <= static_cast<uint64_t>(INT64_MAX))
        return value.as_uint64();
    throw std::runtime_error("invalid record counters");
}

struct Summary {
    size_t users = 0;
    __uint128_t upload = 0;
    __uint128_t download = 0;
};

Summary Summarize(std::string_view raw) {
    const auto value = ::json::parse(raw);
    if (!value.is_array()) throw std::runtime_error("record must contain a row array");
    Summary summary;
    for (const auto& row : value.as_array()) {
        if (!row.is_array() || row.as_array().size() != 3)
            throw std::runtime_error("invalid record row");
        const auto& fields = row.as_array();
        if (Counter(fields[0]) == 0) throw std::runtime_error("invalid user id");
        summary.upload += Counter(fields[1]);
        summary.download += Counter(fields[2]);
        ++summary.users;
    }
    return summary;
}

std::string Decimal(__uint128_t value) {
    std::string text;
    do {
        text.push_back(static_cast<char>('0' + value % 10));
        value /= 10;
    } while (value != 0);
    std::reverse(text.begin(), text.end());
    return text;
}

std::string Quote(std::string_view text) {
    return ::json::serialize(::json::value(text));
}

std::string Digest(std::string_view raw) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest {};
    SHA256(reinterpret_cast<const unsigned char*>(raw.data()), raw.size(), digest.data());
    constexpr char Hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * digest.size());
    for (unsigned char byte : digest) {
        result.push_back(Hex[byte >> 4]);
        result.push_back(Hex[byte & 15]);
    }
    return result;
}

bool ValidEvidence(std::string_view text) {
    size_t characters = 0;
    bool visible = false;
    for (size_t index = 0; index < text.size();) {
        const auto first = static_cast<unsigned char>(text[index++]);
        uint32_t point = first;
        unsigned continuation = 0;
        uint32_t minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) { point &= 0x1f; continuation = 1; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { point &= 0x0f; continuation = 2; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { point &= 0x07; continuation = 3; minimum = 0x10000; }
        else if (first >= 0x80) return false;
        if (continuation > text.size() - index) return false;
        for (unsigned count = 0; count < continuation; ++count) {
            const auto next = static_cast<unsigned char>(text[index++]);
            if ((next & 0xc0) != 0x80) return false;
            point = (point << 6) | (next & 0x3f);
        }
        if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) return false;
        if (++characters > 512) return false;
        const bool whitespace = (point >= 9 && point <= 13) || (point >= 0x1c && point <= 0x20) ||
            point == 0x85 || point == 0xa0 || point == 0x1680 || (point >= 0x2000 && point <= 0x200a) ||
            point == 0x2028 || point == 0x2029 || point == 0x202f || point == 0x205f || point == 0x3000;
        visible |= !whitespace;
    }
    return visible;
}

void List(int directory) {
    const int copy = ::dup(directory);
    if (copy < 0) FailSystem("dup");
    DIR* raw_directory = ::fdopendir(copy);
    if (!raw_directory) { ::close(copy); FailSystem("fdopendir"); }
    const auto close_directory = [](DIR* value) { ::closedir(value); };
    std::unique_ptr<DIR, decltype(close_directory)> entries(raw_directory, close_directory);
    std::vector<std::string> names;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(entries.get());
        if (!entry) {
            if (errno != 0) FailSystem("readdir");
            break;
        }
        if (RecordName(entry->d_name)) names.emplace_back(entry->d_name);
    }
    std::sort(names.begin(), names.end());
    for (const auto& name : names) {
        const auto summary = Summarize(ReadRecord(directory, name));
        std::cout << "{\"record\":" << Quote(name) << ",\"state\":" << Quote(name.substr(13))
                  << ",\"users\":" << summary.users << ",\"upload\":" << Decimal(summary.upload)
                  << ",\"download\":" << Decimal(summary.download) << "}\n";
    }
}

void Resolve(int directory, const std::string& record, std::string_view decision, std::string_view evidence) {
    if (!RecordName(record) || !record.ends_with(".unknown"))
        throw std::runtime_error("resolve requires one exact unknown record filename");
    if (decision != "confirmed-applied" && decision != "confirmed-not-applied")
        throw std::runtime_error("decision must be confirmed-applied or confirmed-not-applied");
    if (!ValidEvidence(evidence)) throw std::runtime_error("evidence must contain 1..512 UTF-8 characters");
    const auto raw = ReadRecord(directory, record);
    const auto summary = Summarize(raw);
    const auto ready = record.substr(0, 12) + ".ready";
    if (decision == "confirmed-not-applied") {
        struct stat destination {};
        if (::fstatat(directory, ready.c_str(), &destination, AT_SYMLINK_NOFOLLOW) == 0)
            throw std::runtime_error("ready destination already exists");
        if (errno != ENOENT) FailSystem("fstatat");
    }
    const std::time_t now = std::time(nullptr);
    std::tm utc {};
    if (!::gmtime_r(&now, &utc)) throw std::runtime_error("invalid system time");
    std::array<char, 32> timestamp {};
    if (std::strftime(timestamp.data(), timestamp.size(), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0)
        throw std::runtime_error("cannot format audit time");
    const ::json::object entry {
        {"event", "reconciliation-intent"}, {"record", record}, {"sha256", Digest(raw)},
        {"decision", decision}, {"evidence", evidence}, {"time", timestamp.data()}
    };
    const auto audit_line = ::json::serialize(entry) + '\n';
    File audit(::openat(directory, ".reconciliation.jsonl", O_CREAT | O_WRONLY | O_APPEND |
                       O_CLOEXEC | O_NOFOLLOW, 0600));
    struct stat info {};
    if (::fstat(audit.Get(), &info) != 0) FailSystem("fstat audit");
    if (!S_ISREG(info.st_mode) || info.st_size < 0 ||
        static_cast<uint64_t>(info.st_size) > MaxAuditBytes ||
        audit_line.size() > MaxAuditBytes - static_cast<size_t>(info.st_size))
        throw std::runtime_error("audit limit reached; archive .reconciliation.jsonl while stopped first");
    // Durable intent is not a claim of completed reconciliation; the record suffix remains authoritative.
    size_t written = 0;
    while (written < audit_line.size()) {
        const auto count = ::write(audit.Get(), audit_line.data() + written, audit_line.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) FailSystem("write audit");
        written += static_cast<size_t>(count);
    }
    Sync(audit.Get());
    Sync(directory);
    if (decision == "confirmed-applied") {
        if (::unlinkat(directory, record.c_str(), 0) != 0) FailSystem("unlink record");
    } else {
        // Never overwrite a ready record, even if a non-cooperating writer ignored the lock.
        if (::syscall(SYS_renameat2, directory, record.c_str(), directory, ready.c_str(), 1U) != 0)
            FailSystem("rename record");
    }
    Sync(directory);
    std::cout << "{\"event\":\"reconciled\",\"record\":" << Quote(record)
              << ",\"decision\":" << Quote(decision) << ",\"users\":" << summary.users << "}\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 3) throw std::runtime_error("usage: cnode_traffic_journal DIRECTORY list | resolve RECORD --decision DECISION --evidence EVIDENCE");
        const std::string_view command(argv[2]);
        if ((command == "list" && argc != 3) || (command == "resolve" && argc != 8) ||
            (command != "list" && command != "resolve"))
            throw std::runtime_error("invalid command arguments");
        std::string_view decision, evidence;
        if (command == "resolve") {
            for (int index = 4; index < argc; index += 2) {
                const std::string_view option(argv[index]);
                if (option == "--decision" && decision.empty()) decision = argv[index + 1];
                else if (option == "--evidence" && evidence.empty()) evidence = argv[index + 1];
                else throw std::runtime_error("invalid or repeated option");
            }
        }
        File directory(::open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        File lock(::openat(directory.Get(), ".lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600));
        if (::flock(lock.Get(), LOCK_EX | LOCK_NB) != 0) FailSystem("lock journal (stop cnode first)");
        if (command == "list") List(directory.Get());
        else Resolve(directory.Get(), argv[3], decision, evidence);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "traffic journal: " << error.what() << '\n';
        return 1;
    }
}
