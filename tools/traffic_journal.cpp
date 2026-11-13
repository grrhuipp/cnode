#include "infra/json.hpp"
#include "controller/traffic_journal_format.hpp"

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
#include <utility>
#include <vector>

namespace {
constexpr size_t MaxAuditBytes = 1024 * 1024;

[[noreturn]] void FailSystem(const char* operation) {
    throw std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

[[nodiscard]] ::controller::ScopedFd OpenFd(int fd) {
    if (fd < 0) FailSystem("open");
    return ::controller::ScopedFd(fd);
}

void Sync(int fd) {
    if (::fsync(fd) != 0) FailSystem("fsync");
}

struct Summary {
    size_t users = 0;
    __uint128_t upload = 0;
    __uint128_t download = 0;
};

Summary Summarize(std::string_view raw) {
    Summary summary;
    ::controller::VisitRecordRows(raw, [&summary](const ::controller::RecordRow& row) {
        summary.upload += static_cast<uint64_t>(row.upload);
        summary.download += static_cast<uint64_t>(row.download);
        ++summary.users;
    });
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
    return ::infra::serialize(::infra::value(text));
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
    std::vector<std::pair<std::string, ::controller::RecordState>> records;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(entries.get());
        if (!entry) {
            if (errno != 0) FailSystem("readdir");
            break;
        }
        if (const auto state = ::controller::ParseRecordName(entry->d_name))
            records.emplace_back(entry->d_name, *state);
    }
    std::sort(records.begin(), records.end());
    for (const auto& [name, state] : records) {
        const auto summary = Summarize(::controller::ReadRecord(directory, name.c_str()));
        std::cout << "{\"record\":" << Quote(name)
                  << ",\"state\":" << Quote(::controller::RecordSuffix(state).substr(1))
                  << ",\"users\":" << summary.users << ",\"upload\":" << Decimal(summary.upload)
                  << ",\"download\":" << Decimal(summary.download) << "}\n";
    }
}

void Resolve(int directory, const std::string& record, std::string_view decision, std::string_view evidence) {
    if (::controller::ParseRecordName(record) != ::controller::RecordState::Unknown)
        throw std::runtime_error("resolve requires one exact unknown record filename");
    if (decision != "confirmed-applied" && decision != "confirmed-not-applied")
        throw std::runtime_error("decision must be confirmed-applied or confirmed-not-applied");
    if (!ValidEvidence(evidence)) throw std::runtime_error("evidence must contain 1..512 UTF-8 characters");
    const auto raw = ::controller::ReadRecord(directory, record.c_str());
    const auto summary = Summarize(raw);
    const auto ready = ::controller::RecordNameWithState(record, ::controller::RecordState::Ready);
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
    const ::infra::object entry {
        {"event", "reconciliation-intent"}, {"record", record}, {"sha256", ::controller::Sha256Hex(raw)},
        {"decision", decision}, {"evidence", evidence}, {"time", timestamp.data()}
    };
    const auto audit_line = ::infra::serialize(entry) + '\n';
    const auto audit = OpenFd(::openat(directory, ".reconciliation.jsonl",
        O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600));
    struct stat info {};
    if (::fstat(audit.fd, &info) != 0) FailSystem("fstat audit");
    if (!S_ISREG(info.st_mode) || info.st_size < 0 ||
        static_cast<uint64_t>(info.st_size) > MaxAuditBytes ||
        audit_line.size() > MaxAuditBytes - static_cast<size_t>(info.st_size))
        throw std::runtime_error("audit limit reached; archive .reconciliation.jsonl while stopped first");
    // Durable intent is not a claim of completed reconciliation; the record suffix remains authoritative.
    if (!::controller::WriteAllFd(audit.fd, audit_line)) FailSystem("write audit");
    Sync(audit.fd);
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
        const auto directory = OpenFd(::open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        const auto lock = OpenFd(::openat(directory.fd, ".lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600));
        if (::flock(lock.fd, LOCK_EX | LOCK_NB) != 0) FailSystem("lock journal (stop cnode first)");
        if (command == "list") List(directory.fd);
        else Resolve(directory.fd, argv[3], decision, evidence);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "traffic journal: " << error.what() << '\n';
        return 1;
    }
}
